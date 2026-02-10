#!/bin/bash
set -e

#==============================================================================
# Batch Import with Compressed Transfer (Faster)
# 
# Uses tar.gz compression to speed up kubectl cp transfer
# Logs to: ~/Downloads/vt_filtered_batch/import.log
#==============================================================================

# Configuration
LOCAL_DOWNLOAD_DIR="$HOME/Downloads/vt_filtered_batch"
LOG_FILE="$LOCAL_DOWNLOAD_DIR/import.log"
K8S_NAMESPACE="devbusybox"
K8S_POD="toolbox-7f974f5968-7wbxt"
K8S_WORK_DIR="/tmp/parquet_batch"

TIDB_HOST="tidb-dev-us-ashburn-1.cybereason.net"
TIDB_PORT="4000"
TIDB_USER="root"
TIDB_PASSWORD=""
TIDB_DATABASE="threat_intel"
TIDB_BATCH_SIZE="20000"

FILES_PER_BATCH=5  # Compress and upload 5 files at a time

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions (output to both console and log file)
log_info() { 
    local msg="[INFO] $(date '+%Y-%m-%d %H:%M:%S') $1"
    echo -e "${BLUE}${msg}${NC}"
    echo "$msg" >> "$LOG_FILE"
}
log_success() { 
    local msg="[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') $1"
    echo -e "${GREEN}${msg}${NC}"
    echo "$msg" >> "$LOG_FILE"
}
log_error() { 
    local msg="[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $1"
    echo -e "${RED}${msg}${NC}"
    echo "$msg" >> "$LOG_FILE"
}

# Trap Ctrl+C for graceful shutdown
trap 'log_info "Interrupted by user (Ctrl+C). Safe to resume later."; exit 130' INT TERM

# Initialize log file
echo "========================================" > "$LOG_FILE"
echo "Import started at $(date)" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

log_info "Log file: $LOG_FILE"

# Prompt for password
echo ""
log_info "=========================================="
log_info "TiDB Connection"
log_info "=========================================="
echo -e "${BLUE}Host:${NC}     $TIDB_HOST:$TIDB_PORT"
echo -e "${BLUE}Database:${NC} $TIDB_DATABASE"
echo -e "${BLUE}User:${NC}     $TIDB_USER"
echo ""

read -s -p "$(echo -e ${BLUE}[INPUT]${NC} Enter TiDB password: )" TIDB_PASSWORD
echo ""

if [ -z "$TIDB_PASSWORD" ]; then
    log_error "Password cannot be empty!"
    exit 1
fi

log_success "Password received"
echo ""

# Get all parquet files
cd "$LOCAL_DOWNLOAD_DIR"
all_files=($(ls -1 *.parquet 2>/dev/null | sort))
total_files=${#all_files[@]}

if [ $total_files -eq 0 ]; then
    log_error "No parquet files found in $LOCAL_DOWNLOAD_DIR"
    exit 1
fi

log_info "Found $total_files files to process"
log_info "Processing in batches of $FILES_PER_BATCH files"
echo ""

# Upload import script
log_info "Uploading import script..."
kubectl cp /Users/tangxin/work/sage-migration-tools/scripts/import_parquet_to_tidb.py \
  "${K8S_NAMESPACE}/${K8S_POD}:${K8S_WORK_DIR}/"

# Process in batches
batch_num=0
for ((i=0; i<total_files; i+=FILES_PER_BATCH)); do
    ((batch_num++))
    batch_end=$((i + FILES_PER_BATCH))
    if [ $batch_end -gt $total_files ]; then
        batch_end=$total_files
    fi
    
    log_info "=========================================="
    log_info "Batch $batch_num: Files $((i+1))-$batch_end"
    log_info "=========================================="
    
    # Create tar.gz of this batch
    batch_files=("${all_files[@]:$i:$FILES_PER_BATCH}")
    tar_name="batch_${batch_num}.tar.gz"
    
    log_info "Compressing ${#batch_files[@]} files..."
    tar -czf "$tar_name" "${batch_files[@]}"
    
    tar_size=$(ls -lh "$tar_name" | awk '{print $5}')
    log_info "Compressed size: $tar_size"
    
    # Upload compressed file
    log_info "Uploading compressed batch..."
    kubectl cp "$tar_name" "${K8S_NAMESPACE}/${K8S_POD}:/tmp/"
    
    # Extract in busybox
    log_info "Extracting in busybox..."
    kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- \
      tar -xzf "/tmp/$tar_name" -C "$K8S_WORK_DIR/"
    
    # Clean up tar file
    kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- rm "/tmp/$tar_name"
    rm "$tar_name"
    
    # Import
    log_info "Importing to TiDB..."
    kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- \
      python3 "${K8S_WORK_DIR}/import_parquet_to_tidb.py" \
      "$K8S_WORK_DIR/" \
      --host "$TIDB_HOST" \
      --port "$TIDB_PORT" \
      --user "$TIDB_USER" \
      --password "$TIDB_PASSWORD" \
      --database "$TIDB_DATABASE" \
      --batch-size "$TIDB_BATCH_SIZE"
    
    # Clean up parquet files
    log_info "Cleaning up..."
    kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- \
      sh -c "rm -f ${K8S_WORK_DIR}/*.parquet"
    
    log_success "Batch $batch_num completed!"
    echo ""
done

log_success "=========================================="
log_success "All batches completed!"
log_success "=========================================="
log_info "Full log saved to: $LOG_FILE"

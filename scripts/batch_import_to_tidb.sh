#!/bin/bash
set -e

#==============================================================================
# Batch Import VT Filtered Parquet to TiDB
# 
# Prerequisites:
# - Download all parquet files manually to LOCAL_DOWNLOAD_DIR first
# 
# This script:
# 1. Uploads parquet files in batches to K8s busybox pod
# 2. Imports to TiDB with auto-resume support
# 3. Cleans up busybox after each batch
#==============================================================================

# Configuration
LOCAL_DOWNLOAD_DIR="$HOME/Downloads/vt_filtered_batch"
LOCAL_UPLOAD_PROGRESS="$HOME/Downloads/vt_filtered_batch/.upload_progress"

K8S_NAMESPACE="devbusybox"
K8S_POD="toolbox-7f974f5968-7wbxt"
K8S_WORK_DIR="/tmp/parquet_batch"

TIDB_HOST="tidb-dev-us-ashburn-1.cybereason.net"
TIDB_PORT="4000"
TIDB_USER="root"
TIDB_PASSWORD=""  # Will be prompted at runtime
TIDB_DATABASE="threat_intel"
TIDB_BATCH_SIZE="20000"

BATCH_SIZE=3  # Upload 3 files at a time to busybox

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#==============================================================================
# Helper Functions
#==============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

is_file_uploaded() {
    local filename=$1
    if [ ! -f "$LOCAL_UPLOAD_PROGRESS" ]; then
        return 1
    fi
    grep -q "^${filename}$" "$LOCAL_UPLOAD_PROGRESS" 2>/dev/null
}

mark_file_uploaded() {
    local filename=$1
    echo "$filename" >> "$LOCAL_UPLOAD_PROGRESS"
}

get_busybox_imported_files() {
    # Get list of files already imported in busybox (from .import_progress)
    kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- \
        cat "${K8S_WORK_DIR}/.import_progress" 2>/dev/null || echo ""
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [ ! -d "$LOCAL_DOWNLOAD_DIR" ]; then
        log_error "Local download directory not found: $LOCAL_DOWNLOAD_DIR"
        log_error "Please download parquet files manually first!"
        exit 1
    fi
    
    local file_count=$(ls -1 "$LOCAL_DOWNLOAD_DIR"/*.parquet 2>/dev/null | wc -l)
    if [ "$file_count" -eq 0 ]; then
        log_error "No parquet files found in $LOCAL_DOWNLOAD_DIR"
        log_error "Please download parquet files manually first!"
        exit 1
    fi
    
    log_info "Found $file_count parquet files in local directory"
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found! Please install kubectl."
        exit 1
    fi
    
    if ! kubectl get pod -n "$K8S_NAMESPACE" "$K8S_POD" &> /dev/null; then
        log_error "Cannot access pod $K8S_POD in namespace $K8S_NAMESPACE"
        exit 1
    fi
    
    # Initialize upload progress file
    touch "$LOCAL_UPLOAD_PROGRESS"
    
    log_success "Prerequisites check passed"
}

prompt_password() {
    echo ""
    log_info "=========================================="
    log_info "TiDB Connection"
    log_info "=========================================="
    echo -e "${BLUE}Host:${NC}     $TIDB_HOST:$TIDB_PORT"
    echo -e "${BLUE}Database:${NC} $TIDB_DATABASE"
    echo -e "${BLUE}User:${NC}     $TIDB_USER"
    echo ""
    
    # Prompt for password (hidden input)
    read -s -p "$(echo -e ${BLUE}[INPUT]${NC} Enter TiDB password: )" TIDB_PASSWORD
    echo ""
    
    if [ -z "$TIDB_PASSWORD" ]; then
        log_error "Password cannot be empty!"
        exit 1
    fi
    
    log_success "Password received"
    echo ""
}

#==============================================================================
# Upload to Busybox and Import to TiDB
#==============================================================================

upload_and_import() {
    log_info "=========================================="
    log_info "Upload to Busybox & Import to TiDB"
    log_info "=========================================="
    
    # Ensure work directory exists in busybox
    kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- mkdir -p "$K8S_WORK_DIR" 2>/dev/null || true
    
    # Upload the import script (always upload to ensure latest version)
    log_info "Uploading import script to busybox..."
    kubectl cp \
        /Users/tangxin/work/sage-migration-tools/scripts/import_parquet_to_tidb.py \
        "${K8S_NAMESPACE}/${K8S_POD}:${K8S_WORK_DIR}/"
    
    # Get all parquet files in local directory (sorted)
    local all_files=($(ls -1 "$LOCAL_DOWNLOAD_DIR"/*.parquet 2>/dev/null | sort))
    local total_files=${#all_files[@]}
    
    # Check which files are already imported in busybox
    log_info "Checking import progress in busybox..."
    local busybox_imported=$(get_busybox_imported_files)
    
    # Filter out files that are already fully imported
    local to_process=()
    local already_imported=0
    
    for file in "${all_files[@]}"; do
        local filename=$(basename "$file")
        if echo "$busybox_imported" | grep -q "^${filename}$"; then
            ((already_imported++))
        else
            to_process+=("$file")
        fi
    done
    
    log_info "Total files found: $total_files"
    log_info "Already imported: $already_imported"
    log_info "To process: ${#to_process[@]}"
    log_info "Batch size: $BATCH_SIZE files per batch"
    echo ""
    
    if [ ${#to_process[@]} -eq 0 ]; then
        log_success "All files already imported! Nothing to do."
        return
    fi
    
    local total_batches=$(( (${#to_process[@]} + BATCH_SIZE - 1) / BATCH_SIZE ))
    local current_batch=0
    local processed_count=0
    
    # Process files in batches
    for ((batch_start=0; batch_start<${#to_process[@]}; batch_start+=BATCH_SIZE)); do
        ((current_batch++))
        local batch_end=$((batch_start + BATCH_SIZE))
        if [ $batch_end -gt ${#to_process[@]} ]; then
            batch_end=${#to_process[@]}
        fi
        
        log_info "Processing batch $current_batch/$total_batches (files $((batch_start+1))-$batch_end of ${#to_process[@]} remaining)..."
        
        # Upload files in this batch
        local uploaded_count=0
        local uploaded_files=()
        
        for ((i=batch_start; i<batch_end; i++)); do
            local local_file="${to_process[$i]}"
            local filename=$(basename "$local_file")
            
            log_info "  [$((processed_count+i-batch_start+1))/${#to_process[@]}] Uploading $filename..."
            if kubectl cp "$local_file" "${K8S_NAMESPACE}/${K8S_POD}:${K8S_WORK_DIR}/" 2>/dev/null; then
                ((uploaded_count++))
                uploaded_files+=("$filename")
            else
                log_error "  Failed to upload $filename"
            fi
        done
        
        if [ $uploaded_count -eq 0 ]; then
            log_warning "No files uploaded in this batch, skipping import"
            continue
        fi
        
        # Import this batch
        log_info "  Importing $uploaded_count file(s) to TiDB..."
        if kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- \
            python3 "${K8S_WORK_DIR}/import_parquet_to_tidb.py" \
            "$K8S_WORK_DIR/" \
            --host "$TIDB_HOST" \
            --port "$TIDB_PORT" \
            --user "$TIDB_USER" \
            --password "$TIDB_PASSWORD" \
            --database "$TIDB_DATABASE" \
            --batch-size "$TIDB_BATCH_SIZE"; then
            
            # Mark uploaded files as completed in local progress
            for filename in "${uploaded_files[@]}"; do
                mark_file_uploaded "$filename"
            done
            
            log_success "  Import successful, marked ${#uploaded_files[@]} files as completed"
        else
            log_error "  Import failed! Files NOT marked as completed (can retry)"
        fi
        
        # Clean up parquet files in busybox (keep script and progress file)
        log_info "  Cleaning up parquet files in busybox..."
        kubectl exec -n "$K8S_NAMESPACE" "$K8S_POD" -- \
            sh -c "rm -f ${K8S_WORK_DIR}/*.parquet"
        
        processed_count=$((processed_count + uploaded_count))
        log_success "Batch $current_batch completed! ($processed_count/${#to_process[@]} files processed)"
        echo ""
    done
    
    log_success "Import phase completed! Total files processed: $processed_count"
}

#==============================================================================
# Main
#==============================================================================

main() {
    echo ""
    log_info "=========================================="
    log_info "VT Parquet Batch Import to TiDB"
    log_info "=========================================="
    log_info "Local dir: $LOCAL_DOWNLOAD_DIR"
    log_info "Target: $TIDB_HOST:$TIDB_PORT/$TIDB_DATABASE"
    log_info "=========================================="
    echo ""
    
    check_prerequisites
    echo ""
    
    # Prompt for password
    prompt_password
    
    # Upload and Import
    upload_and_import
    echo ""
    
    log_success "=========================================="
    log_success "All operations completed successfully!"
    log_success "=========================================="
}

# Run main function
main

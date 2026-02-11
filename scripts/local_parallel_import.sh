#!/bin/bash
set -e

#==============================================================================
# Local Parallel Import - Direct VPN Connection to TiDB
#
# Skips busybox entirely, imports directly from local machine via VPN.
# Much faster: no upload/compress steps needed.
#
# Usage:
#   ./local_parallel_import.sh           # Process all files
#   ./local_parallel_import.sh 6         # Process first 6 files only (test)
#==============================================================================

# Configuration
LOCAL_DIR="$HOME/Downloads/vt_filtered_batch"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/../venv/bin/python3"
IMPORT_SCRIPT="$SCRIPT_DIR/import_parquet_to_tidb.py"
LOG_FILE="$LOCAL_DIR/import_local_parallel.log"

TIDB_HOST="tidb-stg-ap-tokyo-1.cybereason.net"
TIDB_PORT="4000"
TIDB_USER="root"
TIDB_PASSWORD=""
TIDB_DATABASE="threat_intel"
TIDB_BATCH_SIZE="10000"

PARALLEL_WORKERS=3
FILE_LIMIT="${1:-0}"  # 0 = no limit, or pass number as argument

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "$1" | tee -a "$LOG_FILE"; }

# Trap signals - kill ALL child processes (including Python workers in pipes)
cleanup() {
    log "\n${YELLOW}Interrupted! Cleaning up all workers...${NC}"
    # Kill all descendants of this script
    pkill -P $$ 2>/dev/null
    sleep 1
    # Force kill any remaining import_parquet processes started by us
    for pid in "${worker_pids[@]}"; do
        pkill -P "$pid" 2>/dev/null
        kill "$pid" 2>/dev/null
    done
    # Nuclear option: kill entire process group
    kill 0 2>/dev/null
    exit 130
}
trap cleanup INT TERM EXIT
worker_pids=()

#==============================================================================
# Pre-flight checks
#==============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Local Parallel Import (${PARALLEL_WORKERS} workers) - Direct VPN${NC}"
if [ "$FILE_LIMIT" -gt 0 ] 2>/dev/null; then
    echo -e "${YELLOW}Testing with first ${FILE_LIMIT} files only${NC}"
fi
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check venv
if [ ! -f "$VENV_PYTHON" ]; then
    echo -e "${RED}❌ Python venv not found at $VENV_PYTHON${NC}"
    echo -e "${YELLOW}Run: cd $(dirname $SCRIPT_DIR) && python3 -m venv venv && source venv/bin/activate && pip install mysql-connector-python pyarrow pandas${NC}"
    exit 1
fi

# Check script
if [ ! -f "$IMPORT_SCRIPT" ]; then
    echo -e "${RED}❌ Import script not found at $IMPORT_SCRIPT${NC}"
    exit 1
fi

#==============================================================================
# Password input with VPN connection validation
#==============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}TiDB Password Required${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

while true; do
    read -sp "Enter TiDB password for ${TIDB_USER}@${TIDB_HOST}: " TIDB_PASSWORD
    echo
    
    if [ -z "$TIDB_PASSWORD" ]; then
        echo -e "${RED}Password cannot be empty.${NC}"
        continue
    fi
    
    echo -e "${BLUE}Validating connection (direct VPN)...${NC}"
    
    if "$VENV_PYTHON" -c "
import mysql.connector, sys
try:
    conn = mysql.connector.connect(
        host='${TIDB_HOST}', port=${TIDB_PORT},
        user='${TIDB_USER}', password='${TIDB_PASSWORD}',
        database='${TIDB_DATABASE}', connection_timeout=15, ssl_disabled=True
    )
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM ioc_file_hashes')
    count = cursor.fetchone()[0]
    print(f'OK:{count}')
    conn.close()
    sys.exit(0)
except Exception as e:
    print(f'FAIL:{e}')
    sys.exit(1)
" 2>/dev/null | grep -q "^OK:"; then
        count=$("$VENV_PYTHON" -c "
import mysql.connector
conn = mysql.connector.connect(
    host='${TIDB_HOST}', port=${TIDB_PORT},
    user='${TIDB_USER}', password='${TIDB_PASSWORD}',
    database='${TIDB_DATABASE}', connection_timeout=15, ssl_disabled=True
)
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM ioc_file_hashes')
print(cursor.fetchone()[0])
conn.close()
" 2>/dev/null)
        echo -e "${GREEN}✓ Connected! Current rows: ${count}${NC}"
        break
    else
        echo -e "${RED}✗ Connection failed. Check VPN and password.${NC}"
        TIDB_PASSWORD=""
    fi
done

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

#==============================================================================
# Collect files
#==============================================================================
cd "$LOCAL_DIR"

all_files=()
while IFS= read -r f; do
    all_files+=("$f")
done < <(ls -1 part_*_filtered.parquet 2>/dev/null | sort)

if [ ${#all_files[@]} -eq 0 ]; then
    echo -e "${RED}No parquet files found in $LOCAL_DIR${NC}"
    exit 1
fi

# Apply file limit
if [ "$FILE_LIMIT" -gt 0 ] 2>/dev/null && [ "$FILE_LIMIT" -lt "${#all_files[@]}" ]; then
    all_files=("${all_files[@]:0:$FILE_LIMIT}")
fi

# Check progress (reuse the same progress file)
progress_file="$LOCAL_DIR/.import_progress_local"
completed=()
if [ -f "$progress_file" ]; then
    while IFS= read -r line; do
        [ -n "$line" ] && completed+=("$line")
    done < "$progress_file"
fi

# Filter pending
pending=()
for f in "${all_files[@]}"; do
    skip=false
    for c in "${completed[@]}"; do
        if [ "$f" = "$c" ]; then
            skip=true
            break
        fi
    done
    $skip || pending+=("$f")
done

echo -e "${BLUE}Total files:      ${#all_files[@]}${NC}"
echo -e "${BLUE}Already imported: ${#completed[@]}${NC}"
echo -e "${BLUE}Pending:          ${#pending[@]}${NC}"
echo -e "${BLUE}Progress file:    ${progress_file}${NC}"
echo

if [ ${#pending[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ All files already imported!${NC}"
    exit 0
fi

#==============================================================================
# Split files across workers and run in parallel
#==============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Starting ${PARALLEL_WORKERS} parallel workers...${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

start_time=$(date +%s)

# Create temp file lists for each worker
for ((w=0; w<PARALLEL_WORKERS; w++)); do
    rm -f "/tmp/worker_${w}_files.txt"
    touch "/tmp/worker_${w}_files.txt"
done

# Round-robin distribute files
for ((i=0; i<${#pending[@]}; i++)); do
    w=$((i % PARALLEL_WORKERS))
    echo "${pending[$i]}" >> "/tmp/worker_${w}_files.txt"
done

# Launch workers
pids=()
worker_pids=()
for ((w=0; w<PARALLEL_WORKERS; w++)); do
    file_count=$(wc -l < "/tmp/worker_${w}_files.txt" | tr -d ' ')
    if [ "$file_count" -eq 0 ]; then
        continue
    fi
    
    echo -e "${BLUE}Worker-${w}: ${file_count} files${NC}"
    
    (
        while IFS= read -r filename; do
            log "[Worker-${w}] $(date '+%H:%M:%S') Processing: ${filename}"
            
            "$VENV_PYTHON" -u "$IMPORT_SCRIPT" \
                "$LOCAL_DIR/$filename" \
                --host "$TIDB_HOST" \
                --port "$TIDB_PORT" \
                --user "$TIDB_USER" \
                --password "$TIDB_PASSWORD" \
                --database "$TIDB_DATABASE" \
                --batch-size "$TIDB_BATCH_SIZE" \
                --progress-file "$progress_file" \
                2>&1 | while IFS= read -r line; do
                    echo "[Worker-${w}] $line" | tee -a "$LOG_FILE"
                done
            
            log "[Worker-${w}] $(date '+%H:%M:%S') ✓ Done: ${filename}"
        done < "/tmp/worker_${w}_files.txt"
        
        log "[Worker-${w}] $(date '+%H:%M:%S') ✅ Finished all files"
    ) &
    pids+=($!)
    worker_pids+=($!)
done

# Wait for all workers
echo
log "$(date '+%H:%M:%S') Waiting for ${#pids[@]} workers to finish..."
echo

for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Cleanup temp files
for ((w=0; w<PARALLEL_WORKERS; w++)); do
    rm -f "/tmp/worker_${w}_files.txt"
done

end_time=$(date +%s)
elapsed=$((end_time - start_time))
hours=$((elapsed / 3600))
minutes=$(((elapsed % 3600) / 60))
seconds=$((elapsed % 60))

# Final count
final_count=$("$VENV_PYTHON" -c "
import mysql.connector
conn = mysql.connector.connect(
    host='${TIDB_HOST}', port=${TIDB_PORT},
    user='${TIDB_USER}', password='${TIDB_PASSWORD}',
    database='${TIDB_DATABASE}', connection_timeout=15, ssl_disabled=True
)
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM ioc_file_hashes')
print(cursor.fetchone()[0])
conn.close()
" 2>/dev/null || echo "?")

# Disable cleanup trap on successful completion
trap - EXIT

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ All workers completed!${NC}"
echo -e "${GREEN}Total time: ${hours}h ${minutes}m ${seconds}s${NC}"
echo -e "${GREEN}TiDB rows:  ${final_count}${NC}"
echo -e "${GREEN}Log: ${LOG_FILE}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

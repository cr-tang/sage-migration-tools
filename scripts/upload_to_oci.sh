#!/bin/bash
#
# Upload filtered parquet files to OCI Object Storage bucket.
#
# Usage:
#   ./upload_to_oci.sh                           # Upload all files
#   ./upload_to_oci.sh --parallel 4              # Upload with 4 parallel workers
#   ./upload_to_oci.sh --dir ~/Downloads/other   # Upload from different directory
#   ./upload_to_oci.sh --dry-run                 # Show what would be uploaded
#
set -euo pipefail

# === Configuration ===
NAMESPACE="id9uy08ld7kh"
BUCKET="vt-raw-data-tidb"
REGION="us-ashburn-1"
PROFILE="dev"
AUTH="security_token"
SOURCE_DIR="${SOURCE_DIR:-$HOME/Downloads/vt_filtered_batch}"
PARALLEL=2
DRY_RUN=false
PREFIX=""  # OCI object prefix (subfolder), e.g. "filtered/"

# === Parse arguments ===
while [[ $# -gt 0 ]]; do
    case $1 in
        --parallel|-p) PARALLEL="$2"; shift 2 ;;
        --dir|-d) SOURCE_DIR="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--parallel N] [--dir DIR] [--prefix PREFIX] [--dry-run]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# === Progress tracking ===
PROGRESS_FILE="${SOURCE_DIR}/.upload_progress"
touch "$PROGRESS_FILE"

# === Collect files to upload ===
echo "=== OCI Upload ==="
echo "Source:  $SOURCE_DIR"
echo "Bucket:  oci://$NAMESPACE/$BUCKET"
echo "Region:  $REGION"
echo "Prefix:  ${PREFIX:-<root>}"
echo "Parallel: $PARALLEL"
echo ""

# Find all parquet files not yet uploaded
TOTAL=$(ls "$SOURCE_DIR"/*.parquet 2>/dev/null | wc -l | tr -d ' ')
DONE=$(wc -l < "$PROGRESS_FILE" | tr -d ' ')
echo "Total files: $TOTAL"
echo "Already uploaded: $DONE"

# Build list of remaining files
REMAINING_FILE=$(mktemp)
for f in "$SOURCE_DIR"/*.parquet; do
    basename=$(basename "$f")
    if ! grep -qxF "$basename" "$PROGRESS_FILE"; then
        echo "$f" >> "$REMAINING_FILE"
    fi
done

REMAINING=$(wc -l < "$REMAINING_FILE" | tr -d ' ')
echo "Remaining: $REMAINING"
echo ""

if [ "$REMAINING" -eq 0 ]; then
    echo "✅ All files already uploaded!"
    rm -f "$REMAINING_FILE"
    exit 0
fi

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would upload $REMAINING files:"
    head -10 "$REMAINING_FILE" | while read f; do echo "  $(basename "$f")"; done
    [ "$REMAINING" -gt 10 ] && echo "  ... and $((REMAINING - 10)) more"
    rm -f "$REMAINING_FILE"
    exit 0
fi

# === Upload function ===
upload_file() {
    local filepath="$1"
    local basename=$(basename "$filepath")
    local object_name="${PREFIX}${basename}"
    local start_time=$(date +%s)

    oci os object put \
        --namespace-name "$NAMESPACE" \
        --bucket-name "$BUCKET" \
        --region "$REGION" \
        --profile "$PROFILE" \
        --auth "$AUTH" \
        --name "$object_name" \
        --file "$filepath" \
        --no-multipart \
        --force \
        2>&1

    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        # Thread-safe append to progress file
        flock "$PROGRESS_FILE" bash -c "echo '$basename' >> '$PROGRESS_FILE'"
        local done_now=$(wc -l < "$PROGRESS_FILE" | tr -d ' ')
        echo "$(date +%H:%M:%S) ✅ $basename (${duration}s) [$done_now/$TOTAL]"
    else
        echo "$(date +%H:%M:%S) ❌ $basename FAILED (exit=$exit_code)"
    fi

    return $exit_code
}

export -f upload_file
export NAMESPACE BUCKET REGION PROFILE AUTH PREFIX PROGRESS_FILE TOTAL

# === Run uploads ===
echo "Starting upload at $(date +%H:%M:%S)..."
echo ""

if [ "$PARALLEL" -eq 1 ]; then
    # Sequential upload
    while read filepath; do
        upload_file "$filepath"
    done < "$REMAINING_FILE"
else
    # Parallel upload using xargs
    cat "$REMAINING_FILE" | xargs -P "$PARALLEL" -I {} bash -c 'upload_file "$@"' _ {}
fi

rm -f "$REMAINING_FILE"

# === Summary ===
FINAL_DONE=$(wc -l < "$PROGRESS_FILE" | tr -d ' ')
echo ""
echo "=== Upload Complete ==="
echo "Uploaded: $FINAL_DONE / $TOTAL"
echo "Finished at $(date +%H:%M:%S)"

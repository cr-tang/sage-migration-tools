# Sage Migration Tools - Usage Guide

This guide covers all scripts in the sage-migration-tools repository.

## Table of Contents

1. [parallel_bson_processor.py](#parallel_bson_processorpy) - Process file_rep BSON dumps
2. [domain_bson_processor.py](#domain_bson_processorpy) - Process domain_classification BSON dumps
3. [sinkhole_importer.py](#sinkhole_importerpy) - Import SINKHOLE_IDENTIFIERS to TiDB
4. [tidb_importer.py](#tidb_importerpy) - Import NDJSON to TiDB
5. [tokens_importer.py](#tokens_importerpy) - Import TOKENS collection

---

## parallel_bson_processor.py

Processes MongoDB `file_rep` BSON dumps from GCS, extracts threat records, and outputs compressed NDJSON files.

### Quick Start

```bash
# Process a single shard
python3 parallel_bson_processor.py --shard r01

# Process all shards
python3 parallel_bson_processor.py

# Resume after interruption
python3 parallel_bson_processor.py --shard r01 --resume
```

### Custom Input/Output

```bash
python3 parallel_bson_processor.py \
  --input-file gs://sage_prod_dump/r01/cybereason/file_rep.bson \
  --output-file file_rep_r01_full.ndjson.gz \
  --log-file bson_processor_r01.log \
  --workers 40
```

### Output

- `file_rep_{shard}_full.ndjson.gz` - Compressed NDJSON with threat records
- `file_rep_{shard}_full.ndjson.gz.checkpoint` - Resume checkpoint

### Filtering Logic

- **SKIP**: `response_code == 0` (VT has no data)
- **SKIP**: `classification == 'indifferent'` or `'unknown'` (neutral)
- **KEEP**: Valid threat classification (malware, ransomware, etc.)
- **KEEP**: `positives > 0` (AV detections even without classification)

---

## domain_bson_processor.py

Processes MongoDB `domain_classification` BSON dumps from GCS.

### Quick Start

```bash
# Process a single shard
python3 domain_bson_processor.py --shard r01

# Resume after interruption
python3 domain_bson_processor.py --shard r01 --resume
```

### Custom Input/Output

```bash
python3 domain_bson_processor.py \
  --input-file gs://sage_prod_dump/r01/cybereason/domain_classification.bson \
  --output-file domain_classification_r01.ndjson.gz \
  --log-file domain_processor_r01.log \
  --workers 20
```

### Output

- `domain_classification_{shard}.ndjson.gz` - Compressed NDJSON with domain records
- `domain_classification_{shard}.ndjson.gz.checkpoint` - Resume checkpoint

### Filtering Logic

- **SKIP**: `maliciousClassification=unknown` (VT has no data)
- **SKIP**: `maliciousClassification=indifferent` (neutral, unless has detectedUrls)
- **KEEP**: Malicious classification (malware, whitelist, etc.)
- **KEEP**: Has `detectedUrls` with `positives > 0`

---

## sinkhole_importer.py

Imports SINKHOLE_IDENTIFIERS and TOKENS IP entries to TiDB `ioc_ips` table.

### Quick Start

```bash
# Import from GCS
python3 sinkhole_importer.py \
  --sinkhole-file gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000 \
  --password 'your_password'

# Also import TOKENS IP entries
python3 sinkhole_importer.py \
  --sinkhole-file gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson \
  --include-tokens \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000

# Dry run (no database writes)
python3 sinkhole_importer.py \
  --sinkhole-file SINKHOLE_IDENTIFIERS.bson \
  --dry-run
```

### Options

| Option | Description |
|--------|-------------|
| `--sinkhole-file` | Path to SINKHOLE_IDENTIFIERS.bson (local or gs://) |
| `--include-tokens` | Also import IP entries from ioc_tokens table |
| `--host` | TiDB host (default: localhost) |
| `--port` | TiDB port (default: 4000) |
| `--user` | TiDB user (default: root) |
| `--password` | TiDB password |
| `--database` | Database name (default: threat_intel) |
| `--dry-run` | Parse data but don't write to database |

---

## tidb_importer.py

Imports processed NDJSON files to TiDB tables.

### Quick Start

```bash
python3 tidb_importer.py \
  --input-file file_rep_r01_full.ndjson.gz \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000 \
  --database threat_intel \
  --table ioc_file_hashes
```

---

## tokens_importer.py

Imports TOKENS collection to TiDB `ioc_tokens` table.

### Quick Start

```bash
python3 tokens_importer.py \
  --tokens-file gs://sage_prod_dump/r01/cybereason/TOKENS.bson \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000
```

---

## Running on VM (Background)

### Method 1: Using nohup (Works without tmux)

```bash
# SSH to VM
ssh -i ~/path/to/key.pem centos@phoenix-vt-feeder

# Run with nohup
cd /path/to/scripts
nohup python3 parallel_bson_processor.py --shard r01 > output.log 2>&1 &

# Check progress
tail -f output.log
ps aux | grep parallel_bson_processor

# Stop gracefully
kill <PID>
```

### Method 2: Using tmux

```bash
# Create session
tmux new -s bson_processor

# Run script
python3 parallel_bson_processor.py --shard r01

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t bson_processor

# Stop: Ctrl+C (saves checkpoint)
```

---

## Check Progress

```bash
# View checkpoint
cat file_rep_r01_full.ndjson.gz.checkpoint

# View output file sizes
ls -lh *.ndjson.gz

# Count processed records
zcat file_rep_r01_full.ndjson.gz | wc -l
```

---

## Performance & Memory

### File Hash Processor (parallel_bson_processor.py)
- **Chunk size**: 400MB
- **Workers**: 32-40
- **Peak memory**: ~19GB
- **Processing time**: ~5 hours per shard (950GB)

### Domain Processor (domain_bson_processor.py)
- **Chunk size**: 256MB
- **Workers**: 20
- **Processing time**: ~1-2 hours per shard (80GB)

---

## Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Required packages:
# - bson (pymongo)
# - orjson
# - google-cloud-storage
# - mysql-connector-python

# GCS Authentication
gcloud auth application-default login
```

---

## TiDB Connection Info

| Environment | Host | Port |
|-------------|------|------|
| Dev | tidb-dev-us-ashburn-1.cybereason.net | 4000 |
| Stage | tidb-stg-ap-tokyo-1.cybereason.net | 4000 |
| Prod | tidb-prod-ap-tokyo-1.cybereason.net | 4000 |

Database: `threat_intel`

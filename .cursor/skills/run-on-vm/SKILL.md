# Run Scripts on Phoenix VM

## VM Access

### SSH to phoenix-vt-feeder
```bash
# Using SSH key
ssh -i ~/path/to/key.pem centos@34.26.16.84

# Or using gcloud
gcloud compute ssh phoenix-vt-feeder --project=cybereason-production
```

## Setup Environment

### 1. Clone Repository
```bash
cd ~
git clone https://github.com/cr-tang/sage-migration-tools.git
cd sage-migration-tools/scripts
```

### 2. Install Dependencies
```bash
pip3 install -r ../requirements.txt
# or
pip3 install pymongo orjson google-cloud-storage mysql-connector-python
```

### 3. Verify GCS Access
```bash
gcloud auth application-default print-access-token
gsutil ls gs://sage_prod_dump/
```

## Run Scripts

### File Hash Processing (Long Running)
```bash
# Run single shard with nohup
cd ~/sage-migration-tools/scripts
nohup python3 parallel_bson_processor.py --shard r01 > bson_r01.log 2>&1 &

# Check progress
tail -f bson_r01.log
ps aux | grep parallel_bson_processor

# Resume if interrupted
python3 parallel_bson_processor.py --shard r01 --resume
```

### Domain Processing
```bash
nohup python3 domain_bson_processor.py --shard r01 > domain_r01.log 2>&1 &
```

### Sinkhole Import (Quick)
```bash
python3 sinkhole_importer.py \
  --sinkhole-file gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson \
  --include-tokens \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000 \
  --password 'YOUR_PASSWORD'
```

### TiDB Import
```bash
python3 tidb_importer.py \
  --input-file file_rep_r01_full.ndjson.gz \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000 \
  --database threat_intel \
  --table ioc_file_hashes
```

## Using tmux (Recommended for Long Tasks)

```bash
# Create session
tmux new -s migration

# Run script
python3 parallel_bson_processor.py --shard r01

# Detach: Ctrl+B, then D
# List sessions: tmux ls
# Reattach: tmux attach -t migration
```

## Check Progress

```bash
# View checkpoint
cat file_rep_r01_full.ndjson.gz.checkpoint | python3 -m json.tool

# Check output sizes
ls -lh *.ndjson.gz

# Count records
zcat file_rep_r01_full.ndjson.gz | wc -l

# View running processes
ps aux | grep python3
```

## Performance Notes

- **file_rep**: ~5 hours per shard (950GB), use 32-40 workers
- **domain_classification**: ~1-2 hours per shard (75GB), use 20 workers
- **Peak memory**: ~16-19GB (safe for 32GB VM)
- **Disk**: Ensure 500GB+ free for output files

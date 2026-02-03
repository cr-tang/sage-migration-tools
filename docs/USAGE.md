# parallel_bson_processor.py User Guide

## Start

### Process All Shards (Default)
```bash
python3 parallel_bson_processor.py
```

### Process Single Shard (For Testing)
```bash
# Process only r01 shard
python3 parallel_bson_processor.py --shard r01

# Process only r02 shard
python3 parallel_bson_processor.py --shard r02
```

### Resume After Interruption
```bash
# Resume all shards
python3 parallel_bson_processor.py --resume

# Resume specific shard
python3 parallel_bson_processor.py --shard r01 --resume
```

## Run on VM (Background)

### Method 1: Using nohup (Recommended - Works without tmux)

#### 1. SSH to VM
```bash
ssh -i ~/path/to/ppem.pem centos@34.26.16.84
cd /path/to/scripts/parallel-bson-processor
```

#### 2. Run with nohup
```bash
nohup python3 parallel_bson_processor.py > output.log 2>&1 &
```

#### 3. Check Process
```bash
# View process ID
ps aux | grep parallel_bson_processor

# View real-time logs
tail -f output.log
```

#### 4. Stop Script
```bash
# Find process ID
ps aux | grep parallel_bson_processor

# Graceful stop (will save checkpoint)
kill <PID>

# Or force kill (not recommended)
kill -9 <PID>
```

### Method 2: Using tmux (Requires Installation)

**Install tmux first (if not available):**
```bash
# On CentOS/RHEL
sudo yum install -y tmux

# On Ubuntu/Debian
sudo apt-get install -y tmux
```

#### 1. SSH to VM
```bash
ssh -i ~/path/to/ppem.pem centos@34.26.16.84
cd /path/to/scripts/parallel-bson-processor
```

#### 2. Create tmux Session
```bash
tmux new -s bson_processor
```
This will create a new tmux session and you'll be inside it.

#### 3. Run Script in tmux
Inside the tmux session, run:
```bash
cd /path/to/scripts/parallel-bson-processor
python3 parallel_bson_processor.py
```
**Note:** You can see real-time logs directly in the tmux window.

#### 4. Detach (Run in Background)
```
Press Ctrl+B, then press D
```
Now you can safely close SSH connection, script will continue running.

#### 5. Reconnect to View Progress/Logs
```bash
tmux attach -t bson_processor
```
This will reconnect to the tmux session and you'll see the current output/logs.

#### 6. Stop Script
Inside tmux session:
```
Press Ctrl+C (will save checkpoint)
Then type exit
```

#### View Logs in tmux
- **Scroll up**: Press `Ctrl+B` then `[` to enter scroll mode, use arrow keys to scroll, press `q` to exit
- **Reattach anytime**: `tmux attach -t bson_processor` to see current output

## Output Files

Output files are saved in the **current working directory** where you run the script.

**Example:** If you run the script from `/root/`, files will be saved as:
- `/root/file_rep_r01.ndjson.gz` ~ `/root/file_rep_r06.ndjson.gz` (6 output files)
- `/root/file_rep_r01.ndjson.gz.checkpoint` ~ `/root/file_rep_r06.ndjson.gz.checkpoint` (checkpoint files)

**To save files in a specific directory:**
```bash
cd /path/to/output/directory
python3 parallel_bson_processor.py
```

## Check Progress

```bash
# View checkpoint
cat file_rep_r01.ndjson.gz.checkpoint

# View output file sizes
ls -lh file_rep_*.ndjson.gz

# View number of processed records
zcat file_rep_r01.ndjson.gz | wc -l
```

## Useful Commands

### tmux Commands
```bash
tmux ls                              # List all sessions
tmux attach -t bson_processor        # Attach to session
tmux kill-session -t bson_processor  # Kill session
```

### Process Management
```bash
ps aux | grep parallel_bson_processor  # Find process
kill <PID>                              # Stop process gracefully
tail -f output.log                      # View logs (if using nohup)
```

## Performance & Memory

### Current Configuration
- **Chunk size**: 400MB (larger chunks reduce HTTP overhead, better network utilization)
- **Concurrent workers**: 32 (processes 32 ranges simultaneously for maximum network throughput)
- **Total workers**: 32-48 (auto-calculated based on file size)
- **Peak memory**: ~19GB (safe for 32GB VM, actual usage typically lower)
- **Batch writing**: 8MB byte-based batching for better I/O performance

### Expected Performance
- **Processing time**: ~1-1.5 hours per shard (for 950GB file, optimized based on low memory usage)
- **Memory usage**: ~16GB peak (well within 32GB VM limits, actual usage typically much lower)
- **Network**: Aggressively optimized for GCS download speed (memory is not a constraint)

## Notes

1. **GCS Authentication**: Ensure configured with `gcloud auth application-default login`
2. **Disk Space**: Each shard output is ~100-300GB, ensure sufficient space
3. **Resume**: Use `--resume` to continue, automatically skips completed workers
4. **Memory**: Script uses chunked download (400MB chunks) to optimize network efficiency while staying within memory limits
5. **Performance**: Optimized for network throughput (GCS download is the bottleneck, not CPU/memory)

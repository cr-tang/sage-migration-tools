# VT Incremental Import - K8s CronJob

Automated daily import of VT (VirusTotal) file reputation data into TiDB.

## What It Does

- **Runs daily at 02:00 UTC** (10:00 JST)
- Syncs VT data from **2 days ago** (allows time for GCS data to stabilize)
- Processes: GCS → Filter → OCI → TiDB
- Automatically skips already-processed dates

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  K8s CronJob (phoenix namespace)                        │
│  Schedule: 0 2 * * * (daily 02:00 UTC)                  │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │ 1. Export from GCS                   │
    │    gs://vt-file-feeder-by-date       │
    │    Target: $(date -2d)               │
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ 2. Filter parquet files              │
    │    Remove low-value records          │
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ 3. Upload to OCI                     │
    │    vt_data_incremental/YYYY-MM-DD/   │
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ 4. Import to TiDB                    │
    │    threat_intel.ioc_file_hashes      │
    └──────────────────────────────────────┘
```

## Setup

### Prerequisites

1. **K8s cluster access** with `phoenix` namespace
2. **OCI credentials** at `~/.oci/config` and `~/.oci/sessions/dev/oci_api_key.pem`
3. **TiDB password** for `tidb-stg-ap-tokyo-1.cybereason.net`
4. **GCP service account** with GCS read access (for the pod)

### Installation

```bash
cd /Users/tangxin/work/sage-migration-tools/k8s

# Run setup script (creates secrets + deploys CronJob)
./setup-cronjob.sh

# Or manually:
kubectl apply -f vt-incremental-import-cronjob.yaml
```

### Create Secrets Manually

```bash
# TiDB credentials
kubectl create secret generic tidb-credentials \
  --from-literal=host=tidb-stg-ap-tokyo-1.cybereason.net \
  --from-literal=user=root \
  --from-literal=password=YOUR_PASSWORD \
  -n phoenix

# OCI credentials
kubectl create secret generic oci-credentials \
  --from-file=config=$HOME/.oci/config \
  --from-file=oci_api_key.pem=$HOME/.oci/sessions/dev/oci_api_key.pem \
  -n phoenix
```

## Usage

### Check Status

```bash
# View CronJob
kubectl get cronjob vt-incremental-import -n phoenix

# View recent jobs
kubectl get jobs -n phoenix -l app=vt-incremental-import

# View job history
kubectl get jobs -n phoenix -l app=vt-incremental-import --sort-by=.status.startTime
```

### View Logs

```bash
# Latest job logs
kubectl logs -f -n phoenix \
  $(kubectl get pods -n phoenix -l app=vt-incremental-import \
    --sort-by=.metadata.creationTimestamp -o name | tail -1)

# Specific job logs
kubectl logs -f -n phoenix job/vt-incremental-import-28449210
```

### Manual Trigger

```bash
# Trigger immediate run
kubectl create job --from=cronjob/vt-incremental-import \
  vt-manual-$(date +%s) -n phoenix

# Watch progress
kubectl get jobs -n phoenix -w
```

### Suspend/Resume

```bash
# Suspend (stop automatic runs)
kubectl patch cronjob vt-incremental-import -n phoenix \
  -p '{"spec":{"suspend":true}}'

# Resume
kubectl patch cronjob vt-incremental-import -n phoenix \
  -p '{"spec":{"suspend":false}}'
```

## Configuration

Edit `vt-incremental-import-cronjob.yaml`:

```yaml
# Change schedule (default: daily 02:00 UTC)
spec:
  schedule: "0 2 * * *"

# Change target date offset (default: 2 days ago)
TARGET_DATE=$(date -u -d '2 days ago' +%Y-%m-%d)

# Change resource limits
resources:
  requests:
    memory: "4Gi"
    cpu: "2"
```

## Monitoring

### Success Criteria

- Job completes in < 6 hours
- Exit code 0
- Logs show: `✅ Import complete for YYYY-MM-DD`

### Common Issues

**Job times out (6h limit exceeded)**
- Check GCS access (network issues?)
- Increase `activeDeadlineSeconds` if needed

**OCI auth errors**
- Recreate `oci-credentials` secret
- Verify OCI session is valid: `oci session validate --profile dev`

**TiDB connection refused**
- Check VPN/network policies in K8s cluster
- Verify `tidb-credentials` secret

**Already processed date**
- Normal! Job skips if date exists in OCI `vt_data_incremental/`
- To reprocess: delete OCI folder and re-run job

## Data Organization

### OCI Bucket Structure

```
vt-raw-data-tidb/
├── vt_data/                          # Historical bulk import (509 files)
│   ├── part_0000_filtered.parquet
│   └── ...
│
└── vt_data_incremental/              # Daily incremental imports
    ├── 2026-02-14/
    │   └── part_0000_filtered.parquet
    ├── 2026-02-15/
    │   └── part_0000_filtered.parquet
    └── ...
```

### TiDB Table

All data goes into: `threat_intel.ioc_file_hashes`
- Uses `INSERT IGNORE` for automatic deduplication
- Indexed by: sha256 (PK), sha1, md5

## Maintenance

### Update Scripts

Scripts are fetched from GitHub on each run:
```bash
git clone --depth 1 https://github.com/cr-tang/sage-migration-tools.git
```

To use a different branch/commit:
```yaml
# In CronJob yaml
git clone --depth 1 --branch YOUR_BRANCH https://github.com/...
```

### Cleanup Old Jobs

```bash
# Delete jobs older than 7 days
kubectl delete jobs -n phoenix \
  -l app=vt-incremental-import \
  --field-selector 'status.completionTime<$(date -u -d '7 days ago' --iso-8601=seconds)'
```

### Update OCI Credentials

```bash
# Re-authenticate OCI CLI locally
oci session authenticate --profile dev

# Update secret
kubectl delete secret oci-credentials -n phoenix
kubectl create secret generic oci-credentials \
  --from-file=config=$HOME/.oci/config \
  --from-file=oci_api_key.pem=$HOME/.oci/sessions/dev/oci_api_key.pem \
  -n phoenix
```

## Removal

```bash
# Delete CronJob
kubectl delete cronjob vt-incremental-import -n phoenix

# Delete secrets
kubectl delete secret tidb-credentials oci-credentials -n phoenix

# Delete completed jobs
kubectl delete jobs -n phoenix -l app=vt-incremental-import
```

## Historical Context

**Initial Bulk Import (Feb 2026)**
- Exported 1744 days (2021-02 to 2026-02)
- 509 parquet files, 6.73 billion rows
- Stored in OCI `vt_data/` folder

**Incremental Import (Ongoing)**
- CronJob handles new daily data
- Starts from 2026-02-14 onwards
- Stored in OCI `vt_data_incremental/YYYY-MM-DD/` folders

## Support

For issues or questions:
- Check logs: `kubectl logs -n phoenix <pod-name>`
- View K8s events: `kubectl get events -n phoenix`
- Repository: https://github.com/cr-tang/sage-migration-tools

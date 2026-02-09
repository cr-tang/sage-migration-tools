# Sage Migration Tools

Tools and documentation for migrating Threat Intelligence data from Sage (MongoDB) to Phoenix (TiDB).

## Overview

This repository contains scripts, documentation, and sample data for:
- Processing large MongoDB BSON dumps from GCS
- Extracting and filtering threat intelligence records
- Exporting VirusTotal data to Parquet format for TiDB Lightning import
- Enriching VT data with Broccoli ML classification

## Related Projects

| Project | Repository | Purpose |
|---------|------------|---------|
| Phoenix Flink | [cybereason-labs/phoenix-flink](https://github.com/cybereason-labs/phoenix-flink) | Flink jobs with TI enrichment (ThreatIntelService, TidbStorage) |
| Phoenix | [cybereason-labs/Phoenix](https://github.com/cybereason-labs/Phoenix) | Main Phoenix monorepo with TiDB migrations |
| Sage Content Provider | [cybereason-labs/sage-content-provider](https://github.com/cybereason-labs/sage-content-provider) | Original Sage service (MongoDB, VT integration) |
| VT Feeder Suite | [cybereason-labs/vt-feeder-suite](https://github.com/cybereason-labs/vt-feeder-suite) | VirusTotal Feed API integration |

## Directory Structure

```
sage-migration-tools/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── scripts/
│   ├── vt_parquet_exporter.py       # Export VT data to Parquet (multi-process)
│   ├── broccoli_backfill.py         # Backfill classification from GCS (multi-process)
│   ├── broccoli_updater.py          # Update classification in TiDB (legacy)
│   ├── parallel_bson_processor.py   # Process file_rep BSON dumps
│   ├── domain_bson_processor.py     # Process domain_classification BSON
│   ├── file_rep_importer.py         # Import file_rep NDJSON to TiDB (legacy)
│   ├── domain_importer.py           # Import domains to TiDB
│   ├── generate_sinkhole_seed.py    # Generate sinkhole SQL
│   └── generate_tokens_sql.py       # Generate TOKENS SQL
├── docs/
│   ├── MIGRATION_PLAN.md            # Current migration plan and todos
│   ├── data-migration-cost-analysis.html
│   └── schema/                      # Sage schema documentation
│       ├── INDEX.md                 # MongoDB dump index
│       ├── SCHEMA_SUMMARY.md        # Collection schemas
│       ├── SCHEMA_VALIDATION.md
│       ├── PHOENIX_MIGRATION_NOTES.md
│       └── VT_FEEDER_UNBOXING.md    # VT Feeder architecture
└── .cursor/
    ├── rules/                       # AI coding rules
    └── skills/                      # AI automation skills
```

## Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Required packages:
# - pyarrow
# - google-cloud-storage
# - aiohttp
# - orjson
# - google-auth
```

### Exporting VT Data to Parquet

```bash
cd scripts

# Export VT data from GCS to Parquet (with deduplication and checkpointing)
python3 vt_parquet_exporter.py \
  --output-dir /data/vt_export \
  --start-date 20201101 \
  --end-date 20260130 \
  --workers 30

# Resume from checkpoint (automatic if .progress file exists)
python3 vt_parquet_exporter.py --output-dir /data/vt_export

# Processing: ~17-18 files/sec on 32-vCPU VM
# Deduplication: In-memory SHA256 set with binary checkpoint for fast restarts
# Output: Parquet files with zstd compression, ~500K rows per file
```

### Backfilling Broccoli Classification

```bash
# Backfill classification from broccoli-enricher GCS bucket
# Run AFTER vt_parquet_exporter.py completes
python3 broccoli_backfill.py /data/vt_export --workers 4

# Multi-process architecture:
# - 4 worker processes (default), each with 500 concurrent aiohttp connections
# - Aggregate throughput: ~6800 QPS with 0% error rate
# - In-place Parquet updates (no disk doubling)
# - Auto-resume support

# Dry run (count SHA1s without GCS lookup)
python3 broccoli_backfill.py /data/vt_export --dry-run
```

### Importing to TiDB with Lightning

```bash
# Transfer Parquet files from GCP to OCI
rsync -avz --progress /data/vt_export/*.parquet \
  user@oci-host:/data/tidb_import/vt_export/

# Use TiDB Lightning to import Parquet files
tiup tidb-lightning \
  --backend local \
  --sorted-kv-dir /data/tidb_import/sorted \
  --data-source-dir /data/vt_export/ \
  --tidb-host tidb-stg-ap-tokyo-1.cybereason.net \
  --tidb-port 4000 \
  --pd-addr pd-stg-ap-tokyo-1.cybereason.net:2379
```

## Data Sources

| Source | GCS Location | Size | Output Format |
|--------|--------------|------|---------------|
| VT File Reports | `gs://vt-file-feeder-by-date/{YYYYMMDD}/` | 5+ TB | Parquet (zstd) |
| Broccoli Classification | `gs://broccoli-enricher/latest-reports/{sha1}` | N/A | JSON per SHA1 |
| domain_classification | `gs://sage_prod_dump/r01-r06/cybereason/domain_classification.bson` | 446 GB | NDJSON → TiDB |
| TOKENS | `gs://sage_prod_dump/r01/cybereason/TOKENS.bson` | 890 KB | SQL seed |
| FILE_EXTENSION_CLASSIFICATION | `gs://sage_prod_dump/r04/cybereason/FILE_EXTENSION_CLASSIFICATION.bson` | 105 KB | SQL seed |

**Note**: SINKHOLE_IDENTIFIERS is NOT imported - SINKHOLED IPs are not treated as blacklisted per rule team.

## TiDB Target Tables

| Table | Purpose | Source |
|-------|---------|--------|
| `ioc_file_hashes` | File hash reputation (SHA1, MD5, SHA256) | file_rep + TOKENS |
| `ioc_domains` | Domain reputation | domain_classification + TOKENS |
| `ioc_ips` | IP reputation (malicious only) | TOKENS (IP entries) |
| `ioc_tokens` | Internal curated threat intel | TOKENS |
| `file_extension_classification` | Extension type for double-extension detection | FILE_EXTENSION_CLASSIFICATION |
| `customer_ioc` | Customer-specific blocklist/whitelist | Phoenix Portal API |

## Current Progress

| Table | Status | Records | Notes |
|-------|--------|---------|-------|
| `ioc_tokens` | Done | ~2,500 | Internal threat intel |
| `file_extension_classification` | Done | ~337 | Static data |
| `ioc_file_hashes` | In Progress | ~160M+ | Parquet export + classification backfill |
| `ioc_domains` | Pending | TBD | Need domain_bson_processor.py |
| `ioc_ips` | Pending | ~3,500 | Need sinkhole_importer.py |

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    VT Export Pipeline                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 1: Export VT Data to Parquet                             │
│  ┌────────────────────────────────────────────────┐            │
│  │ vt_parquet_exporter.py (30 workers)            │            │
│  │ - Download tar.bz2 from GCS                    │            │
│  │ - Decompress, parse, deduplicate (SHA256)      │            │
│  │ - Extract: sha256, sha1, md5, positives,       │            │
│  │   total, scan_date, detection_names            │            │
│  │ - Output: Parquet (zstd, 500K rows/file)       │            │
│  │ - Checkpoint: .progress, .dedup_checkpoint     │            │
│  └────────────────────────────────────────────────┘            │
│                        ▼                                        │
│  Step 2: Backfill Classification                               │
│  ┌────────────────────────────────────────────────┐            │
│  │ broccoli_backfill.py (4 processes × 500 conn)  │            │
│  │ - Read Parquet files                           │            │
│  │ - Lookup classification from GCS               │            │
│  │   (gs://broccoli-enricher/latest-reports/)     │            │
│  │ - Update Parquet in-place                      │            │
│  │ - ~6800 QPS aggregate throughput               │            │
│  └────────────────────────────────────────────────┘            │
│                        ▼                                        │
│  Step 3: Import to TiDB                                        │
│  ┌────────────────────────────────────────────────┐            │
│  │ TiDB Lightning (local backend)                 │            │
│  │ - Transfer Parquet: GCP → OCI (rsync/scp)      │            │
│  │ - Bulk import to ioc_file_hashes table         │            │
│  └────────────────────────────────────────────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Documentation

- [Migration Plan](docs/MIGRATION_PLAN.md) - Current plan with todos
- [Schema Summary](docs/schema/SCHEMA_SUMMARY.md) - MongoDB collection schemas
- [VT Feeder Architecture](docs/schema/VT_FEEDER_UNBOXING.md) - VT Feeder deep dive
- [MongoDB Dump Index](docs/schema/INDEX.md) - GCS bucket structure

## License

Internal use only - Cybereason

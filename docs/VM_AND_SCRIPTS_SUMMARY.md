# VT Data Migration — VM & Scripts Summary

## VM: phoenix-vtfeeder (GCP)

- **IP:** 35.231.87.234
- **User:** centos
- **SSH:** `ssh -i ~/path/to/ppem.pem centos@35.231.87.234`
- **Disk:** 500 GB (`/data`), ~378 GB used

### Directory Structure

```
/data/
├── vt_export/                          # VT file reputation export (368 GB)
│   ├── part_0000.parquet               # Raw export files (509 files, ~195 GB)
│   ├── part_0001.parquet
│   ├── ...
│   ├── part_0508.parquet
│   ├── filtered/                       # Filtered parquet files (509 files)
│   │   ├── part_0000_filtered.parquet
│   │   ├── ...
│   │   └── part_0508_filtered.parquet
│   ├── export.log                      # Export log
│   └── .progress                       # Export progress (completed days)
│
├── ti-import/                          # Data import workspace (1.6 GB)
│   ├── scripts/                        # Processing scripts
│   │   ├── vt_parquet_exporter.py      # Main VT export script (GCS → Parquet)
│   │   ├── broccoli_backfill.py        # Backfill Broccoli ML classification
│   │   ├── filter_parquet.py           # Filter raw parquet (remove low-value records)
│   │   ├── parallel_bson_processor.py  # Process file_rep BSON dumps → NDJSON
│   │   ├── domain_bson_processor.py    # Process domain_classification BSON → NDJSON
│   │   ├── file_rep_importer.py        # Import file_rep NDJSON → TiDB (legacy)
│   │   ├── domain_importer.py          # Import domain NDJSON → TiDB
│   │   ├── vt_feeder_importer.py       # Import VT feeder data (legacy)
│   │   ├── import_task_manager.py      # Task manager for imports (legacy)
│   │   └── requirements.txt            # Python dependencies
│   │
│   ├── file_rep/                       # MongoDB file_rep BSON → NDJSON output
│   │   ├── file_rep_r01_full.ndjson.gz # Shard r01 (6 shards total)
│   │   ├── file_rep_r02_full.ndjson.gz
│   │   ├── file_rep_r03_full.ndjson.gz
│   │   ├── file_rep_r04_full.ndjson.gz
│   │   ├── file_rep_r05_full.ndjson.gz
│   │   └── file_rep_r06_full.ndjson.gz
│   │
│   ├── domain/                         # Domain classification output
│   │   └── domain_classification_all.ndjson.gz  # All 6 shards merged (421 KB, 38K records)
│   │
│   └── logs/                           # Processing logs
│       ├── bson_processor_r0[1-6].log  # BSON processing logs per shard
│       ├── domain_processor_all.log    # Domain processing log
│       ├── domain_import.log           # Domain import log
│       └── file_rep_import.log         # File rep import log
```

## Local Machine (Tang's Mac)

### Files

```
~/Downloads/
├── vt_filtered_batch/                  # Downloaded filtered parquet files
│   ├── part_0000_filtered.parquet      # 509 files (~160 GB total)
│   ├── ...
│   ├── part_0508_filtered.parquet
│   ├── .import_progress_local          # Import progress tracking
│   └── .upload_progress                # OCI upload progress tracking
│
└── mongodump_parquet/                  # Converted MongoDB dump
    └── mongodump_all.parquet           # 376K rows, 214 MB (historical file_rep)
```

### Scripts (sage-migration-tools repo)

| Script | Purpose | Usage |
|--------|---------|-------|
| `scripts/import_parquet_loaddata.py` | Import parquet files into TiDB via LOAD DATA | `python import_parquet_loaddata.py *.parquet --host HOST --password PASS` |
| `scripts/upload_to_oci.sh` | Upload parquet files to OCI Object Storage | `./upload_to_oci.sh --parallel 4` |
| `scripts/domain_bson_processor.py` | Process domain_classification BSON from GCS | `python domain_bson_processor.py --shard r01` |
| `scripts/domain_importer.py` | Import domain NDJSON into TiDB | `python domain_importer.py --input FILE --host HOST` |
| `scripts/convert_mongodump_to_parquet.py` | Convert MongoDB dump NDJSON to Parquet | `python convert_mongodump_to_parquet.py` |

## GCS Buckets

| Project | Bucket | Contents |
|---------|--------|----------|
| vt-feed-pipeline-acfe9f | broccoli-enricher | Broccoli ML classification data |
| vt-feed-pipeline-acfe9f | vt-file-feeder-by-date | VT scan raw data (daily archives) |
| cr-core-host-project-c320755e | sage_prod_dump | MongoDB dump (domain_classification, file_rep BSON) |

## OCI Object Storage

| Namespace | Bucket | Region | Contents |
|-----------|--------|--------|----------|
| id9uy08ld7kh | vt-raw-data-tidb | us-ashburn-1 | Filtered parquet files (for TiDB import bypass) |

## TiDB

- **Host:** tidb-stg-ap-tokyo-1.cybereason.net:4000
- **Database:** threat_intel
- **Version:** v8.5.4 Community
- **VPN:** JPN VPN required

## Pipeline Flow

```
GCS (vt-file-feeder-by-date)
  → vt_parquet_exporter.py (on VM)       # Export raw parquet (509 files)
  → broccoli_backfill.py (on VM)         # Backfill ML classification
  → filter_parquet.py (on VM)            # Filter low-value records
  → scp to local Mac (TLV VPN)           # Download filtered files
  → import_parquet_loaddata.py (JPN VPN) # LOAD DATA into TiDB
  → Re-add indexes (sha1, md5)           # After all imports complete

GCS (sage_prod_dump)
  → parallel_bson_processor.py (on VM)   # Process file_rep BSON → NDJSON
  → convert_mongodump_to_parquet.py      # Convert to Parquet (on local)
  → import_parquet_loaddata.py           # Import into TiDB

  → domain_bson_processor.py (on VM)     # Process domain BSON → NDJSON
  → domain_importer.py                   # Import into TiDB
```

## VPN Constraints

| VPN | Access |
|-----|--------|
| TLV | GCP VM (phoenix-vtfeeder) for downloading |
| JPN | TiDB (tidb-stg-ap-tokyo-1) for importing |

Download and import **cannot run simultaneously** — requires VPN switching.

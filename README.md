# Sage Migration Tools

Tools and documentation for migrating Threat Intelligence data from Sage (MongoDB) to Phoenix (TiDB).

## Overview

This repository contains scripts, documentation, and sample data for:
- Processing large MongoDB BSON dumps from GCS
- Extracting and filtering threat intelligence records
- Importing data to TiDB for Phoenix Flink enrichment

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
│   ├── parallel_bson_processor.py   # Process file_rep BSON dumps
│   ├── domain_bson_processor.py     # Process domain_classification BSON (TODO)
│   ├── sinkhole_importer.py         # Import SINKHOLE_IDENTIFIERS (TODO)
│   ├── tidb_importer.py             # Import NDJSON to TiDB
│   └── tokens_importer.py           # Import TOKENS collection
├── docs/
│   ├── MIGRATION_PLAN.md            # Current migration plan and todos
│   ├── TI_DATA_MIGRATION_PLAN.html  # Migration status dashboard
│   ├── TI_DATA_MIGRATION_PLAN.md    # Migration plan (Markdown)
│   ├── TOKENS_MIGRATION_PLAN.md     # TOKENS specific migration
│   ├── USAGE.md                     # Script usage documentation
│   ├── data-migration-cost-analysis.html
│   └── schema/                      # Sage schema documentation
│       ├── INDEX.md                 # MongoDB dump index
│       ├── INDEX.html
│       ├── SCHEMA_SUMMARY.md        # Collection schemas
│       ├── SCHEMA_VALIDATION.md
│       ├── PHOENIX_MIGRATION_NOTES.md
│       ├── VT_FEEDER_UNBOXING.md    # VT Feeder architecture
│       ├── VT_FEEDER_UNBOXING.html
│       ├── SAGE_DATA_SOURCES.html
│       └── DATA_MIGRATION_GUIDE.html
└── samples/                         # Sample data from MongoDB dump
    ├── file_rep_sample.json         # VT file scan results
    ├── domain_classification_sample.json
    ├── TOKENS_sample.json           # Internal threat intel
    ├── SINKHOLE_IDENTIFIERS_sample.json
    └── FILE_EXTENSION_CLASSIFICATION_sample.json
```

## Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Required packages:
# - bson (pymongo)
# - orjson
# - google-cloud-storage
# - mysql-connector-python
```

### Processing File Hashes (file_rep)

```bash
cd scripts

# Process a single shard
python3 parallel_bson_processor.py \
  --input-file gs://sage_prod_dump/r01/cybereason/file_rep.bson \
  --output-file file_rep_r01_full.ndjson.gz \
  --log-file bson_processor_r01.log \
  --workers 40

# Resume from checkpoint
python3 parallel_bson_processor.py \
  --input-file gs://sage_prod_dump/r01/cybereason/file_rep.bson \
  --output-file file_rep_r01_full.ndjson.gz \
  --resume
```

### Importing to TiDB

```bash
python3 tidb_importer.py \
  --input-file file_rep_r01_full.ndjson.gz \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --port 4000 \
  --database threat_intel \
  --table ioc_file_hashes
```

## Data Sources

| Source | GCS Location | Size | Target Table |
|--------|--------------|------|--------------|
| file_rep | `gs://sage_prod_dump/r01-r06/cybereason/file_rep.bson` | 5.6 TB | `ioc_file_hashes` |
| domain_classification | `gs://sage_prod_dump/r01-r06/cybereason/domain_classification.bson` | 446 GB | `ioc_domains` |
| SINKHOLE_IDENTIFIERS | `gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson` | 456 KB | `ioc_ips` |
| TOKENS | `gs://sage_prod_dump/r01/cybereason/TOKENS.bson` | 890 KB | `ioc_tokens` |
| FILE_EXTENSION_CLASSIFICATION | `gs://sage_prod_dump/r04/cybereason/FILE_EXTENSION_CLASSIFICATION.bson` | 105 KB | `file_extension_classification` |

## TiDB Target Tables

| Table | Purpose | Source |
|-------|---------|--------|
| `ioc_file_hashes` | File hash reputation (SHA1, MD5, SHA256) | file_rep + TOKENS |
| `ioc_domains` | Domain reputation | domain_classification + TOKENS |
| `ioc_ips` | IP reputation (sinkhole + malicious) | SINKHOLE_IDENTIFIERS + TOKENS |
| `ioc_tokens` | Internal curated threat intel | TOKENS |
| `file_extension_classification` | Extension type for double-extension detection | FILE_EXTENSION_CLASSIFICATION |
| `customer_ioc` | Customer-specific blocklist/whitelist | Phoenix Portal API |

## Current Progress

| Table | Status | Records | Notes |
|-------|--------|---------|-------|
| `ioc_tokens` | Done | ~2,500 | Internal threat intel |
| `file_extension_classification` | Done | ~337 | Static data |
| `ioc_file_hashes` | In Progress | ~1M | r06 done, r01-r05 pending |
| `ioc_domains` | Pending | TBD | Need domain_bson_processor.py |
| `ioc_ips` | Pending | ~3,500 | Need sinkhole_importer.py |

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Data Source Strategy                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Baseline: MongoDB Dump (2020-11-05)                           │
│  ├── file_rep         → ioc_file_hashes                        │
│  ├── domain_classification → ioc_domains                       │
│  ├── SINKHOLE_IDENTIFIERS → ioc_ips                           │
│  └── TOKENS (IP entries) → ioc_ips                            │
│                                                                 │
│  Future Updates:                                                │
│  ├── File Hashes: VT Feeder GCS (real-time by SHA1)           │
│  ├── Domains: VT Lookup API (on-demand + cache)               │
│  └── IPs: Manually maintained (deferred)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Documentation

- [Migration Plan](docs/MIGRATION_PLAN.md) - Current plan with todos
- [Migration Dashboard (HTML)](docs/TI_DATA_MIGRATION_PLAN.html) - Visual status
- [Usage Guide](docs/USAGE.md) - Script usage
- [Schema Summary](docs/schema/SCHEMA_SUMMARY.md) - MongoDB collection schemas
- [VT Feeder Architecture](docs/schema/VT_FEEDER_UNBOXING.md) - VT Feeder deep dive
- [MongoDB Dump Index](docs/schema/INDEX.md) - GCS bucket structure

## License

Internal use only - Cybereason

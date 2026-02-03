# Sage Migration Tools - Project Rules

## Project Overview

This repository contains tools for migrating Threat Intelligence data from Sage (MongoDB) to Phoenix (TiDB).

## Directory Guide

| Path | Purpose |
|------|---------|
| `scripts/` | Python processing and import scripts |
| `docs/` | Migration documentation and status |
| `docs/schema/` | Sage MongoDB schema documentation |
| `samples/` | Sample data from MongoDB dump |

## Key Files

| File | Description |
|------|-------------|
| `scripts/parallel_bson_processor.py` | Process file_rep BSON from GCS |
| `scripts/domain_bson_processor.py` | Process domain_classification BSON |
| `scripts/sinkhole_importer.py` | Import SINKHOLE_IDENTIFIERS to TiDB |
| `scripts/tidb_importer.py` | Import NDJSON to TiDB |
| `docs/USAGE.md` | Script usage guide |
| `docs/TI_DATA_MIGRATION_PLAN.html` | Migration status dashboard |
| `docs/schema/SCHEMA_SUMMARY.md` | MongoDB collection schemas |

## GCS Data Sources

```
gs://sage_prod_dump/
├── r01-r06/cybereason/
│   ├── file_rep.bson           # 5.6 TB total (VT file scans)
│   ├── domain_classification.bson  # 446 GB total
│   ├── domain_dns.bson         # 3.85 TB total
│   └── ...
├── r01/cybereason/TOKENS.bson  # Internal threat intel
├── r02/cybereason/SINKHOLE_IDENTIFIERS.bson
└── r04/cybereason/FILE_EXTENSION_CLASSIFICATION.bson
```

## TiDB Target Tables

| Table | Source | Status |
|-------|--------|--------|
| `ioc_file_hashes` | file_rep | In Progress |
| `ioc_domains` | domain_classification | Ready |
| `ioc_ips` | TOKENS (IP entries only) | Done via TOKENS |
| `ioc_tokens` | TOKENS | Done |
| `file_extension_classification` | FILE_EXTENSION_CLASSIFICATION | Done |
| `customer_ioc` | Phoenix Portal | Done |

**Note**: SINKHOLED IPs are NOT treated as blacklisted (per rule team), so we don't import SINKHOLE_IDENTIFIERS.

## Related Repositories

| Repo | Purpose | Key Files |
|------|---------|-----------|
| **phoenix-flink** | Flink TI enrichment | `ThreatIntelService.kt`, `TidbStorage.kt`, `Classification.kt` |
| **Phoenix** | TiDB migrations | `migrations/mysql/up/*.sql`, `migrate-ti.sh` |
| **sage-content-provider** | Original Sage service | MongoDB, VT integration |
| **vt-feeder-suite** | VT Feed API | GCS storage logic |

# TI Data Migration Plan

> See also: [Confluence Status Page](https://cybereason.atlassian.net/wiki/spaces/CE/pages/32394936365/Phoenix+Flink+TI+Enrichment+Data+Migration+Status)

## Overview

Migrate file hash reputation data from Sage MongoDB to Phoenix TiDB, with three distinct steps:

1. **Download** - Download and process BSON dumps from MongoDB snapshot
2. **Import** - Import processed NDJSON to TiDB
3. **GCS Update** - Update/enrich data using live GCS sources (vt-file-feeder-by-date + broccoli-enricher)

---

## File Rep Migration: Three Steps

### Step 1: Download ✅ COMPLETE

Download and process MongoDB BSON dumps into NDJSON format.

| Source | Location | Status |
|--------|----------|--------|
| file_rep (6 shards) | `gs://sage_prod_dump/cr-mongo-shard-{r01-r06}.cybereason.net/sage/file_rep.bson` | ✅ Downloaded |

**Processing**:
```bash
# Process BSON → NDJSON (per shard)
python parallel_bson_processor.py \
  --input-file gs://sage_prod_dump/new/cr-mongo-shard-r01.cybereason.net/cybereason/file_rep.bson \
  --output-file /data/ti-import/file_rep/file_rep_r01.ndjson.gz
```

**Output**: `/data/ti-import/file_rep/file_rep_*.ndjson.gz` (~20M records total)

**Data Coverage**: Up to ~2020 (MongoDB snapshot cutoff)

---

### Step 2: Import ✅ COMPLETE

Import processed NDJSON files to TiDB `ioc_file_hashes` table.

**Script**: `file_rep_importer.py`

```bash
python file_rep_importer.py \
  --input "/data/ti-import/file_rep/file_rep_*.ndjson.gz" \
  --host localhost --port 3306 \
  --user root --password phoenix123 \
  --database threat_intel \
  --batch-size 5000 --workers 4
```

**Key Fields Imported**:
| Field | Description |
|-------|-------------|
| sha256 | Primary key (BINARY 32) |
| sha1 | Secondary index (BINARY 20) |
| md5 | Secondary index (BINARY 16) |
| classification | MALWARE, RANSOMWARE, etc. |
| detection_names | Extracted from `scans` field: `engine:result;engine:result;...` |

**Status**: ✅ Complete with detection_names (~20M records)

---

### Step 3: GCS Update ⏳ PENDING

Update and enrich data using live GCS sources.

#### 3a. Incremental Data (vt-file-feeder-by-date + broccoli-enricher)

Import new file hashes from 2020 onwards (after MongoDB snapshot).

> **Important**: VT Feeder data has **NO classification** - only raw scan results!
> Classification comes from Broccoli ML service separately.
> See `docs/schema/VT_FEEDER_UNBOXING.md` for complete data flow.

**Data Flow**:
```
vt-file-feeder-by-date          broccoli-enricher
┌─────────────────────┐        ┌─────────────────────┐
│ Raw VT Report       │        │ ML Classification   │
│ - sha1, sha256, md5 │        │ - classification    │
│ - positives         │   +    │ - algoVersion       │
│ - scans: {...}      │        │                     │
│ - NO classification │        │                     │
└─────────────────────┘        └─────────────────────┘
         │                              │
         └──────────────┬───────────────┘
                        ▼
              ┌─────────────────────┐
              │ ioc_file_hashes     │
              │ - sha256, sha1, md5 │
              │ - classification    │  ← from broccoli (or inferred)
              │ - detection_names   │  ← from scans
              └─────────────────────┘
```

| Source | Location | Content |
|--------|----------|---------|
| VT Reports | `gs://vt-file-feeder-by-date/{YYYYMMDD}/` | Raw scans, hashes, positives |

**Script**: `vt_feeder_importer.py` ✅ Created

```bash
# Import single day
python vt_feeder_importer.py --date 20260205 --password phoenix123

# Import date range
python vt_feeder_importer.py --start-date 20201101 --end-date 20260130 --password phoenix123

# Dry run (test without DB changes)
python vt_feeder_importer.py --date 20260205 --dry-run --max-files 5 --password phoenix123

# Custom performance tuning
python vt_feeder_importer.py --start-date 20201101 --end-date 20260130 \
  --download-workers 30 --db-workers 12 --password phoenix123
```

**Note**: Database configuration is fixed (localhost:3306, user=root, database=threat_intel)

**Architecture**: Hash-partitioned pipeline with GCS SDK
- 20 download workers (parallel GCS downloads)
- 8 DB writers (hash-partitioned by SHA256, no lock contention)
- UPSERT logic (updates existing records)

**Processing**:
1. Filter: `positives > 0` (has AV detections)
2. Extract: `sha256`, `sha1`, `md5`, `detection_names`
3. UPSERT to `ioc_file_hashes` (classification=NULL, will be filled by broccoli_updater)

**Performance**:
- Single day (~1440 files): ~5-6 seconds
- 2 months (Nov-Dec 2020): ~5-6 minutes
- Full 5 years (2020-11 to 2026-02): ~3 hours

**Dependencies**:
```bash
pip install google-cloud-storage mysql-connector-python orjson
```

#### 3b. Classification Enrichment (broccoli-enricher)

Fill classifications using Broccoli ML results. Run **after** `vt_feeder_importer.py` completes.

| Attribute | Value |
|-----------|-------|
| Location | `gs://broccoli-enricher/latest-reports/{sha1}` |
| Format | JSON file per SHA1 |
| Content | `{"classification":"malware", "hash":"...", ...}` |

**Script**: `broccoli_updater.py` ✅ Created

```bash
# Update classifications + cleanup
python broccoli_updater.py --password phoenix123

# Cleanup only (delete unwanted classifications)
python broccoli_updater.py --cleanup-only --password phoenix123
```

**Processing**:
1. Query records with NULL classification
2. Lookup Broccoli by SHA1 → update classification
3. Cleanup: Delete records where classification = INDIFFERENT/UNKNOWN/WHITELIST

---

## Data Sources Summary

| Source | Type | Location | Use |
|--------|------|----------|-----|
| MongoDB Dump | Historical | `gs://sage_prod_dump/` | Step 1-2: Initial data (up to 2020) |
| vt-file-feeder-by-date | Incremental | `gs://vt-file-feeder-by-date/` | Step 3a: Import (positives>0, classification=NULL) |
| broccoli-enricher | Enrichment | `gs://broccoli-enricher/` | Step 3b: Fill classification + cleanup |

---

## Scripts

| Script | Step | Purpose | Status |
|--------|------|---------|--------|
| `parallel_bson_processor.py` | 1 | Process BSON → NDJSON | ✅ Complete |
| `file_rep_importer.py` | 2 | Import NDJSON to TiDB | ✅ Complete (with detection_names) |
| `vt_feeder_importer.py` | 3a | Import incremental data (classification=NULL) | ✅ Created |
| `broccoli_updater.py` | 3b | Fill classification + delete unwanted | ✅ Created |

**Execution Order**:
1. `vt_feeder_importer.py` - Import VT data with `positives > 0`, classification = NULL
2. `broccoli_updater.py` - Fill classification from Broccoli ML
3. `broccoli_updater.py --cleanup-only` - Delete INDIFFERENT/UNKNOWN/WHITELIST records

---

## Current Progress

| Step | Description | Status | Records |
|------|-------------|--------|---------|
| 1. Download | BSON → NDJSON | ✅ Complete | 6 shards |
| 2. Import | NDJSON → TiDB | ✅ Complete | ~20M |
| 3a. GCS Update (incremental) | vt-file-feeder-by-date | ⏳ Pending | Est. 100M+ |
| 3b. GCS Update (classification) | broccoli-enricher | ⏳ Pending | ~91K |

---

## VM Environment

```
Host: phoenix-vt-feeder (34.26.16.84)
SSH: ssh -i ~/path/to/ppem.pem centos@34.26.16.84
Database: MariaDB localhost:3306
Credentials: root / phoenix123
Data Dir: /data/ti-import/
```

---

## Quick Reference

```bash
# Check import progress
mysql -uroot -pphoenix123 threat_intel -e "SELECT COUNT(*) FROM ioc_file_hashes;"

# Check detection_names coverage
mysql -uroot -pphoenix123 threat_intel -e \
  "SELECT COUNT(*) as total, COUNT(detection_names) as with_names FROM ioc_file_hashes;"

# Check empty classifications
mysql -uroot -pphoenix123 threat_intel -e \
  "SELECT COUNT(*) FROM ioc_file_hashes WHERE classification IS NULL OR classification = '';"

# Sample detection_names
mysql -uroot -pphoenix123 threat_intel -e \
  "SELECT LEFT(detection_names, 100) FROM ioc_file_hashes WHERE detection_names IS NOT NULL LIMIT 3;"
```

---

## Notes

1. **Detection Names Format**: Extracted from VT `scans` field as `engine:result;engine:result;...`
2. **Classification Priority**: Broccoli ML > inferred from detection_names > positives count
3. **Deduplication**: Uses `INSERT IGNORE` based on sha256 primary key
4. **Case Sensitivity**: SHA1/SHA256 hashes are lowercase in GCS filenames

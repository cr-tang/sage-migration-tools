# Sage MongoDB Production Dump Index

**Source**: `gs://sage_prod_dump/`  
**Database**: `cybereason`  
**Verified**: 2026-01-26

---

## ⚠️ Important: Two Dump Versions Exist

The GCS bucket contains **two separate dumps** (total ~20 TB):

| Directory | Dump Date | file_rep | domain_dns | domain_classification | Total |
|-----------|-----------|----------|------------|----------------------|-------|
| Root (`/`) | 2020-11-05 | 5.19 TB | 3.85 TB | 446 GB | **~9.5 TB** |
| `new/` | 2020-11-26 | 5.53 TB | 3.95 TB | 447 GB | **~10 TB** |
| **Combined** | | 10.72 TB | 7.80 TB | 893 GB | **~19.5 TB** |

**Recommendation**: Use **Root directory** (2020-11-05) - confirmed complete dump.

> ⚠️ **Note**: `new/` directory contains `config/oplog.bson` and may be an **incremental backup** or **incomplete dump**. The local samples were downloaded from Root directory.

### Per-Shard Comparison (file_rep.bson)

| Shard | Root (2020-11-05) | new/ (2020-11-26) |
|-------|-------------------|-------------------|
| r01 | 853.3 GB | 971.8 GB |
| r02 | 863.6 GB | 937.9 GB |
| r03 | 924.5 GB | 921.4 GB |
| r04 | 881.7 GB | 952.1 GB |
| r05 | 962.9 GB | 961.9 GB |
| r06 | 831.7 GB | 920.2 GB |
| **Total** | **5.19 TB** | **5.53 TB** |

---

## Data Migration Estimate

| Stage | Data Size | Notes |
|-------|-----------|-------|
| Original (Root directory) | ~9.5 TB | Complete dump (2020-11-05) |
| After filtering (response_code=1) | ~950 GB | ~10% has VT data |
| After filtering (positives>0) | ~95 GB | ~1% has detections |
| After field extraction | ~9.5 GB | Remove scans details |
| After gzip compression | **~1-3 GB** | Final transfer size |

---

## Collection Summary by Shard

### All Collections Summary (Deduplicated)

| Collection | Purpose | Present in Shards | Data Scale |
|------------|---------|-------------------|------------|
| `DLL_OFFSETS` | DLL offset data | r01-r06 | ~30-42 KB |
| `PROCESS_HIERARCHY` | Process hierarchy relationships | r01, r05(empty) | ~1.4 KB |
| `TOKENS` | Token classification data | r01, r05(empty) | ~890 KB |
| `PORT_CLASSIFICATION` | Port classification | r02, r05(empty) | ~1.7 MB |
| `SINKHOLE_IDENTIFIERS` | Sinkhole identifiers | r02, r05(empty) | ~456 KB |
| `MALOP_CONSTANTS` | Malop constants | r03, r05(empty) | ~17 KB |
| `FILE_EXTENSION_CLASSIFICATION` | File extension classification | r04, r05(empty) | ~105 KB |
| `FILE_CLASSIFICATION` | File classification | r05 | ~22 KB |
| `PRODUCT_CLASSIFICATION` | Product classification | r05 | ~30 KB |
| `ENGINES` | Engine configuration | r05(empty), r06 | ~181 KB |
| `QUOTA_LIMITS` | Quota limits | r05(empty), r06 | ~980 B |
| `TTL` | TTL configuration | r05 | ~942 B |
| `alerts` | Alert records | r04, r05(empty) | ~6.8 MB |
| `cp_server_configuration` | CP server configuration | r03, r05(empty) | ~1.1 KB |
| `sage_configurations` | Sage configuration | r02, r05(empty) | ~8.3 KB |
| `state_properties` | State properties | r03, r05(empty) | ~9 KB |
| `properties` | Property configuration | r01, r05(empty) | ~505 B |
| `domain_classification` | Domain classification (VT) | r01-r06 | **~75-85 GB/shard** |
| `domain_dns` | Domain DNS records | r01-r06 | **~675-729 GB/shard** |
| `file_rep` | File reputation (VT) | r01-r06 | **~893 GB - 1 TB/shard** |
| `file_rep_revlabs` | File reputation (RevLabs) | r01-r06 | 0 B (empty) |
| `default.quota` | Default quota | r01-r06 | 0 B (empty) |
| `reversing_labs_quota` | RevLabs quota | r01-r06 | 0 B (empty) |
| `virus_total_quota` | VT quota | r01-r06 | 0 B (empty) |

---

## Detailed File List by Shard

### Shard r01 (`cr-mongo-shard-r01.cybereason.net`)

| Collection | Size | Download Status |
|------------|------|-----------------|
| DLL_OFFSETS.bson | 38 KB | ⬜ |
| PROCESS_HIERARCHY.bson | 1.4 KB | ⬜ |
| TOKENS.bson | 890 KB | ⬜ |
| properties.bson | 505 B | ⬜ |
| domain_classification.bson | 84.7 GB | ⬜ (needs sampling) |
| domain_dns.bson | 728.8 GB | ⬜ (needs sampling) |
| file_rep.bson | 916.3 GB | ⬜ (needs sampling) |
| default.quota.bson | 0 B | ⬜ |
| file_rep_revlabs.bson | 0 B | ⬜ |
| reversing_labs_quota.bson | 0 B | ⬜ |
| virus_total_quota.bson | 0 B | ⬜ |

### Shard r02 (`cr-mongo-shard-r02.cybereason.net`)

| Collection | Size | Download Status |
|------------|------|-----------------|
| DLL_OFFSETS.bson | 29 KB | ⬜ |
| PORT_CLASSIFICATION.bson | 1.7 MB | ⬜ |
| SINKHOLE_IDENTIFIERS.bson | 456 KB | ⬜ |
| sage_configurations.bson | 8.3 KB | ⬜ |
| domain_classification.bson | 84.2 GB | ⬜ (needs sampling) |
| domain_dns.bson | 710.2 GB | ⬜ (needs sampling) |
| file_rep.bson | 927.3 GB | ⬜ (needs sampling) |
| default.quota.bson | 0 B | ⬜ |
| file_rep_revlabs.bson | 0 B | ⬜ |
| reversing_labs_quota.bson | 0 B | ⬜ |
| virus_total_quota.bson | 0 B | ⬜ |

### Shard r03 (`cr-mongo-shard-r03.cybereason.net`)

| Collection | Size | Download Status |
|------------|------|-----------------|
| DLL_OFFSETS.bson | 42 KB | ⬜ |
| MALOP_CONSTANTS.bson | 17.7 KB | ⬜ |
| cp_server_configuration.bson | 1.1 KB | ⬜ |
| state_properties.bson | 9 KB | ⬜ |
| domain_classification.bson | 76.6 GB | ⬜ (needs sampling) |
| domain_dns.bson | 705 GB | ⬜ (needs sampling) |
| file_rep.bson | 992.7 GB | ⬜ (needs sampling) |
| default.quota.bson | 0 B | ⬜ |
| file_rep_revlabs.bson | 0 B | ⬜ |
| reversing_labs_quota.bson | 0 B | ⬜ |
| virus_total_quota.bson | 0 B | ⬜ |

### Shard r04 (`cr-mongo-shard-r04.cybereason.net`)

| Collection | Size | Download Status |
|------------|------|-----------------|
| DLL_OFFSETS.bson | 42 KB | ⬜ |
| FILE_EXTENSION_CLASSIFICATION.bson | 105 KB | ⬜ |
| alerts.bson | 6.9 MB | ⬜ |
| domain_classification.bson | 81.2 GB | ⬜ (needs sampling) |
| domain_dns.bson | 713.7 GB | ⬜ (needs sampling) |
| file_rep.bson | 946.7 GB | ⬜ (needs sampling) |
| default.quota.bson | 0 B | ⬜ |
| file_rep_revlabs.bson | 0 B | ⬜ |
| reversing_labs_quota.bson | 0 B | ⬜ |
| virus_total_quota.bson | 0 B | ⬜ |

### Shard r05 (`cr-mongo-shard-r05.cybereason.net`)

| Collection | Size | Download Status |
|------------|------|-----------------|
| DLL_OFFSETS.bson | 34 KB | ⬜ |
| FILE_CLASSIFICATION.bson | 22 KB | ⬜ |
| PRODUCT_CLASSIFICATION.bson | 30 KB | ⬜ |
| TTL.bson | 942 B | ⬜ |
| domain_classification.bson | 75.7 GB | ⬜ (needs sampling) |
| domain_dns.bson | 675.3 GB | ⬜ (needs sampling) |
| file_rep.bson | 1.03 TB | ⬜ (needs sampling) |
| ENGINES.bson | 0 B | ⬜ |
| FILE_EXTENSION_CLASSIFICATION.bson | 0 B | ⬜ |
| MALOP_CONSTANTS.bson | 0 B | ⬜ |
| PORT_CLASSIFICATION.bson | 0 B | ⬜ |
| PROCESS_HIERARCHY.bson | 0 B | ⬜ |
| QUOTA_LIMITS.bson | 0 B | ⬜ |
| SINKHOLE_IDENTIFIERS.bson | 0 B | ⬜ |
| TOKENS.bson | 0 B | ⬜ |
| alerts.bson | 0 B | ⬜ |
| cp_server_configuration.bson | 0 B | ⬜ |
| default.quota.bson | 0 B | ⬜ |
| file_rep_revlabs.bson | 0 B | ⬜ |
| properties.bson | 0 B | ⬜ |
| reversing_labs_quota.bson | 0 B | ⬜ |
| sage_configurations.bson | 0 B | ⬜ |
| state_properties.bson | 0 B | ⬜ |
| virus_total_quota.bson | 0 B | ⬜ |

### Shard r06 (`cr-mongo-shard-r06.cybereason.net`)

| Collection | Size | Download Status |
|------------|------|-----------------|
| DLL_OFFSETS.bson | 38 KB | ⬜ |
| ENGINES.bson | 181 KB | ⬜ |
| QUOTA_LIMITS.bson | 980 B | ⬜ |
| domain_classification.bson | 76.9 GB | ⬜ (needs sampling) |
| domain_dns.bson | 702.7 GB | ⬜ (needs sampling) |
| file_rep.bson | 893 GB | ⬜ (needs sampling) |
| default.quota.bson | 0 B | ⬜ |
| file_rep_revlabs.bson | 0 B | ⬜ |
| reversing_labs_quota.bson | 0 B | ⬜ |
| virus_total_quota.bson | 0 B | ⬜ |

---

## Data Volume Statistics (Verified 2026-01-26)

### new/ Directory (Recommended - 2020-11-26)

| Data Type | Per-Shard Average | 6-Shard Total |
|-----------|-------------------|---------------|
| file_rep | ~922 GB | **5.53 TB** |
| domain_dns | ~658 GB | **3.95 TB** |
| domain_classification | ~75 GB | **447 GB** |
| **Total** | ~1.65 TB | **~10 TB** |

### Root Directory (Older - 2020-11-05)

| Data Type | Per-Shard Average | 6-Shard Total |
|-----------|-------------------|---------------|
| file_rep | ~865 GB | **5.19 TB** |
| domain_dns | ~642 GB | **3.85 TB** |
| domain_classification | ~74 GB | **446 GB** |
| **Total** | ~1.58 TB | **~9.5 TB** |

---

## Downloaded Sample Statistics

### Large File 10MB Samples (from r01 shard)

| Collection | Sample Size | Sample Record Count | Original File Size |
|------------|-------------|---------------------|-------------------|
| `file_rep` | 10 MB | ~9,005 records | 916.3 GB |
| `domain_classification` | 10 MB | ~17,848 records | 84.7 GB |
| `domain_dns` | 10 MB | ~21,417 records | 728.8 GB |

### Small Files (Full Download)

| Collection | File Size | Location |
|------------|-----------|----------|
| `TOKENS` | 890 KB | r01 |
| `DLL_OFFSETS` | 38 KB | r01 |
| `PROCESS_HIERARCHY` | 1.4 KB | r01 |
| `properties` | 505 B | r01 |
| `sage_configurations` | 8.3 KB | r02 |
| `PORT_CLASSIFICATION` | 1.7 MB | r02 |
| `SINKHOLE_IDENTIFIERS` | 456 KB | r02 |
| `cp_server_configuration` | 1.1 KB | r03 |
| `state_properties` | 9 KB | r03 |
| `MALOP_CONSTANTS` | 17.7 KB | r03 |
| `alerts` | 6.9 MB | r04 |
| `FILE_EXTENSION_CLASSIFICATION` | 105 KB | r04 |
| `FILE_CLASSIFICATION` | 22 KB | r05 |
| `PRODUCT_CLASSIFICATION` | 30 KB | r05 |
| `TTL` | 942 B | r05 |
| `ENGINES` | 181 KB | r06 |
| `QUOTA_LIMITS` | 980 B | r06 |

---

## Download Strategy

### Small Files (< 10 MB) - Full Download
- Directly download entire file using `gsutil cp`
- Convert to JSON using `bsondump` for viewing

### Large Files (> 1 GB) - 10MB Sampling
- Download first 10MB using `gsutil cat -r 0-10485760`
- Convert to JSON using `bsondump` to view sample data

---

## GCS Path Mapping

```
gs://sage_prod_dump/                              # Total: ~19.5 TB
│
├── cr-mongo-shard-r01.cybereason.net/           ─┐
│   └── cybereason/                               │
│       ├── *.bson                                │
│       └── *.metadata.json                       │
├── cr-mongo-shard-r02.cybereason.net/            │
│   └── cybereason/                               ├── COMPLETE DUMP (2020-11-05)
├── cr-mongo-shard-r03.cybereason.net/            │   ~9.5 TB ✅ RECOMMENDED
│   └── cybereason/                               │   (local samples from here)
├── cr-mongo-shard-r04.cybereason.net/            │
│   └── cybereason/                               │
├── cr-mongo-shard-r05.cybereason.net/            │
│   └── cybereason/                               │
├── cr-mongo-shard-r06.cybereason.net/           ─┘
│   └── cybereason/
│
└── new/                                         ─┐
    ├── config/                                   │  ⚠️ Contains oplog.bson
    │   ├── oplog.bson                            │  May be incremental backup
    │   ├── admin/                                │  or incomplete dump
    │   └── config/                               │
    ├── cr-mongo-shard-r01.cybereason.net/        ├── POSSIBLY INCOMPLETE (2020-11-26)
    │   └── cybereason/                           │   ~10 TB
    ├── cr-mongo-shard-r02.cybereason.net/        │
    │   └── cybereason/                           │
    ├── cr-mongo-shard-r03.cybereason.net/        │
    │   └── cybereason/                           │
    ├── cr-mongo-shard-r04.cybereason.net/        │
    │   └── cybereason/                           │
    ├── cr-mongo-shard-r05.cybereason.net/        │
    │   └── cybereason/                           │
    └── cr-mongo-shard-r06.cybereason.net/       ─┘
        └── cybereason/
```

---

## Local Directory Structure

```
mongo_dump_samples/
├── INDEX.md (this file)
├── SCHEMA_SUMMARY.md
├── SCHEMA_VALIDATION.md
├── API_CLASSIFICATION.md
├── PHOENIX_MIGRATION_NOTES.md
├── SAGE_DATA_SOURCES.html
├── DATA_MIGRATION_GUIDE.html
├── r01/
│   └── cybereason/
│       ├── *.bson
│       └── *.json (bsondump output)
├── r02/
│   └── cybereason/
├── r03/
│   └── cybereason/
├── r04/
│   └── cybereason/
├── r05/
│   └── cybereason/
└── r06/
    └── cybereason/
```

---

## Phoenix Migration: Data Transfer Estimate

### Filter Strategy

| Strategy | Filter Condition | Estimated Data |
|----------|-----------------|----------------|
| **A: All VT Data** | `response_code = 1` | ~10% of original |
| **B: Malicious Only** | `positives > 0` | ~1% of original |

### Sample Analysis (from file_rep_sample.json, 20 records)

| Metric | Count | Percentage |
|--------|-------|------------|
| Total records | 20 | 100% |
| `response_code = 1` (VT has data) | 2 | 10% |
| `response_code = 0` (VT no data) | 18 | 90% |
| `positives > 0` (has detections) | 0 | 0% |

### Record Count Estimates (from Sample Analysis)

| Source | Original Size | Avg Record | Est. Total Records |
|--------|---------------|------------|-------------------|
| file_rep | 5.19 TB | ~1,164 bytes | **~4.9 billion** |
| domain_classification | 446 GB | ~588 bytes | **~815 million** |
| TOKENS | 890 KB | ~350 bytes | **~2,538** |
| SINKHOLE_IDENTIFIERS | 456 KB | ~150 bytes | **~3,000** |

### After Filtering

| Source | Filter | Est. Records | Notes |
|--------|--------|--------------|-------|
| file_rep | `response_code=1` | ~490 million | 10% has VT data |
| file_rep | `positives>0` | ~49 million | 1% has detections |
| domain_classification | has detections | ~80 million | ~10% estimated |
| TOKENS | all | 2,538 | 100% (small dataset) |
| SINKHOLE_IDENTIFIERS | all | ~3,000 | 100% (small dataset) |

### TiDB Schema Row Sizes

| Table | Fields | Row Size | Notes |
|-------|--------|----------|-------|
| `ioc_file_hashes` | sha256(32) + sha1(20) + md5(16) + enum(1) + enum(1) + datetime(8) | **~88 bytes** | Binary hashes |
| `ioc_domains` | domain(~30 avg) + enum(1) + enum(1) + datetime(8) | **~50 bytes** | VARCHAR domain |
| `ioc_ips` | ip(16) + tinyint(1) + enum(1) + enum(1) + varchar(~30) + datetime(8) | **~70 bytes** | Binary IP |
| `customer_ioc` | bigint(8) + enum(1) + varchar(64) + enum(1) + varchar(~100) + datetime(8) | **~200 bytes** | Per org |

### Final Data Size Estimates (TiDB Storage)

**Strategy A: Malicious Only (positives > 0)**

| TiDB Table | Source | Records | Row Size | Data Size | With Index |
|------------|--------|---------|----------|-----------|------------|
| `ioc_file_hashes` | file_rep | 49M | 88 bytes | **4.3 GB** | ~6 GB |
| `ioc_domains` | domain_classification | 80M | 50 bytes | **4.0 GB** | ~6 GB |
| `ioc_ips` | SINKHOLE_IDENTIFIERS | 3K | 70 bytes | **0.2 MB** | ~0.5 MB |
| `ioc_file_hashes` | TOKENS (hashes) | ~2K | 88 bytes | **0.2 MB** | ~0.5 MB |
| `ioc_domains` | TOKENS (domains) | ~500 | 50 bytes | **25 KB** | ~50 KB |
| **Total** | | | | **~8.3 GB** | **~12 GB** |

**Strategy B: All VT Data (response_code = 1)**

| TiDB Table | Source | Records | Row Size | Data Size | With Index |
|------------|--------|---------|----------|-----------|------------|
| `ioc_file_hashes` | file_rep | 490M | 88 bytes | **43 GB** | ~65 GB |
| `ioc_domains` | domain_classification | 245M | 50 bytes | **12 GB** | ~18 GB |
| `ioc_ips` | SINKHOLE_IDENTIFIERS | 3K | 70 bytes | **0.2 MB** | ~0.5 MB |
| **Total** | | | | **~55 GB** | **~83 GB** |

### Transfer File Sizes (gzip compressed NDJSON)

| Strategy | Data for Transfer | gzip Compressed | Notes |
|----------|-------------------|-----------------|-------|
| **A: Malicious Only** | ~8 GB NDJSON | **~2 GB** | Recommended |
| **B: All VT Data** | ~55 GB NDJSON | **~15 GB** | Complete VT data |

### Compression Summary

```
Original MongoDB (Root):     9.5 TB (100%)
    ↓ Filter response_code=0
Valid VT Data:               ~950 GB (10%)
    ↓ Filter positives=0
Malicious Only:              ~95 GB (1%)
    ↓ Extract to TiDB schema
TiDB Row Format:             ~8 GB (0.08%)
    ↓ gzip for transfer
Transfer File:               ~2 GB (0.02%)
```

---

## Verification Commands

```bash
# Login to GCS
gcloud auth login

# Compare root vs new/ directory
gsutil ls -l gs://sage_prod_dump/cr-mongo-shard-r01.cybereason.net/cybereason/file_rep.bson
gsutil ls -l gs://sage_prod_dump/new/cr-mongo-shard-r01.cybereason.net/cybereason/file_rep.bson

# Calculate total size
for shard in r01 r02 r03 r04 r05 r06; do
    gsutil ls -l "gs://sage_prod_dump/new/cr-mongo-shard-${shard}.cybereason.net/cybereason/file_rep.bson"
done
```

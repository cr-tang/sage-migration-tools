---
name: TI Data Migration Completion
overview: Complete the pending TI data migrations using MongoDB dump as baseline, with VT Feeder for future updates on file hashes. Internal data updates are deferred.
todos:
  - id: setup-repo
    content: Move scripts and docs to sage-migration-tools repo
    status: completed
  - id: file-hashes-processing
    content: Run parallel_bson_processor.py for all shards (r01-r06) on phoenix-vt-feeder
    status: in_progress
  - id: file-hashes-import
    content: Import processed file_rep NDJSON to TiDB ioc_file_hashes
    status: pending
  - id: domain-processing
    content: Run domain_bson_processor.py for domain_classification
    status: pending
  - id: domain-import
    content: Import processed domains to TiDB ioc_domains
    status: pending
isProject: false
---

# TI Data Migration Completion Plan

## Current Status (Updated 2026-02-03)

| Table                           | Status       | Notes                                    |
| ------------------------------- | ------------ | ---------------------------------------- |
| `ioc_tokens`                    | ✅ Done      | ~2,500 records                           |
| `file_extension_classification` | ✅ Done      | ~337 records                             |
| `ioc_ips`                       | ✅ Done      | Via TOKENS (IPv4 entries only)           |
| `customer_ioc`                  | ✅ Schema Ready | Runtime populated via API             |
| `ioc_file_hashes`               | 🔄 In Progress | Processing r01-r06 shards              |
| `ioc_domains`                   | ⏳ Pending   | Script ready, not started yet            |

**Note:** SINKHOLE_IDENTIFIERS is NOT imported - per rule team, SINKHOLED IPs are "a diversion from blacklisted", not treated as blacklisted.

## Data Source Strategy

```
Baseline: MongoDB Dump (2020-11-05)
├── file_rep              → ioc_file_hashes (In Progress)
├── domain_classification → ioc_domains (Pending)
└── TOKENS (IPv4 entries) → ioc_ips (Done via TOKENS import)

Future Updates:
├── File Hashes: VT Feeder GCS (vt-file-feeder/latest-reports/{sha1})
├── Domains: VT Lookup API (no GCS cache, consider on-demand + cache)
└── IPs: Manually maintained via TOKENS
```

## Phase 1: ioc_file_hashes (In Progress)

**Script:** `scripts/parallel_bson_processor.py`

**Run on phoenix-vt-feeder server:**

```bash
# Process each shard
for shard in r01 r02 r03 r04 r05 r06; do
  nohup python3 parallel_bson_processor.py --shard $shard > bson_${shard}.log 2>&1 &
done
```

**Estimated time:** ~5 hours per shard, ~30 hours total

**Output files:**
- `file_rep_r01_full.ndjson.gz` ... `file_rep_r06_full.ndjson.gz`

## Phase 2: ioc_domains (Pending)

**Script:** `scripts/domain_bson_processor.py`

**Run on phoenix-vt-feeder server:**

```bash
# Process each shard
for shard in r01 r02 r03 r04 r05 r06; do
  nohup python3 domain_bson_processor.py --shard $shard > domain_${shard}.log 2>&1 &
done
```

**Filtering Logic:**
- Skip: `maliciousClassification=unknown` (VT has no data)
- Skip: `maliciousClassification=indifferent` (neutral, unless has detectedUrls)
- Keep: Malicious classification or `detectedUrls` with `positives > 0`

## Phase 3: Import to TiDB

**Script:** `scripts/tidb_importer.py`

```bash
# Import file hashes
python3 tidb_importer.py \
  --input-file file_rep_r01_full.ndjson.gz \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --database threat_intel \
  --table ioc_file_hashes

# Import domains
python3 tidb_importer.py \
  --input-file domain_classification_r01.ndjson.gz \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --database threat_intel \
  --table ioc_domains
```

## Scripts Available

| Script | Purpose | Status |
| ------ | ------- | ------ |
| `parallel_bson_processor.py` | Process file_rep BSON | ✅ Ready |
| `domain_bson_processor.py` | Process domain_classification BSON | ✅ Ready |
| `tidb_importer.py` | Import NDJSON to TiDB | ✅ Ready |
| `tokens_importer.py` | Import TOKENS collection | ✅ Used |
| `generate_sinkhole_seed.py` | Generate sinkhole seed (NOT NEEDED) | ❌ Not used |

## Update Strategy (Future)

| Data Type | Update Source | Method |
| --------- | ------------- | ------ |
| File Hash | VT Feeder GCS | Direct GCS read by Phoenix (future) |
| Domain    | VT Lookup API | On-demand query + cache in TiDB |
| IP        | TOKENS        | Manually maintained |

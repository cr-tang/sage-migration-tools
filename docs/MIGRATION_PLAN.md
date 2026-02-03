---
name: TI Data Migration Completion
overview: Complete the pending TI data migrations using MongoDB dump as baseline, with VT Feeder for future updates on file hashes. Internal data updates are deferred.
todos:
  - id: setup-repo
    content: Move scripts and docs to sage-migration-tools repo
    status: in_progress
  - id: file-hashes-remaining
    content: Run parallel_bson_processor.py for remaining 5 shards (r01-r05) on phoenix-vt-feeder
    status: pending
  - id: sinkhole-importer
    content: Create sinkhole_importer.py to import SINKHOLE_IDENTIFIERS + TOKENS IPs to ioc_ips
    status: pending
  - id: domain-processor
    content: Create domain_bson_processor.py to process domain_classification BSON
    status: pending
  - id: tidb-import
    content: Import processed data to TiDB (file_hashes, ips, domains)
    status: pending
  - id: update-docs
    content: Update USAGE.md and TI_DATA_MIGRATION_PLAN.html
    status: pending
isProject: false
---

# TI Data Migration Completion Plan

## Current Status


| Table                           | Status       | Notes                                    |
| ------------------------------- | ------------ | ---------------------------------------- |
| `ioc_tokens`                    | Done         | ~2,500 records                           |
| `file_extension_classification` | Done         | ~337 records                             |
| `ioc_file_hashes`               | In Progress  | r06 done (143K records), r01-r05 pending |
| `ioc_domains`                   | Pending      | Need processing script                   |
| `ioc_ips`                       | Pending      | SINKHOLE_IDENTIFIERS + TOKENS IP entries |
| `customer_ioc`                  | Schema Ready | Runtime populated via API                |


## Data Source Strategy

```
Baseline: MongoDB Dump (2020-11-05)
├── file_rep         → ioc_file_hashes (In Progress)
├── domain_classification → ioc_domains (Pending)
├── SINKHOLE_IDENTIFIERS → ioc_ips (Pending)
└── TOKENS (IP entries) → ioc_ips (Pending)

Future Updates:
├── File Hashes: VT Feeder GCS (vt-file-feeder/latest-reports/{sha1})
├── Domains: VT Lookup API (no GCS cache, consider on-demand + cache)
└── IPs: Manually maintained via Sage API (deferred)
```

## Phase 1: Complete ioc_file_hashes (Remaining 5 Shards)

Already have [parallel_bson_processor.py](tools/scripts/parallel-bson-processor/parallel_bson_processor.py) working.

**Run on phoenix-vt-feeder server:**

```bash
for shard in r01 r02 r03 r04 r05; do
  python3 parallel_bson_processor.py \
    --input-file gs://sage_prod_dump/${shard}/cybereason/file_rep.bson \
    --output-file file_rep_${shard}_full.ndjson.gz \
    --log-file bson_processor_${shard}.log \
    --workers 40
done
```

**Estimated time:** ~~25 hours total (~~5 hours/shard)

## Phase 2: Create ioc_ips Importer

Simple script since data is small (~3,500 records total).

**Data Sources:**

1. SINKHOLE_IDENTIFIERS (~3,000 IPs) - `gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson`
2. TOKENS IP entries (~500 IPs) - Already in `ioc_tokens`, filter by `indicator_type='IPV4'`

**Schema mapping:**

```python
# SINKHOLE_IDENTIFIERS
{
  "_id": {"identifier": "104.236.245.219"},
  "value": {"type": "IP", "entity": "Georgia Tech / Damballa"}
}
# → ioc_ips
{
  "ip": INET6_ATON("104.236.245.219"),
  "ip_version": 4,
  "classification": "SINKHOLED",
  "source": "SINKHOLE_IDENTIFIERS",
  "sinkhole_entity": "Georgia Tech / Damballa"
}

# TOKENS (IP entries)
{
  "_id": "1.2.3.4",
  "value": {"type": "IPv4", "maliciousType": "malware"}
}
# → ioc_ips
{
  "ip": INET6_ATON("1.2.3.4"),
  "ip_version": 4,
  "classification": "MALWARE",
  "source": "TOKENS",
  "sinkhole_entity": NULL
}
```

**Create:** `tools/scripts/parallel-bson-processor/sinkhole_importer.py`

## Phase 3: Create ioc_domains Processor

**Data Source:** `gs://sage_prod_dump/r01-r06/cybereason/domain_classification.bson` (~446 GB)

**Filtering Logic (similar to file_rep):**

```python
# Skip:
# - response contains "maliciousClassification=unknown" (VT has no data)
# - response contains "maliciousClassification=indifferent" (neutral)

# Keep:
# - maliciousClassification=malware, whitelist, etc.
# - OR value.detectedUrls has entries with positives > 0
```

**Sample record:**

```json
{
  "_id": "malicious.com",
  "response": "maliciousClassification=malware",
  "value": {
    "responseCode": 1,
    "detectedUrls": [{"url": "...", "positives": 4, "total": 71}],
    "categories": ["malware"]
  }
}
```

**Options:**

- **Option A:** Modify `parallel_bson_processor.py` to support `--type domain`
- **Option B:** Create separate `domain_bson_processor.py` (simpler, no Broccoli dependency)

**Recommended: Option B** - Domain processing is simpler (no ML re-classification needed).

**Create:** `tools/scripts/parallel-bson-processor/domain_bson_processor.py`

## Phase 4: Import to TiDB

Use existing [tidb_importer.py](tools/scripts/parallel-bson-processor/tidb_importer.py) or create table-specific importers.

**Import order:**

1. `ioc_file_hashes` - From processed NDJSON files
2. `ioc_ips` - From sinkhole_importer.py output
3. `ioc_domains` - From domain_bson_processor.py output

## Deliverables


| File                                  | Purpose                                             |
| ------------------------------------- | --------------------------------------------------- |
| `sinkhole_importer.py`                | Import SINKHOLE_IDENTIFIERS + TOKENS IPs to ioc_ips |
| `domain_bson_processor.py`            | Process domain_classification BSON to NDJSON        |
| Updated `USAGE.md`                    | Document new scripts                                |
| Updated `TI_DATA_MIGRATION_PLAN.html` | Track progress                                      |


## Update Strategy (Future)


| Data Type | Update Source | Method                                           |
| --------- | ------------- | ------------------------------------------------ |
| File Hash | VT Feeder GCS | Direct GCS read by Phoenix (future optimization) |
| Domain    | VT Lookup API | On-demand query + cache in TiDB                  |
| IP        | Sage API      | Deferred - manually maintained                   |



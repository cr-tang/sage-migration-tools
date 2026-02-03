# Sage Migration Tools - Agent Guide

## Project Purpose

Migrate Threat Intelligence data from Sage (MongoDB on GCS) to Phoenix (TiDB) for real-time enrichment.

## Quick Reference

| Need to... | Check |
|------------|-------|
| Understand project structure | `.cursor/rules/project.md` |
| Connect to GCS | `.cursor/skills/gcs/SKILL.md` |
| Connect to TiDB | `.cursor/skills/tidb/SKILL.md` |
| Run scripts on VM | `.cursor/skills/run-on-vm/SKILL.md` |
| See script usage | `docs/USAGE.md` |
| Check migration status | `docs/TI_DATA_MIGRATION_PLAN.html` |
| Understand MongoDB schema | `docs/schema/SCHEMA_SUMMARY.md` |
| View sample data | `samples/` directory |

## Data Flow

```
MongoDB Dump (GCS)           Processing Script              TiDB
──────────────────          ──────────────────          ───────────
file_rep.bson        →   parallel_bson_processor.py  →  ioc_file_hashes
domain_classification.bson → domain_bson_processor.py →  ioc_domains
SINKHOLE_IDENTIFIERS.bson → sinkhole_importer.py     →  ioc_ips
TOKENS.bson          →   tokens_importer.py          →  ioc_tokens
```

## Common Tasks

### 1. Process New Data Shard
```bash
# On phoenix-vt-feeder VM
python3 parallel_bson_processor.py --shard r01
```

### 2. Import Processed Data
```bash
python3 tidb_importer.py \
  --input-file file_rep_r01_full.ndjson.gz \
  --host tidb-stg-ap-tokyo-1.cybereason.net \
  --database threat_intel \
  --table ioc_file_hashes
```

### 3. Check Migration Progress
- Open `docs/TI_DATA_MIGRATION_PLAN.html` in browser
- Query TiDB: `SELECT COUNT(*) FROM ioc_file_hashes;`

## Related Repositories

| Repo | Purpose | Key Files |
|------|---------|-----------|
| phoenix-flink | TI enrichment in Flink | `ThreatIntelService.kt`, `TidbStorage.kt` |
| Phoenix | TiDB migrations | `migrations/mysql/up/*.sql` |
| sage-content-provider | Original Sage service | MongoDB integration |
| vt-feeder-suite | VT Feed ingestion | GCS storage logic |

# Generate Seed Files for Small Datasets

For small static datasets (< 10,000 records), use SQL seed files instead of Python import scripts.

## When to Use Seeder

| Data | Size | Approach | Status |
|------|------|----------|--------|
| TOKENS | ~2,500 | Seed file | Done |
| FILE_EXTENSION_CLASSIFICATION | ~337 | Seed file | Done |
| file_rep | ~1M+ | Python processor | In Progress |
| domain_classification | ~50M+ | Python processor | Pending |

**Note**: SINKHOLE_IDENTIFIERS is NOT imported - SINKHOLED IPs are not treated as blacklisted per rule team.

## Seed File Location in Phoenix

```
Phoenix/
└── migrations/
    └── mysql/
        └── seed/
            ├── seeder.sql                # Main seeder (test data)
            └── data/
                └── 20260121134500_file_extension_classification.sql
```

## Benefits of Seeder Approach

1. **Version controlled** - Data changes tracked in git
2. **Reproducible** - Every environment gets same data
3. **Simple deployment** - Just run `migrate-ti.sh seed`
4. **No runtime dependencies** - No Python/GCS needed at deploy time

## IP Data

IP data comes from **TOKENS** collection only (entries with type="IPv4").
These are imported via `tokens_importer.py` to both `ioc_tokens` and used for IP lookups.

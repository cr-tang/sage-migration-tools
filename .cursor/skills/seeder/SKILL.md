# Generate Seed Files for Small Datasets

For small static datasets (< 10,000 records), use SQL seed files instead of Python import scripts.

## When to Use Seeder

| Data | Size | Approach |
|------|------|----------|
| SINKHOLE_IDENTIFIERS | ~3,000 | Seed file |
| TOKENS | ~2,500 | Seed file (done) |
| FILE_EXTENSION_CLASSIFICATION | ~337 | Seed file (done) |
| file_rep | ~1M+ | Python processor |
| domain_classification | ~50M+ | Python processor |

## Generate Sinkhole Seed File

```bash
cd ~/work/sage-migration-tools/scripts

# Use local BSON from samples/bson/
python3 generate_sinkhole_seed.py \
  --input ../samples/bson/SINKHOLE_IDENTIFIERS.bson \
  --output sinkhole_identifiers_seed.sql
```

## Deploy Seed File

```bash
# 1. Copy to Phoenix repo
cp sinkhole_identifiers_seed.sql \
  ~/work/Phoenix/migrations/mysql/seed/data/20260130000000_sinkhole_identifiers.sql

# 2. Run seeder
cd ~/work/Phoenix
./scripts/migrate-ti.sh seed
```

## Seed File Location in Phoenix

```
Phoenix/
└── migrations/
    └── mysql/
        └── seed/
            ├── seeder.sql                # Main seeder (test data)
            └── data/
                ├── 20260121134500_file_extension_classification.sql
                └── 20260130000000_sinkhole_identifiers.sql  # New
```

## Benefits of Seeder Approach

1. **Version controlled** - Data changes tracked in git
2. **Reproducible** - Every environment gets same data
3. **Simple deployment** - Just run `migrate-ti.sh seed`
4. **No runtime dependencies** - No Python/GCS needed at deploy time

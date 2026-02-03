# GCS Connection and Data Access

## Prerequisites

### 1. Install Google Cloud SDK
```bash
# macOS
brew install google-cloud-sdk

# Linux
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
```

### 2. Authenticate
```bash
# Login with browser (for local development)
gcloud auth login
gcloud auth application-default login

# Set project
gcloud config set project cybereason-production
```

### 3. Verify Access
```bash
# List sage_prod_dump bucket
gsutil ls gs://sage_prod_dump/

# Check file size
gsutil du -s gs://sage_prod_dump/r01/cybereason/file_rep.bson
```

## Data Locations

### MongoDB Dumps (sage_prod_dump)
```
gs://sage_prod_dump/
├── r01/ - r06/              # 6 shards
│   └── cybereason/
│       ├── file_rep.bson              # ~950GB each, 5.6TB total
│       ├── domain_classification.bson # ~75GB each, 446GB total
│       ├── domain_dns.bson            # ~640GB each, 3.85TB total
│       └── ...
├── r01/cybereason/TOKENS.bson         # ~890KB
├── r02/cybereason/SINKHOLE_IDENTIFIERS.bson  # ~456KB
└── r04/cybereason/FILE_EXTENSION_CLASSIFICATION.bson  # ~105KB
```

### VT Feeder Data
```
gs://vt-file-feeder/
└── latest-reports/
    └── {sha1}                         # Latest VT report by SHA1

gs://broccoli-enricher/
└── latest-reports/
    └── {sha1}                         # ML classification by SHA1
```

## Common Commands

### Download Sample
```bash
# Download first 100MB of file_rep
gsutil cp -r gs://sage_prod_dump/r01/cybereason/file_rep.bson - | head -c 104857600 > sample.bson
```

### Check File Info
```bash
# Get file metadata
gsutil stat gs://sage_prod_dump/r01/cybereason/file_rep.bson

# List with sizes
gsutil ls -l gs://sage_prod_dump/r01/cybereason/
```

### Python GCS Access
```python
from google.cloud import storage

client = storage.Client()
bucket = client.bucket('sage_prod_dump')
blob = bucket.blob('r01/cybereason/file_rep.bson')

# Get size
blob.reload()
print(f"Size: {blob.size / (1024**3):.2f} GB")

# Download range
data = blob.download_as_bytes(start=0, end=1024*1024)  # First 1MB
```

## Troubleshooting

### Permission Denied
```bash
# Check current identity
gcloud auth list

# Re-authenticate
gcloud auth application-default login
```

### Slow Downloads
- Use chunked downloads in Python (256MB chunks recommended)
- Run from GCP VM for faster network (phoenix-vt-feeder)

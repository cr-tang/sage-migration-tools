# VT Feeder Unboxing

> Complete technical documentation of the VirusTotal Feeder data pipeline and Sage integration.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Diagram](#architecture-diagram)
3. [VT Feeder Suite](#vt-feeder-suite)
4. [GCS Bucket Structure](#gcs-bucket-structure)
5. [Broccoli Classification Service](#broccoli-classification-service)
6. [Sage Query Flow](#sage-query-flow)
7. [MongoDB Role](#mongodb-role)
8. [Data Type Comparison](#data-type-comparison)
9. [Key Takeaways](#key-takeaways)

---

## Overview

### What is VT Feeder?

VT Feeder is a data pipeline that:
1. **Pulls** full data stream from VirusTotal Feed API (every minute)
2. **Stores** raw reports in GCS buckets (indexed by hash)
3. **Enriches** reports with ML classification (Broccoli service)
4. **Serves** data to Sage for real-time queries

### Why VT Feeder instead of Direct VT API?

| Aspect | Direct VT API | VT Feeder |
|--------|--------------|-----------|
| **Speed** | ~500ms per query | ~50ms per query |
| **Rate Limit** | Limited by VT API quota | No limit (pre-fetched) |
| **Cost** | Per-query API cost | Fixed storage cost |
| **Data Coverage** | On-demand only | Full VT dataset |
| **Classification** | Raw results only | ML-enhanced classification |

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        VT Feeder Complete Architecture                               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ╔═══════════════════════════════════════════════════════════════════════════════╗  │
│  ║  LAYER 1: Data Ingestion (VT Feeder Suite)                                    ║  │
│  ╠═══════════════════════════════════════════════════════════════════════════════╣  │
│  ║                                                                               ║  │
│  ║   ┌──────────────────┐                                                        ║  │
│  ║   │  VirusTotal      │                                                        ║  │
│  ║   │  Feed API        │  /vtapi/v2/file/feed?package={timestamp}              ║  │
│  ║   │  (Premium)       │  Returns: tar.bz2 with ALL files scanned that minute  ║  │
│  ║   └────────┬─────────┘                                                        ║  │
│  ║            │                                                                  ║  │
│  ║            │ Every 60 seconds                                                 ║  │
│  ║            ▼                                                                  ║  │
│  ║   ┌──────────────────┐                                                        ║  │
│  ║   │  VT Feeder Suite │  VtFeederSchedulerService.java                        ║  │
│  ║   │  (Scheduled Job) │  VtFeederPackageHandlerService.java                   ║  │
│  ║   └────────┬─────────┘                                                        ║  │
│  ║            │                                                                  ║  │
│  ║            ├──────────────────────┬──────────────────────┐                   ║  │
│  ║            │                      │                      │                   ║  │
│  ║            ▼                      ▼                      ▼                   ║  │
│  ║   ┌────────────────┐    ┌────────────────┐    ┌────────────────┐            ║  │
│  ║   │ vt-file-feeder │    │ vt-file-feeder │    │ Broccoli       │            ║  │
│  ║   │ /latest-reports│    │ -by-date/      │    │ Service        │            ║  │
│  ║   │ /{sha1}        │    │ {date}/{ts}    │    │ (ML Pipeline)  │            ║  │
│  ║   └────────────────┘    └────────────────┘    └───────┬────────┘            ║  │
│  ║         │                                             │                      ║  │
│  ║         │ Real-time lookup                            │                      ║  │
│  ║         │ by hash                                     ▼                      ║  │
│  ║         │                                    ┌────────────────┐              ║  │
│  ║         │                                    │broccoli-enricher              ║  │
│  ║         │                                    │/latest-reports │              ║  │
│  ║         │                                    │/{sha1}         │              ║  │
│  ║         │                                    └────────────────┘              ║  │
│  ║         │                                             │                      ║  │
│  ╚═════════╪═════════════════════════════════════════════╪══════════════════════╝  │
│            │                                             │                         │
│            └──────────────────┬──────────────────────────┘                         │
│                               │                                                    │
│  ╔════════════════════════════╪════════════════════════════════════════════════╗   │
│  ║  LAYER 2: Sage Service     │                                                ║   │
│  ╠════════════════════════════╪════════════════════════════════════════════════╣   │
│  ║                            ▼                                                ║   │
│  ║   ┌──────────────────────────────────────────────────────────────────────┐  ║   │
│  ║   │  VtFeederClient.java                                                 │  ║   │
│  ║   │                                                                      │  ║   │
│  ║   │  getReport(sha1)        → reads vt-file-feeder/latest-reports/{sha1}│  ║   │
│  ║   │  getClassification(sha1) → reads broccoli-enricher/latest-reports/  │  ║   │
│  ║   └──────────────────────────────────────────────────────────────────────┘  ║   │
│  ║                            │                                                ║   │
│  ║                            ▼                                                ║   │
│  ║   ┌──────────────────────────────────────────────────────────────────────┐  ║   │
│  ║   │  VirusTotalFileClassificationService.java                            │  ║   │
│  ║   │                                                                      │  ║   │
│  ║   │  - Combine raw report + ML classification                           │  ║   │
│  ║   │  - Calculate product classification                                  │  ║   │
│  ║   │  - Set TTL for cache expiration                                     │  ║   │
│  ║   └──────────────────────────────────────────────────────────────────────┘  ║   │
│  ║                            │                                                ║   │
│  ║                            ▼                                                ║   │
│  ║   ┌──────────────────────────────────────────────────────────────────────┐  ║   │
│  ║   │  MongoDB file_rep Collection (Cache)                                 │  ║   │
│  ║   │                                                                      │  ║   │
│  ║   │  - Stores processed classification results                          │  ║   │
│  ║   │  - Avoids re-querying GCS for same hash                             │  ║   │
│  ║   │  - Managed by TTL for freshness                                     │  ║   │
│  ║   └──────────────────────────────────────────────────────────────────────┘  ║   │
│  ║                                                                             ║   │
│  ╚═════════════════════════════════════════════════════════════════════════════╝   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## VT Feeder Suite

### Repository Location

```
/Users/tangxin/work/vt-feeder-suite/
├── services/
│   ├── vt-file-feeder/          # File reports feeder
│   ├── vt-url-feeder/           # URL reports feeder
│   ├── bq-vt-file-report-exporter/   # BigQuery exporter
│   └── bq-vt-url-report-exporter/    # URL to BigQuery
└── common/
    └── vt-feeder-spring-starter/     # Core feeder logic
```

### How VT Feeder Works

#### 1. Scheduled Data Pull

```java
// VtFeederSchedulerService.java
@Scheduled(fixedRateString = "${feederRate:60000}")  // Every 60 seconds
public void scheduleFixedDelayTask() {
    getFeeds();
}
```

#### 2. Download from VT Feed API

```java
// VtFeederPackageHandlerService.java
String feedPkgUrl = "https://www.virustotal.com/vtapi/v2/" + feedType + 
    "/feed?apikey=" + apiKey + "&package=" + timestamp;

// Downloads tar.bz2 package containing ALL files scanned in that minute
```

#### 3. Store to GCS

```java
// For File Feeder (should.store.latest.by.identifier=true)
private void storeFeedsLatestByIdentifier(List<String> allJsonReports) {
    for (String jsonReport : allJsonReports) {
        String identifier = jsonFileReportObject.get("sha1").getAsString();
        String blobPackageName = latestReportFolderName + "/" + identifier;
        gcsStorageConnector.store(jsonReport.getBytes(), blobPackageName, bucketName);
    }
}

// Archive by date (both File and URL)
private void storeFeedsByDate(VtTimePackage timestamp, File feedPackage) {
    String blobPackageName = timestamp.getPackageDateString() + "/" + timestamp.getPackageFullString();
    gcsStorageConnector.store(IOUtils.toByteArray(new FileInputStream(feedPackage)), blobPackageName, feedByDateBucketName);
}
```

### Configuration

**File Feeder** (`vt-file-feeder/application.properties`):
```properties
bucket.name=vt-file-feeder
feeds.by.date.bucket.name=vt-file-feeder-by-date
latest.report.folder.name=latest-reports
should.store.latest.by.identifier=true   # ← Key: Store by SHA1 hash
vt.feed.type=file
```

**URL Feeder** (`vt-url-feeder/application.properties`):
```properties
bucket.name=vt-url-feeder
feeds.by.date.bucket.name=vt-url-feeder-by-date
should.store.latest.by.identifier=false  # ← Key: NOT stored by identifier!
vt.feed.type=url
gcp.bq.enable=true                        # ← URL goes to BigQuery instead
```

---

## GCS Bucket Structure

### Complete Bucket Map

```
Google Cloud Storage
│
├── vt-file-feeder/                          # File reports (real-time lookup)
│   ├── latest-reports/
│   │   ├── {sha1_hash_1}                    # JSON file, ~10KB
│   │   ├── {sha1_hash_2}
│   │   └── ... (millions of files)
│   └── lastPackage                          # Timestamp of last processed package
│
├── vt-file-feeder-by-date/                  # File reports archive
│   ├── 20251224/
│   │   ├── 20251224T0000                    # tar.bz2, ~50MB, all files at 00:00
│   │   ├── 20251224T0001
│   │   └── ... (1440 packages per day)
│   └── 20251225/
│       └── ...
│
├── broccoli-enricher/                       # ML classification results
│   └── latest-reports/
│       ├── {sha1_hash_1}                    # JSON file, ~100 bytes
│       ├── {sha1_hash_2}
│       └── ...
│
└── vt-url-feeder-by-date/                   # URL reports (time-based only!)
    ├── 20251224/
    │   ├── 20251224T0000                    # bzip2, ~2MB, all URLs at 00:00
    │   └── ...
    └── ...
```

### Bucket Comparison Table

| Bucket | Path | Index Key | Query Method | Size/File | Purpose |
|--------|------|-----------|--------------|-----------|---------|
| `vt-file-feeder` | `/latest-reports/{sha1}` | SHA1 hash | ✅ Exact lookup | ~10 KB | Real-time file queries |
| `vt-file-feeder-by-date` | `/{date}/{timestamp}` | Timestamp | ❌ Time-based only | ~50 MB | Historical archive |
| `broccoli-enricher` | `/latest-reports/{sha1}` | SHA1 hash | ✅ Exact lookup | ~100 B | ML classification cache |
| `vt-url-feeder-by-date` | `/{date}/{timestamp}` | Timestamp | ❌ Time-based only | ~2 MB | URL archive (batch analysis) |

---

## Broccoli Classification Service

### What is Broccoli?

**Broccoli** (Classifier V2) is Sage's **ML-based classification service**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Broccoli Service                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input: Raw VT Report                                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ {                                                                     │  │
│  │   "sha1": "abc123",                                                   │  │
│  │   "positives": 45,                                                    │  │
│  │   "scans": {                                                          │  │
│  │     "Kaspersky": {"detected": true, "result": "Trojan.Win32"},       │  │
│  │     "McAfee": {"detected": true, "result": "Artemis"},               │  │
│  │     "Symantec": {"detected": false, "result": null},                 │  │
│  │     ... (70+ engines with conflicting results!)                      │  │
│  │   }                                                                   │  │
│  │ }                                                                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              │ ML Model                                     │
│                              │ - Analyzes all AV engine results             │
│                              │ - Weighs engine quality scores               │
│                              │ - Computes final classification              │
│                              ▼                                              │
│  Output: Classification Result                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ {                                                                     │  │
│  │   "classification": "malware",  ← Final verdict                      │  │
│  │   "algoVersion": "2.3.1"        ← Model version                      │  │
│  │ }                                                                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why ML Classification?

| Problem | Without ML | With Broccoli ML |
|---------|-----------|------------------|
| Conflicting AV results | Which engine to trust? | Weighted score based on engine quality |
| New malware variants | May be missed | Pattern recognition |
| False positives | Hard to filter | Learned from historical data |
| Classification types | Simple majority voting | Accurate type/subtype detection |

### Broccoli Data Flow

```
VT Report ──► Broccoli Service ──► broccoli-enricher bucket
                   │
                   │ Via SQS (async)
                   │
              ┌────┴────┐
              │ ML Model │
              └────┬────┘
                   │
                   ▼
            Classification
```

---

## Sage Query Flow

### File Classification (Complete Flow)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                     Sage File Classification Query Flow                              │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Client Request: classify("sha1:abc123")                                            │
│                         │                                                           │
│                         ▼                                                           │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │  Step 1: Check MongoDB Cache                                                  │  │
│  │                                                                               │  │
│  │  lookupCache.getIfPresent("abc123")                                          │  │
│  │    │                                                                          │  │
│  │    ├── HIT + not expired ──► Return cached classification                    │  │
│  │    │                                                                          │  │
│  │    └── MISS or expired ──► Continue to Step 2                                │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
│                         │                                                           │
│                         ▼                                                           │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │  Step 2: Query GCS (Parallel)                                                 │  │
│  │                                                                               │  │
│  │  ┌─────────────────────────────┐    ┌─────────────────────────────┐          │  │
│  │  │  vt-file-feeder             │    │  broccoli-enricher          │          │  │
│  │  │  /latest-reports/abc123     │    │  /latest-reports/abc123     │          │  │
│  │  │                             │    │                             │          │  │
│  │  │  VtFeederClient             │    │  VtFeederClient             │          │  │
│  │  │  .getReport("abc123")       │    │  .getClassification("abc123")│         │  │
│  │  └──────────────┬──────────────┘    └──────────────┬──────────────┘          │  │
│  │                 │                                  │                          │  │
│  │                 ▼                                  ▼                          │  │
│  │  ┌─────────────────────────────┐    ┌─────────────────────────────┐          │  │
│  │  │  Raw VT Report              │    │  ML Classification          │          │  │
│  │  │  - sha1, md5, sha256        │    │  - "malware"                │          │  │
│  │  │  - positives: 45            │    │  - algoVersion: "2.3.1"     │          │  │
│  │  │  - scans: {...}             │    │                             │          │  │
│  │  │  - submission_names         │    │  (May be null if new file)  │          │  │
│  │  └──────────────┬──────────────┘    └──────────────┬──────────────┘          │  │
│  │                 │                                  │                          │  │
│  │                 └─────────────┬────────────────────┘                          │  │
│  │                               │                                               │  │
│  └───────────────────────────────┼───────────────────────────────────────────────┘  │
│                                  │                                                  │
│                                  ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │  Step 3: Process & Combine                                                    │  │
│  │                                                                               │  │
│  │  if (broccoli classification exists && valid algo version):                   │  │
│  │      maliciousType = broccoli.classification                                  │  │
│  │  else:                                                                        │  │
│  │      // Call Broccoli service async, use v1 classification meanwhile         │  │
│  │      sendToBroccoliQueue(vtReport)                                           │  │
│  │      maliciousType = calculateV1Classification(vtReport)                      │  │
│  │                                                                               │  │
│  │  productClassification = analyzeProductName(vtReport.submission_names)        │  │
│  │  ttl = calculateTTL(maliciousType)                                           │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
│                                  │                                                  │
│                                  ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │  Step 4: Save to MongoDB & Return                                             │  │
│  │                                                                               │  │
│  │  dataElement = {                                                              │  │
│  │      key: "abc123",                                                          │  │
│  │      value: vtReport,                      // Raw VT data                    │  │
│  │      vtClassifierV2Classification: {...},  // Broccoli result                │  │
│  │      response: classificationResult,       // Final classification           │  │
│  │      expiration: now + ttl,                // Cache expiration               │  │
│  │      firstSeen: timestamp                  // First query time               │  │
│  │  }                                                                            │  │
│  │                                                                               │  │
│  │  persistenceManager.save(dataElement, "file_rep")                            │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
│                                  │                                                  │
│                                  ▼                                                  │
│  Return to Client:                                                                  │
│  {                                                                                  │
│      "maliciousClassification": {                                                   │
│          "type": "malware",                                                         │
│          "subTypes": ["trojan", "downloader"]                                       │
│      },                                                                             │
│      "productClassification": {...},                                                │
│      "sha1": "abc123",                                                              │
│      "positives": 45,                                                               │
│      "link": "https://virustotal.com/..."                                          │
│  }                                                                                  │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Domain Classification Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                     Domain Classification Flow                                       │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Client: classify("example.com")                                                    │
│                    │                                                                │
│                    ▼                                                                │
│  ┌──────────────────────────────┐                                                   │
│  │ MongoDB domain_classification│ ─── HIT ──► Return cached                        │
│  └──────────────────────────────┘                                                   │
│                    │ MISS                                                           │
│                    ▼                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │  VirusTotal API (Direct Call)                                                │   │
│  │                                                                              │   │
│  │  ⚠️ NO GCS BUCKET for domains! Uses VT API directly!                        │   │
│  │                                                                              │   │
│  │  https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com       │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                    │                                                                │
│                    ▼                                                                │
│  Process + Save to MongoDB                                                          │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### URL Classification Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        URL Classification Flow                                       │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Client: classify("https://example.com/malware.exe")                                │
│                    │                                                                │
│                    ▼                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │  VirusTotal API (Direct Call)                                                │   │
│  │                                                                              │   │
│  │  ⚠️ vt-url-feeder-by-date exists but NOT used for real-time queries!        │   │
│  │     (Only for batch analysis/archival)                                       │   │
│  │                                                                              │   │
│  │  https://www.virustotal.com/vtapi/v2/url/report?resource=...                │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## MongoDB Role

### Three Functions of MongoDB

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           MongoDB in Sage Architecture                               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌────────────────────────────────────────────────────────────────────────────┐     │
│  │  Function 1: Query Cache                                                   │     │
│  │                                                                            │     │
│  │  - Avoid re-querying GCS for the same hash                                │     │
│  │  - Faster response (MongoDB vs GCS latency)                               │     │
│  │  - Managed by TTL for data freshness                                       │     │
│  │                                                                            │     │
│  │  Collections: file_rep, domain_classification                              │     │
│  └────────────────────────────────────────────────────────────────────────────┘     │
│                                                                                     │
│  ┌────────────────────────────────────────────────────────────────────────────┐     │
│  │  Function 2: Store Processed Results                                       │     │
│  │                                                                            │     │
│  │  GCS stores raw VT data, MongoDB stores:                                   │     │
│  │  - Computed classification (maliciousType, subTypes)                       │     │
│  │  - Product classification                                                   │     │
│  │  - Broccoli ML results (vtClassifierV2Classification)                      │     │
│  │  - First seen timestamp, format version                                    │     │
│  └────────────────────────────────────────────────────────────────────────────┘     │
│                                                                                     │
│  ┌────────────────────────────────────────────────────────────────────────────┐     │
│  │  Function 3: Background Update Target                                      │     │
│  │                                                                            │     │
│  │  FeedProcessingTask (Scheduled Job):                                       │     │
│  │  - Downloads VT feed packages directly from VT API                         │     │
│  │  - Updates ONLY existing records in MongoDB                                │     │
│  │  - Keeps cached data fresh even without client queries                     │     │
│  │                                                                            │     │
│  │  Note: Does NOT import new records, only updates existing ones            │     │
│  └────────────────────────────────────────────────────────────────────────────┘     │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### MongoDB vs GCS Content Comparison

| Field | GCS (vt-file-feeder) | GCS (broccoli-enricher) | MongoDB (file_rep) |
|-------|---------------------|------------------------|-------------------|
| Raw VT Report | ✅ Full report | ❌ | ✅ Cached copy |
| SHA1/MD5/SHA256 | ✅ | ❌ | ✅ |
| Scans (70+ engines) | ✅ | ❌ | ✅ |
| positives/total | ✅ | ❌ | ✅ |
| submission_names | ✅ | ❌ | ✅ |
| ML Classification | ❌ | ✅ | ✅ |
| Product Classification | ❌ | ❌ | ✅ (computed) |
| TTL/Expiration | ❌ | ❌ | ✅ |
| First Seen | ❌ | ❌ | ✅ |
| Format Version | ❌ | ❌ | ✅ |

---

## Data Type Comparison

### Summary Table

| Data Type | GCS Real-time Lookup | Direct VT API | MongoDB Cache |
|-----------|---------------------|---------------|---------------|
| **File** | ✅ `vt-file-feeder` + `broccoli-enricher` | Fallback only | `file_rep` |
| **Domain** | ❌ No bucket | ✅ Primary source | `domain_classification` |
| **URL** | ❌ Time-based only | ✅ Primary source | (varies) |

### Why Different Approaches?

| Aspect | File | Domain/URL |
|--------|------|------------|
| **Query Volume** | Very high (millions/day) | Lower |
| **Index Key** | SHA1 (stable, unique) | Domain/URL (variable length) |
| **VT Coverage** | Every scanned file | On-demand only |
| **GCS Feasibility** | ✅ Fixed-length hash key | ⚠️ URL can be very long |

---

## Key Takeaways

### 1. Data Flow Summary

```
VirusTotal Feed API
       │
       │ Every minute (full data stream)
       ▼
VT Feeder Suite
       │
       ├──► vt-file-feeder/latest-reports/{sha1}     # For real-time lookup
       ├──► vt-file-feeder-by-date/{date}/{ts}       # Archive
       ├──► broccoli-enricher/latest-reports/{sha1}  # ML classification
       └──► vt-url-feeder-by-date/{date}/{ts}        # URL archive (no lookup)
       
       │
       │ On-demand query
       ▼
Sage Service
       │
       ├──► Check MongoDB cache
       ├──► Query GCS (if cache miss)
       ├──► Process & classify
       └──► Save to MongoDB
       
       │
       ▼
Client Response
```

### 2. Key Configurations

```properties
# VT Feeder Configuration
virus.total.vt.feeder.enabled=true
virus.total.vt.feeder.report.bucket.name=vt-file-feeder
virus.total.vt.feeder.classification.bucket.name=broccoli-enricher
virus.total.vt.feeder.folder.name=latest-reports
```

### 3. Critical Points

- **Full VT Data**: VT Feed API provides **complete data stream** (every file scanned by VT)
- **File vs URL**: File has hash-based GCS lookup; URL only has time-based archive
- **MongoDB = Cache**: Not the source of truth; GCS is the source
- **Broccoli = ML**: Adds intelligent classification on top of raw VT results
- **Two-phase Query**: Raw report (vt-file-feeder) + Classification (broccoli-enricher)

---

## References

- VT Feeder Suite: `/Users/tangxin/work/vt-feeder-suite/`
- Sage Service: `/Users/tangxin/work/sage-content-provider/services/sage-service/`
- VtFeederClient: `integration/src/main/java/.../vtfeeder/VtFeederClient.java`
- VirusTotalFileClassificationService: `sage-server/src/main/java/.../VirusTotalFileClassificationService.java`
- Configuration: `sage-server/src/main/resources/properties/cp-keys.properties`

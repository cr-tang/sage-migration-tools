# TOKENS Table Migration Plan

## Overview

The TOKENS table in Sage MongoDB contains Cybereason's curated threat intelligence IOCs. This data represents high-confidence indicators with known attribution (source campaigns/APT groups).

**Data Size**: ~890 KB, ~2,538 records (small enough for full import)

## TOKENS Data Structure

```json
{
  "_id": "04bd6d6f892af445a6791dfedc996f366ff72a91",  // Indicator value
  "_class": "com.cybereason.sage.model.dataset.tokens.TokenRecord",
  "expiration": 9999999999999,
  "response": "malware",
  "firstSeen": 1528368693691,
  "value": {
    "_class": "com.cybereason.sage.model.dataset.tokens.TokenInfo",
    "maliciousType": "malware",  // Classification
    "source": "Operation Dust Storm",  // Campaign/APT attribution
    "link": "https://...",  // Reference URL
    "expiration": 9999999999999,
    "type": "SHA1"  // DOMAIN, SHA1, MD5, SHA256, IPv4
  }
}
```

## Indicator Types in TOKENS

| Type | Description | Target Table |
|------|-------------|--------------|
| SHA1 | File hash (40 hex chars) | `ioc_file_hashes` |
| MD5 | File hash (32 hex chars) | `ioc_file_hashes` |
| SHA256 | File hash (64 hex chars) | `ioc_file_hashes` |
| DOMAIN | Domain name | `ioc_domains` |
| IPv4 | IP address | `ioc_ips` |

## Classification Mapping

Sage `maliciousType` → Phoenix `Classification`:

| Sage maliciousType | Phoenix Classification | Priority |
|-------------------|------------------------|----------|
| ransomware | RANSOMWARE | 1 (highest) |
| maltool | MALTOOL | 2 |
| hacktool | HACKTOOL | 3 |
| unwanted | UNWANTED | 4 |
| malware | MALWARE | 5 |
| suspicious | SUSPICIOUS | 6 |
| blacklist | BLACKLIST | 7 |

## Implementation Tasks

### Phase 1: Add CYBEREASON_TOKENS Source

1. **Update TiSource enum** (`src/.../enrichment/TiSource.kt`):
   - Add `CYBEREASON_TOKENS` source
   - Priority: CYBEREASON_TOKENS > VIRUS_TOTAL (Cybereason curated data is higher confidence)

### Phase 2: Create TOKENS Importer

1. **Create `tokens_importer.py`**:
   - Read TOKENS.bson from GCS or local file
   - Parse BSON records
   - Route by indicator type:
     - SHA1/MD5/SHA256 → `ioc_file_hashes` (hash only, no cross-references)
     - DOMAIN → `ioc_domains`
     - IPv4 → `ioc_ips`
   - Set source = 'CYBEREASON_TOKENS'
   - Store `value.source` (campaign name) in detection_names/description field

### Phase 3: TiDB Schema Updates (if needed)

Current schema should work with minor additions:

```sql
-- ioc_file_hashes already supports CYBEREASON_TOKENS via source ENUM
ALTER TABLE ioc_file_hashes 
  MODIFY COLUMN source ENUM('VIRUS_TOTAL', 'CYBEREASON_TOKENS', 'CUSTOMER') NOT NULL;

-- ioc_domains
ALTER TABLE ioc_domains 
  MODIFY COLUMN source ENUM('VIRUS_TOTAL', 'CYBEREASON_TOKENS', 'CUSTOMER') NOT NULL;

-- ioc_ips
ALTER TABLE ioc_ips 
  MODIFY COLUMN source ENUM('VIRUS_TOTAL', 'CYBEREASON_TOKENS', 'CUSTOMER') NOT NULL;
```

## Data Source Location

**TOKENS.bson**: `gs://sage_prod_dump/cr-mongo-shard-r01.cybereason.net/cybereason/TOKENS.bson` (~890 KB)

**Local Sample**: `/Users/tangxin/work/sage-content-provider/mongo_dump_samples/r01/cybereason/TOKENS.bson`

## Sample Record Analysis

From TOKENS_sample.json:

```json
// Domain indicator
{"_id":".vieweva.com", "response":"malware", "value":{"maliciousType":"malware", "source":"Asian APT", "type":"DOMAIN"}}

// SHA1 file hash
{"_id":"01005fc55c9f4940c21a676abf1b14b178ceeac9", "response":"ransomware", "value":{"maliciousType":"ransomware", "source":"Locky", "type":"SHA1"}}

// IPv4 indicator
{"_id":"0.1.2.3", "response":"malware", "value":{"maliciousType":"malware", "source":"Example", "type":"IPv4"}}
```

## Priority & Conflict Resolution

When same indicator exists in both TOKENS and VIRUS_TOTAL:
- **CYBEREASON_TOKENS wins** - curated data with known attribution
- Source priority order: CYBEREASON_TOKENS > VIRUS_TOTAL > CUSTOMER

## Success Metrics

- [ ] All ~2,538 TOKENS records imported
- [ ] Indicators correctly routed by type (hash/domain/IP)
- [ ] Campaign/source attribution preserved
- [ ] TI enrichment returns CYBEREASON_TOKENS source for matched indicators

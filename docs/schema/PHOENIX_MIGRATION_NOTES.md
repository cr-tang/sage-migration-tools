# Sage Features for Phoenix Migration

This document explains how Sage implements specific features that need to be migrated or replicated in Phoenix.

---

## 1. Classification Types and Sub-Types

### How Sage Determines Classification Type

Sage uses `VirusTotalClassifier.getMaliciousClassification()` to analyze AV engine scan results:

```java
// services/sage-service/sage-server/src/main/java/.../VirusTotalClassifier.java

// For each AV engine result:
for (String engineString : scans.keySet()) {
    if (!scans.get(engineString).isDetected()) {
        continue;  // Skip engines that didn't detect anything
    }
    
    String result = scans.get(engineString).getResult();  // e.g., "Trojan.Win32.GenericKD"
    
    // Classify the engine result string to get type + subtypes
    MaliciousClassification engineClassification = engines.classify(engine, result);
    
    // Calculate score for this engine
    double engineClassificationScore = engines.getTruePositiveTypeFactor(maliciousType) 
                                      * engines.getEngineQualityScore(engine);
    
    // Accumulate scores by type
    incrementValue(maliciousTypeScores, maliciousType, engineClassificationTypeScore);
    
    // Collect subtypes
    addValues(maliciousTypeToSubTypes, maliciousType, engineClassification.getSubTypes());
}

// Final type = type with highest accumulated score
// If scores equal, prefer higher priority type (ransomware > malware > suspicious)
```

### Available Classification Types (MaliciousType)

```
ransomware    - Ransomware (highest priority)
maltool       - Malicious tool
hacktool      - Hacking tool  
unwanted      - Unwanted software (PUP)
malware       - Generic malware
sinkholed     - Sinkhole domain (domain only)
suspicious    - Suspicious but not confirmed malware
whitelist     - Known safe
indifferent   - Neutral/benign
unresolved    - DNS cannot resolve (domain only)
unknown       - No data available
no_type_found - Classification process failed
blacklist     - Customer blacklist
av_detected   - AV reported detection
```

### Classification Sub-Types (MaliciousSubType)

Sub-types are extracted from AV detection name patterns. Examples:
- `trojan`, `ransom`, `backdoor`, `downloader`, `dropper`
- `worm`, `virus`, `rootkit`, `exploit`, `miner`
- `adware`, `spyware`, `riskware`, `greyware`
- `unrecognized` (when pattern not matched)

### Data Available in Response

```json
{
  "maliciousClassificationType": "malware",
  "maliciousClassification": {
    "type": "malware",
    "classificationScore": 0.85,
    "source": "VirusTotal",
    "firstScanTime": 1609459200000,
    "lastScanTime": 1609545600000,
    "subTypes": ["trojan", "downloader"]  // <-- Sub-types!
  },
  "aggregatedResult": {
    "detectionName": "Trojan.Win32.GenericKD",  // <-- First matched detection
    "positiveResults": ["Kaspersky", "McAfee", "Symantec"],
    "classificationScore": 0.85
  }
}
```

### Phoenix Options

**Option A: Enrich events with classification types and create multiple rules**
- Need fields: `maliciousClassificationType`, `maliciousClassification.subTypes[]`
- Create rules for each type: rule_ransomware, rule_trojan, etc.

**Option B: Single generic rule + auto-enrich Malop**
- Generic detection rule
- Post-process to enrich Malop with `maliciousClassificationType` for display

---

## 2. Customer Blocklist

### How Sage Private Handles Customer Blocklists

Each Sage Private instance has customer-specific classification collections:

| Collection | Purpose |
|------------|---------|
| `file_classification_sage_customer` | Customer file blacklist/whitelist |
| `domain_classification_sage_customer` | Customer domain blacklist/whitelist |
| `ip_classification_sage_customer` | Customer IP blacklist/whitelist |

### Customer Classification Model

```java
// services/sage-service/sage-server/src/main/java/.../CustomerClassificationModel.java

public class CustomerClassificationModel {
    private Collection<LookupKey> userLookupKeys;  // SHA1/MD5/domain/IP
    private boolean isBlocking;                     // Should block execution?
    private String owningUser;                      // Who created this entry
    private String comment;                         // User comment
    private MaliciousClassification.MaliciousType maliciousType;  // blacklist/whitelist
}
```

### Classification Response with Customer Data

```json
{
  "cpType": "CUSTOMER_CLASSIFICATION",
  "aggregatedResult": {
    "blocking": true,
    "comment": "Known malware from incident #12345",
    "user": "security.admin@customer.com"
  }
}
```

### Migration Options

1. **Migrate existing customer blocklists from Sage Private MongoDB**
   - Export from each customer's Sage Private instance
   - Import to Phoenix customer-specific storage

2. **New blocklist management in Phoenix**
   - Customer uploads new blocklists to Phoenix directly
   - Phoenix stores and queries independently of Sage

---

## 3. Double Extension Detection (FILE_EXTENSION_CLASSIFICATION)

### How Sage Stores Extension Classification

```json
// FILE_EXTENSION_CLASSIFICATION collection
{
  "_id": {"extension": "exe"},
  "value": {
    "type": "SYSTEM_WINDOWS",
    "description": "Windows Executable"
  }
}
{
  "_id": {"extension": "pdf"},
  "value": {
    "type": "DOCUMENT_GENERAL",
    "description": "Portable Document Format"
  }
}
```

### Extension Types

```
SYSTEM_WINDOWS      - Executable: exe, dll, scr, com, bat, cmd, ps1
SYSTEM_MAC          - Mac executable: app, dmg
SYSTEM_LINUX        - Linux executable: bin, sh
SYSTEM_SCRIPT       - Scripts: vbs, js, wsf
DOCUMENT_GENERAL    - Documents: pdf, doc, xls, ppt
DOCUMENT_AUDIO      - Audio: mp3, wav, aac
DOCUMENT_VIDEO      - Video: mp4, avi, mkv
ARCHIVE_COMPRESSED  - Archives: zip, rar, 7z, tar
```

### Double Extension Detection Logic

Sage doesn't do this detection itself - it provides the data. The detection logic runs on the endpoint:

```
Input: filename = "invoice.pdf.exe"

1. Extract extensions:
   - rightmost = "exe"
   - second = "pdf"

2. Validation:
   - Each extension >= 2 chars
   - Not a number
   - Valid characters

3. Query Sage for classifications:
   - GET /download_v1/file_extension
   - Returns full extension mapping

4. Detection:
   - Is rightmost extension EXECUTABLE type? (exe → SYSTEM_WINDOWS) ✓
   - Is second extension DOCUMENT type? (pdf → DOCUMENT_GENERAL) ✓
   - If both true → DOUBLE EXTENSION ALERT!
```

### How to Get Extension Data

**API Endpoint**: `POST /download_v1/file_extension`

```java
// SageDownloadServicesControllerV1.java
@POST
@Path("/file_extension")
public FileExtensionDownloadResponse downloadFileExtensions(FileExtensionDownloadRequest request) {
    return fileExtensionDownloadService.getDownloadResponse(request);
}
```

**Response**:
```json
{
  "recordsList": [
    {"key": {"extension": "exe"}, "value": {"type": "SYSTEM_WINDOWS", ...}},
    {"key": {"extension": "pdf"}, "value": {"type": "DOCUMENT_GENERAL", ...}},
    // ... ~500 extensions
  ]
}
```

### Phoenix Implementation

**Option A: Pre-load extension mapping in Flink**
```java
// In Flink job initialization
Map<String, String> extensionToType = loadExtensionMapping();

// In event processing
boolean isExecutable = isExecutableExtension(rightmostExt, extensionToType);
boolean isDocument = isDocumentExtension(secondExt, extensionToType);
if (isExecutable && isDocument) {
    // Alert: double extension detected
}
```

**Option B: Use static list**
- Executables: exe, dll, scr, com, bat, cmd, ps1, vbs, js, wsf, msi, jar
- Documents: pdf, doc, docx, xls, xlsx, ppt, pptx, txt, rtf

---

## 4. Confirmed Unresolved Domain (for DGA Detection)

### What is Confirmed Unresolved Domain?

A domain is "confirmed unresolved" when:
1. Local endpoint got NXDOMAIN
2. Sage verifies the domain really doesn't resolve globally
3. VirusTotal has no knowledge of the domain

### Sage's Domain Classification Logic

#### Step 1: DNS Resolution (DnsAccessController.java)

```java
// services/sage-service/sage-server/src/main/java/.../DnsAccessController.java

public DomainDnsReport getDomainDnsReport(String domain) {
    DomainDnsReport report = new DomainDnsReport();
    
    // 1. Check if internal domain (skip)
    if (DomainUtils.isInternalDomain(domain)) {
        report.setInternalDomain(true);
        return report;
    }
    
    // 2. Sage does its own DNS resolution
    InetAddress addressByHost = DomainUtils.domainToIp(domain);
    if (addressByHost != null) {
        report.setResolvedIpAddress(addressByHost.getHostAddress());
        
        // Reverse DNS lookup
        String hostByAddress = DomainUtils.ipToDomain(addressByHost);
        report.setReversedDomain(hostByAddress);
    }
    
    // 3. Resolve Second Level Domain (SLD)
    String sld = DomainUtils.getSecondLevelDomain(domain);
    InetAddress addressBySld = DomainUtils.domainToIp(sld);
    if (addressBySld != null) {
        report.setResolvedSecondLevelDomain(addressBySld.getHostAddress());
    }
    
    // 4. Get Name Servers
    Collection<String> nameServers = DomainUtils.domainToNameServer(domain);
    report.setNameServers(nameServers);
    
    return report;
}
```

#### Step 2: DNS Classification (DomainDnsClassifier.java)

```java
// services/sage-service/sage-server/src/main/java/.../DomainDnsClassifier.java

public static MaliciousClassification getMaliciousClassification(DomainDnsReport value, ...) {
    
    // No IP resolved for domain
    if (value.getResolvedIpAddress() == null || value.getResolvedIpAddress().isEmpty()) {
        
        // Check if SLD also unresolved
        if (value.getResolvedSecondLevelDomain() == null || value.getResolvedSecondLevelDomain().isEmpty()) {
            // Both domain and SLD unresolved
            return new MaliciousClassification(MaliciousType.unresolved, "DNS");
        } else {
            // Domain unresolved but SLD resolves (suspicious!)
            return new MaliciousClassification(MaliciousType.unresolved, 
                                              MaliciousSubType.sldresolved, "DNS");
        }
    }
    
    // Check for sinkhole
    SinkholeIdentifierInfo sinkhole = getSinkholingEntity(value, sinkholeIdentifiers);
    if (sinkhole != null) {
        return new MaliciousClassification(MaliciousType.sinkholed, sinkhole.getEntity());
    }
    
    // Domain resolves normally
    return new MaliciousClassification(MaliciousType.indifferent, "DNS");
}
```

#### Step 3: VirusTotal Domain Classification (VirusTotalClassifier.java)

```java
// services/sage-service/sage-server/src/main/java/.../VirusTotalClassifier.java

public static MaliciousClassification getMaliciousClassification(VirusTotalDomainReport report) {
    
    // VT response code 0 = domain never seen
    if (report.getResponseCode() != 1) {
        return new MaliciousClassification(MaliciousType.unknown, "VirusTotal");
    }
    
    // Domain known in VT - check if it has any data
    boolean hasResolutions = report.getResolutions() != null && report.getResolutions().length > 0;
    boolean hasWhois = report.getWhois() != null && report.getWhois().length() > 0;
    boolean hasSubdomains = report.getSubdomains() != null && report.getSubdomains().length > 0;
    boolean hasSiblings = report.getSiblings() != null && report.getSiblings().length > 0;
    boolean hasCategory = report.hasCategory();
    
    if (hasResolutions || hasWhois || hasSubdomains || hasSiblings || hasCategory) {
        // VT knows about this domain
        return new MaliciousClassification(MaliciousType.indifferent, "VirusTotal");
    } else {
        // VT knows domain but has NO data about it (suspicious!)
        return new MaliciousClassification(MaliciousType.unresolved, "VirusTotal");
    }
}
```

### Complete Confirmed Unresolved Check

```
Is Confirmed Unresolved?
├── Local Server:
│   ├── DNS query returned NXDOMAIN? ✓
│   ├── Domain name is valid? ✓
│   ├── Never seen resolved in organization? ✓
│   └── SLD never resolved in organization? ✓
│
└── Sage Server:
    ├── VT Check: unknown OR (known but no resolution/whois/siblings/subdomains/categories)? ✓
    └── DNS Check: Sage tried to resolve and confirmed it's unresolved? ✓

IF ALL TRUE → Confirmed Unresolved Domain
```

### Response Fields for DGA Detection

```json
{
  "domain_dns": {
    "maliciousClassificationType": "unresolved",
    "maliciousClassification": {
      "type": "unresolved",
      "subTypes": ["sldresolved"]  // SLD resolved but domain didn't
    },
    "aggregatedResult": {
      "resolvedIpAddress": null,
      "resolvedSecondLevelDomain": "192.168.1.1",  // SLD resolved
      "nameServers": null,
      "isInternalDomain": false
    }
  },
  "domain_classification": {
    "maliciousClassificationType": "unknown",  // VT never seen this domain
    "aggregatedResult": {
      "resolutions": [],
      "whois": null,
      "subdomains": [],
      "siblings": [],
      "categories": []
    }
  }
}
```

### Phoenix Implementation for DGA Detection

**Required Data Points**:

1. **Confirmed Unresolved Domain** (from Sage or self-compute):
   - Query Sage for domain classification
   - Check: `domain_dns.maliciousClassificationType == "unresolved"` 
   - AND `domain_classification.maliciousClassificationType == "unknown"`

2. **NXDomain Ratio** (compute in Flink):
   ```java
   // Per-process statistics
   Map<ProcessId, DnsStats> processStats;
   
   class DnsStats {
       long totalQueries;
       long nxdomainResponses;
       
       double getNxdomainRatio() {
           return (double) nxdomainResponses / totalQueries;
       }
   }
   
   // In event processing
   if (event.dnsResponseCode == NXDOMAIN) {
       stats.nxdomainResponses++;
   }
   stats.totalQueries++;
   
   if (stats.getNxdomainRatio() > DGA_THRESHOLD) {
       // Potential DGA activity
   }
   ```

3. **Confirmed Unresolved Ratio** (compute in Flink):
   ```java
   // Query Sage in batch for domains
   List<DomainClassificationResponse> results = sageClient.classifyDomains(domains);
   
   long confirmedUnresolved = results.stream()
       .filter(r -> r.getDnsMaliciousType() == UNRESOLVED)
       .filter(r -> r.getVtMaliciousType() == UNKNOWN)
       .count();
   
   double confirmedUnresolvedRatio = (double) confirmedUnresolved / results.size();
   ```

---

## 5. Sage API Request/Response Format

### Query Method: Hash, NOT Filename

**Important**: Sage queries are performed using file **hashes** (SHA1/MD5/SHA256), not filenames.

#### Evidence from BSON Data

Looking at a `file_rep` collection record:

```json
{
  "_id": "00008aae0779e116297d088ad1ae8a6a58a7354f",  // ← Primary key is SHA1 hash!
  
  "value": {
    "sha1": "00008aae0779e116297d088ad1ae8a6a58a7354f",
    "md5": "bf4ac709be5bf64f331f5d67773a0c82",
    "sha256": "96e5a2a12d386b8a7976fec76fd350e6a3eebdf5763f4bbf4ab18880e9f269e0",
    
    // Same hash submitted with 80+ different filenames!
    "submission_names": [
      "c:\\windows\\system32\\perftrack.dll",
      "perftrack.dll",
      "akamaitest-donotdelete.dll",
      "myfile.exe",
      "data",
      "bit54c4.tmp",
      // ... 80+ different names for the SAME file content
    ],
    
    "times_submitted": 148  // Submitted 148 times with different names
  }
}
```

**Why Hash Instead of Filename?**
1. **Uniqueness**: File content has a unique hash; filenames can be changed arbitrarily
2. **Privacy**: No need to transmit actual files or sensitive filenames
3. **Efficiency**: Fixed-length hash enables fast indexing and lookup
4. **Industry Standard**: VirusTotal and all threat intel services use hash-based queries

### File Classification Request Format

**Endpoint**: `POST /classification_v1/file_batch`

```json
{
  "sourceServerName": "detection-server-123",
  "sourceServerAddress": "192.168.1.100",
  "apiKey": "your-api-key",
  "requestData": [
    {
      "requestKey": {
        "sha1": "00d945ff6ab1583babd4b9bed63c05047988b70e",
        "md5": "a16c042e5255983a577551bbc82179f0",
        "sha256": "5e62f27ec88ee0d5c56c..."
      }
    },
    {
      "requestKey": {
        "sha1": "abc123def456...",
        "md5": ""  // Can provide only one hash
      }
    }
  ]
}
```

### Domain Classification Request Format

**Endpoint**: `POST /classification_v1/domain_batch`

```json
{
  "sourceServerName": "detection-server-123",
  "sourceServerAddress": "192.168.1.100",
  "apiKey": "your-api-key",
  "requestData": [
    {
      "requestKey": {
        "domain": "malware.example.com"
      }
    }
  ]
}
```

### IP Classification Request Format

**Endpoint**: `POST /classification_v1/ip_batch`

```json
{
  "sourceServerName": "detection-server-123",
  "sourceServerAddress": "192.168.1.100",
  "apiKey": "your-api-key",
  "requestData": [
    {
      "requestKey": {
        "ip": "192.168.1.1"
      }
    }
  ]
}
```

### Query Key Summary

| Request Type | Query Key | Notes |
|--------------|-----------|-------|
| **File** | `sha1`, `md5`, `sha256` | Use hash, **NOT filename** |
| **Domain** | `domain` | Full domain name |
| **IP** | `ip` | IP address |

### FileHashKey Schema

```yaml
FileHashKey:
  type: object
  properties:
    sha1:    # SHA1 hash (40 chars)
      type: string
    md5:     # MD5 hash (32 chars)  
      type: string
    sha256:  # SHA256 hash (64 chars)
      type: string
    hash:    # Generic hash field (compatibility)
      type: string
    empty:   # Is empty flag
      type: boolean
```

**Priority**: Sage uses `SHA1 → MD5 → SHA256` order; usually only one hash is needed.

---

## 6. File Classification Response (file_rep) Complete Schema

### Complete Record Structure (Malicious File Example)

```json
{
  // ==================== Sage Wrapper Fields ====================
  "_id": "00d945ff6ab1583babd4b9bed63c05047988b70e",
  "_class": "com.cybereason.sage.services.external.virustotal.VirusTotalFileClassification",
  "formatVersion": 1,
  
  // V2 Classifier Result (new field, optional)
  "vtClassifierV2Classification": {
    "taskUUID": "...",
    "buildVersion": "2.0.5:vtc-1.1.40:plume-1.0.1",
    "algoVersion": "2.0",
    "classification": "indifferent"
  },
  
  "expiration": 1507868361858,        // TTL timestamp (ms)
  "response": "malware.virus.trojan(14.57,14.35);NONE.null",  // Sage classification summary
  "firstSeen": 1481486499872,         // First query timestamp
  "lastUpdate": 1500092361859,        // Last update timestamp
  
  // ==================== VirusTotal Raw Report ====================
  "value": {
    "_class": "com.cybereason.sage.integration.virustotal.VirusTotalFileReport",
    
    // ---------- Scan Summary ----------
    "total": 64,                      // Total engines scanned
    "positives": 63,                  // Engines detected as malicious
    
    // ---------- Per-Engine Results ----------
    "scans": {
      "Kaspersky": {
        "detected": true,             // Detected as malicious?
        "version": "15.0.1.13",
        "result": "Net-Worm.Win32.Allaple.b",  // Detection name
        "update": "20170714"
      },
      "Microsoft": {
        "detected": true,
        "version": "1.1.13903.0",
        "result": "Worm:Win32/Allaple.A",
        "update": "20170715"
      },
      "Webroot": {
        "detected": false,            // Not detected
        "version": "1.0.0.207",
        "update": "20170715"
        // Note: no "result" field when detected=false
      }
      // ... 60+ engines
    },
    
    // ---------- File Hashes ----------
    "sha1": "00d945ff6ab1583babd4b9bed63c05047988b70e",
    "sha256": "5e62f27ec88ee0d5c56c5140d7287ff32af8d05e51f53325a87b2b170627b349",
    "md5": "a16c042e5255983a577551bbc82179f0",
    "resource": "00d945ff6ab1583babd4b9bed63c05047988b70e",
    
    // ---------- Scan Metadata ----------
    "scan_id": "5e62f27ec88ee0d5c56c...-1500091759",
    "scan_date": "2017-07-15 04:09:19",
    "response_code": 1,               // 1=scanned, 0=unknown
    "verbose_msg": "Scan finished, information embedded",
    "permalink": "https://www.virustotal.com/file/.../analysis/.../",
    
    // ---------- File Properties ----------
    "type": "Win32 EXE",
    "size": 63488,
    "times_submitted": 3,
    "first_seen": "2015-12-13 00:54:22",
    "last_seen": "2017-07-15 04:09:19",
    "submission_names": [
      "a16c042e5255983a577551bbc82179f0.virobj",
      "virussign.com_a16c042e5255983a577551bbc82179f0.vir"
    ],
    
    // ---------- Network Sources ----------
    "ITW_urls": [],                   // In-The-Wild URLs where file was found
    
    // ---------- Additional Info ----------
    "additional_info": {
      "exiftool": {
        "MIMEType": "application/octet-stream",
        "FileType": "Win32 EXE",
        "PEType": "PE32",
        "MachineType": "Intel 386 or later",
        "EntryPoint": "0x1b41",
        "CodeSize": "13824"
      },
      "magic": "PE32 executable for MS Windows (GUI) Intel 80386 32-bit",
      "sigcheck": {},
      "trid": "Win32 Executable (generic) (52.9%)..."
    }
  }
}
```

### Sage `response` Field Format

```
malware.virus.trojan(14.57,14.35);NONE.null
   │       │     │      │     │     │    │
   │       │     │      │     │     │    └── productName
   │       │     │      │     │     └── productType (BROWSER, MAIL, etc.)
   │       │     │      │     └── score2 (secondary score)
   │       │     │      └── score1 (primary score, based on positives/total)
   │       │     └── subType (trojan, ransomware, worm, etc.)
   │       └── type (virus, tool, etc.)
   └── maliciousClassification
```

### Common Classification Values

| response | Meaning |
|----------|---------|
| `malware.virus.trojan(14.5,14.3);NONE.null` | Trojan malware |
| `malware.virus.ransomware(12.0,11.5);NONE.null` | Ransomware |
| `unknown(-1.0,-1.0);NONE.null` | VT has no record |
| `indifferent(-1.0,-1.0);NONE.null` | Benign/clean file |
| `indifferent(0.0,0.0);BROWSER.Chrome` | Clean file, identified as Chrome |

---

## 7. Data Flow Architecture

```
┌─────────────────┐     POST /classification_v1/file_batch     ┌─────────────────┐
│  Detection      │  ────────────────────────────────────────▶ │                 │
│  Server         │     { "requestData": [                     │   Sage Global   │
│  (Sensor)       │         { "requestKey": {                  │                 │
│                 │             "sha1": "abc123..."            │                 │
└─────────────────┘           }}]}                             └────────┬────────┘
                                                                        │
                                                                        ▼
                                                               ┌─────────────────┐
                                                               │ Query Flow:     │
                                                               │ 1. Token cache  │
                                                               │ 2. MongoDB cache│
                                                               │ 3. VT Feeder/API│
                                                               │ 4. Customer Block│
                                                               │ 5. Priority Merge│
                                                               └─────────────────┘
                                                                        │
                                                                        ▼
┌─────────────────┐     SageClassificationBatchResponse        ┌─────────────────┐
│  Detection      │  ◀──────────────────────────────────────── │   Sage Global   │
│  Server         │     { "responseData": [                    │                 │
│                 │         { "maliciousClassificationType":   │                 │
│                 │           "malware", ...}]}                │                 │
└─────────────────┘                                            └─────────────────┘
```

---

## Data Export Summary

| Feature | Sage Collection | Export API | Can Phoenix Compute? |
|---------|-----------------|------------|---------------------|
| Classification Types | `file_rep` | Classification API | Need VT or similar |
| Classification Sub-Types | `file_rep` | Classification API | Need VT or similar |
| Customer Blocklist | `*_sage_customer` | Export from Sage Private | Yes, new storage |
| Extension Classification | `FILE_EXTENSION_CLASSIFICATION` | `/download_v1/file_extension` | Yes, use static list |
| Confirmed Unresolved | `domain_dns`, `domain_classification` | Classification API | Partial, need DNS + VT |
| Sinkhole Identifiers | `SINKHOLE_IDENTIFIERS` | `/download_v1/sinkhole_identifiers` | Yes, use static list |

---

## 8. VT Feeder Data Source (GCS)

Sage has a new data path using GCS buckets instead of direct VT API calls:

### GCS Bucket Structure

```
gs://vt-file-feeder/latest-reports/
└── {hash}              # Pre-processed VT reports (JSON)

gs://broccoli-enricher/latest-reports/
└── {hash}              # Pre-computed classification results
```

### Phoenix Direct Access Option

Phoenix can potentially bypass Sage and read directly from these GCS buckets:

```java
// VtFeederClient pattern
Storage storage = StorageOptions.getDefaultInstance().getService();
Blob blob = storage.get("vt-file-feeder", "latest-reports/" + hash);
VirusTotalFileReport report = parseJson(blob, VirusTotalFileReport.class);
```

**Benefits**:
- Lower latency (no Sage middleman)
- Access to raw VT data
- Can process in batch

**Considerations**:
- Need GCS credentials
- Must handle classification logic (currently done by Sage)
- TTL/caching management

---

## 8. Complete Data Sources Reference

This section provides a comprehensive overview of all data sources used by Sage, including code evidence and calling methods.

### 8.1 Data Sources Summary Table

| # | CPType | Data Source | Type | Query Key | MongoDB Collection | Status |
|---|--------|-------------|------|-----------|-------------------|--------|
| 1 | `VIRUS_TOTAL` | VirusTotal (via VT Feeder) | GCS Bucket | SHA1/MD5/SHA256 | `file_rep`, `domain_classification` | **Primary** |
| 2 | `REVERSING_LABS` | Reversing Labs | External API | SHA1 | `reversing_labs_file` | Active |
| 3 | `OPSWAT` | OPSWAT MetaDefender | External API | SHA1/MD5 | `opswat_file` | Active |
| 4 | `TOKEN` | Internal Token Library | MongoDB | SHA1/Domain/IP | `TOKENS` | Active |
| 5 | `DNS_RESOLVER` | DNS Resolution Service | Internal | Domain | `domain_dns` | Active |
| 6 | `STIX_TAXII` | TAXII/STIX Threat Intel | External Feed | SHA1/Domain | `threat_feed` | Active |
| 7 | `SAGE_GLOBAL` | Sage Global Instance | Internal API | SHA1/Domain/IP | (pass-through) | For Private |
| 8 | `SAGE_API` | Sage API | Internal API | SHA1/Domain/IP | (pass-through) | For Private |
| 9 | `CUSTOMER_CLASSIFICATION` | Customer Blocklist | MongoDB | SHA1/Domain/IP | `customer_classification` | For Private |
| 10 | `AV_REPORTED` | Antivirus Reports | Sensor Upload | SHA1 | `av_classification` | Active |
| 11 | `ISIGHT` | iSight Partners | External API | SHA1/Domain/IP | - | **Deprecated** |

### 8.2 VirusTotal - VT Feeder (Primary Data Source)

#### Evidence: VT Feeder is Enabled by Default

**Configuration file**: `sage-server/src/main/resources/properties/cp-keys.properties`

```properties
# Line 50-54
virus.total.vt.feeder.enabled=true
virus.total.vt.feeder.report.bucket.name=vt-file-feeder
virus.total.vt.feeder.classification.bucket.name=broccoli-enricher
virus.total.vt.feeder.folder.name=latest-reports
virus.total.vt.feeder.credential.path=
```

#### Evidence: VT Feeder Priority Over API

**Source file**: `integration/src/main/java/.../virustotal/VirusTotalWebService.java` (Lines 191-201)

```java
@Override
public VirusTotalFileReport scanFileHash(String hash)
        throws InvalidArgumentsException, UnSupportedFeatureException {
    if (hash == null || hash.length() < 1) {
        throw new InvalidArgumentsException(configSettings.getWebServiceName() + ": Must send at least 1 file");
    }

    // VT Feeder takes priority - if enabled, use GCS bucket
    if (vtFeederWebService.isEnable()) {
        VirusTotalFileReport virusTotalFileReport = vtFeederWebService.scanFileHash(hash);
        LOD.log("vt-feeder response : {}", virusTotalFileReport);
        return virusTotalFileReport;
    }

    // Fallback: Direct VirusTotal API call (legacy)
    LOD.log("scanning file hash {} using {}", hash, this.getClass().getSimpleName());
    WebServiceRequestMessage request = new WebServiceRequestMessage(configSettings.getWebServiceHost(), true,
            URI_VT2_FILE_SCAN_REPORT);
    request.setRequestMethod(RequestMethod.POST);
    request.addString("resource", hash);   // Query by HASH
    request.addString("apikey", configSettings.getAPIKey());
    request.addString("allinfo", "1");
    // ...
}
```

#### Evidence: VT Feeder Client Implementation

**Source file**: `integration/src/main/java/.../virustotal/vtfeeder/VtFeederClient.java`

```java
@Singleton
@Slf4j
public class VtFeederClient {
    private final Storage storage;  // Google Cloud Storage client
    private final String reportBucketName;      // "vt-file-feeder"
    private final String classificationBucketName; // "broccoli-enricher"
    private final String folderName;            // "latest-reports"

    public VirusTotalFileReport getReport(String key) {
        String path = String.format("%s/%s", folderName, key);  // "latest-reports/{hash}"
        Blob blob = storage.get(reportBucketName, path);        // Read from GCS
        
        if (blob == null) {
            // Return empty report if not found
            VirusTotalFileReport virusTotalFileReport = new VirusTotalFileReport();
            virusTotalFileReport.setResource(key);
            virusTotalFileReport.setVerboseMessage("No report found in vt-feeder");
            virusTotalFileReport.setResponseCode(0);
            return virusTotalFileReport;
        }
        
        return toReport(blob, VirusTotalFileReport.class);  // Parse JSON from GCS
    }
    
    // Batch query support
    public VirusTotalFileReport[] getReports(List<String> hashes) {
        List<BlobId> blobs = hashes.stream()
            .map(k -> BlobId.of(reportBucketName, String.format("%s/%s", folderName, k)))
            .collect(Collectors.toList());
        List<Blob> blobList = storage.get(blobs);  // Batch read from GCS
        // ...
    }
}
```

#### VT Feeder Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VT Feeder Architecture                             │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────┐
                    │   VirusTotal     │
                    │   (External)     │
                    └────────┬─────────┘
                             │
                             │ Periodic Data Push
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                    Google Cloud Storage                       │
│  ┌─────────────────────────┐  ┌─────────────────────────────┐ │
│  │   vt-file-feeder        │  │   broccoli-enricher         │ │
│  │   /latest-reports/      │  │   /latest-reports/          │ │
│  │   └── {sha1}  (raw VT)  │  │   └── {sha1} (classification)│ │
│  └─────────────────────────┘  └─────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                             │
                             │ Read by Hash
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                      VtFeederClient                           │
│  storage.get("vt-file-feeder", "latest-reports/" + hash)     │
└──────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                  VirusTotalFileReport                         │
│  - sha1, md5, sha256                                          │
│  - scans: {engine: {detected, result}}                       │
│  - positives, total                                           │
│  - submission_names (metadata, not query input)               │
└──────────────────────────────────────────────────────────────┘
```

### 8.3 Reversing Labs

#### Configuration

```properties
# cp-keys.properties lines 58-63
reversing.labs.api.public.key=NOT-A-VALID-KEY-NEVER-USE-PRODUCTION-KEY-IN-DEV
reversing.labs.host=ticloud-aws1-api.reversinglabs.com
reversing.labs.access=true
reversing.labs.api.private.key=NOT-A-VALID-KEY-NEVER-USE-PRODUCTION-KEY-IN-DEV
reversing.labs.connect.timeout.ms=2000
reversing.labs.read.timeout.ms=5000
```

#### API Call Implementation

**Source file**: `integration/src/main/java/.../reversinglabs/ReversingLabsMalwarePresenceWebService.java`

```java
@Override
public ReversingLabsMalwarePresenceReport scanFileHash(String hash) 
        throws InvalidArgumentsException, UnSupportedFeatureException {
    
    // API endpoint: GET /api/databrowser/malware_presence/query/sha1/{hash}
    WebServiceRequestMessage request = new WebServiceRequestMessage(
        configSettings.getWebServiceHost(),  // ticloud-aws1-api.reversinglabs.com
        true,
        URI_MALWARE_PRESENCE_QUERY + "sha1/" + hash + "?extended=true&format=json"
    );
    request.setRequestMethod(RequestMethod.GET);
    request.addBasicAuthentication(configSettings.getAPIKey(), configSettings.getAPISecretKey());
    submit(request);
    
    return gsonProcessor.fromJson(response, ReversingLabsMalwarePresenceWebAPIResponseReport.class)
                        .getMalwarePresenceList().getMalwarePresenceReport();
}
```

#### Query Method

| Parameter | Value |
|-----------|-------|
| Host | `ticloud-aws1-api.reversinglabs.com` |
| Method | `GET` |
| Endpoint | `/api/databrowser/malware_presence/query/sha1/{hash}?extended=true&format=json` |
| Auth | Basic Authentication (public_key:private_key) |
| Query Key | **SHA1 hash only** |

### 8.4 OPSWAT MetaDefender

#### Configuration

```properties
# cp-keys.properties lines 65-69
opswat.api.key=NOT-A-VALID-KEY-NEVER-USE-PRODUCTION-KEY-IN-DEV
opswat.host=api.metadefender.com
opswat.access=true
opswat.connect.timeout.ms=2000
opswat.read.timeout.ms=5000
```

#### API Call Implementation

**Source file**: `integration/src/main/java/.../opswat/OpswatWebService.java`

```java
@Override
public OpswatFileReport scanFileHash(String hash) 
        throws InvalidArgumentsException, UnSupportedFeatureException {
    
    // API endpoint: GET /v2/hash/{hash}
    WebServiceRequestMessage request = new WebServiceRequestMessage(
        configSettings.getWebServiceHost(),  // api.metadefender.com
        true,
        URI_HASH_QUERY + hash                // /v2/hash/{hash}
    );
    request.setRequestMethod(RequestMethod.GET);
    request.addHeader("apikey", configSettings.getAPIKey());
    submit(request);
    
    return gsonProcessor.fromJson(response, OpswatFileReport.class);
}
```

#### Query Method

| Parameter | Value |
|-----------|-------|
| Host | `api.metadefender.com` |
| Method | `GET` |
| Endpoint | `/v2/hash/{hash}` |
| Auth | Header `apikey: {api_key}` |
| Query Key | **SHA1 or MD5 hash** |

### 8.5 Token Library (Internal)

#### Description

Token is Cybereason's internal curated list of known malicious/benign file hashes, domains, and IPs. Data is stored in MongoDB and updated via the Upload Service.

#### Configuration

```properties
token.store.name=TOKENS
token.service.ttl=604800000  # 7 days
tokens.md5.enabled=true
token.in.mem.cache.enabled=true
```

#### Data Source

- **Source**: Internal Cybereason research team uploads via `UploadService`
- **Storage**: MongoDB collection `TOKENS`
- **Query Key**: SHA1 (MD5 optional), Domain, IP

#### Code Evidence

**Source file**: `sage-server/src/main/java/.../tokens/TokenFileClassificationService.java`

```java
@Singleton
public class TokenFileClassificationService extends AbstractFileClassificationService<TokenInfo, TokenDataElement> 
        implements DownloadServiceListener {
    
    @Inject
    public TokenFileClassificationService(
            PersistenceManager persistenceManager,
            UploadService uploadService,
            @Named(SageCommonPropertiesKeys.TOKEN_STORE_NAME) String storeName,  // "TOKENS"
            // ...
    ) {
        super(CPType.TOKEN.getId(), CPType.TOKEN, persistenceManager, storeName, ...);
        this.uploadService = uploadService;
    }
    
    @PostConstruct
    public void listen() {
        this.uploadService.register(this, true);  // Listen for token updates
    }
}
```

### 8.6 DNS Resolver

#### Description

Internal service that resolves domains and detects sinkhole indicators.

#### Configuration

```properties
domain.dns.store.storeName=domain_dns
domain.dns.service.ttl=2592000000  # 30 days
```

#### Code Evidence

**Source file**: `sage-server/src/main/java/.../virustotal/dns/ResolveDomainService.java`

```java
public ResolveDomainService(
    // ...
    @Named(STORE_NAME) String storeName,  // "domain_dns"
) {
    super(CPType.DNS_RESOLVER.getId(), CPType.DNS_RESOLVER, persistenceManager, storeName, ...);
}

// Resolves domain and checks for sinkhole indicators
protected DomainDnsReport queryExternalService(LookupKey lookupKey, SourceClientDetails sourceClientDetails) {
    DomainDnsReport report = new DomainDnsReport();
    
    // 1. DNS A record lookup
    String resolvedIp = DomainUtils.domainToIPAddress(domain);
    report.setResolvedIpAddress(resolvedIp);
    
    // 2. NS record lookup
    Collection<String> nameServers = DomainUtils.domainToNameServer(domain);
    report.setNameServers(nameServers);
    
    // 3. Check sinkhole identifiers
    // ...
    
    return report;
}
```

### 8.7 Data Source Priority

Sage uses a priority-based decision system when multiple data sources return results:

```java
// FileClassificationProviderImpl.java
public SageFileClassificationResponse get(SageFileClassificationRequest request, ...) {
    // 1. First: Token classification (internal whitelist/blacklist)
    SageFileClassificationResponse tokenResponse = tokenFileClassificationService.get(request, ...);
    
    // 2. Second: VirusTotal (via VT Feeder)
    SageFileClassificationResponse vtResponse = virusTotalFileClassificationService.get(request, ...);
    
    // 3. Third: Reversing Labs
    SageFileClassificationResponse rlResponse = reversingLabsFileClassificationService.get(request, ...);
    
    // 4. Merge results using priority
    SageFileClassificationResponse response = simpleMerge(tokenResponse, vtResponse, rlResponse);
    
    return response;
}
```

### 8.8 Summary: All Queries Use Hash, Not Filename

| Data Source | Query Input | Example |
|-------------|-------------|---------|
| VT Feeder | `storage.get(bucket, "latest-reports/" + hash)` | `latest-reports/a1b2c3d4...` |
| VirusTotal API (legacy) | `request.addString("resource", hash)` | `resource=a1b2c3d4...` |
| Reversing Labs | `/api/databrowser/.../sha1/{hash}` | `/sha1/a1b2c3d4...` |
| OPSWAT | `/v2/hash/{hash}` | `/v2/hash/a1b2c3d4...` |
| Token | `persistenceManager.findById(hash)` | MongoDB query by _id |

**Conclusion**: All data sources use **file hash** (SHA1/MD5/SHA256) as the query key. `submission_names` and other filename metadata are **returned results**, not query inputs.

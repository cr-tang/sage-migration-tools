# MongoDB Collections Schema Summary

Based on production environment dump data analysis (2020-11-05)  
**Sample Size**: 10MB per collection (for large files)

---

## 1. TOKENS (Token Classification Data)
**Collection**: `TOKENS`  
**Purpose**: Store malware, domain, IP token marking data (blacklist/whitelist, etc.)  
**Shard Location**: r01

```json
{
  "_id": "domain/SHA1/IP address",
  "_class": "com.cybereason.sage.model.dataset.tokens.TokenRecord",
  "expiration": NumberLong,
  "response": "malware|ransomware|whitelist",
  "firstSeen": NumberLong,
  "value": {
    "_class": "com.cybereason.sage.model.dataset.tokens.TokenInfo",
    "maliciousType": "malware|ransomware|whitelist",
    "source": "threat intelligence source name",
    "link": "reference URL",
    "expiration": NumberLong,
    "type": "DOMAIN|SHA1|IPv4|MD5"
  }
}
```

---

## 2. file_rep (VirusTotal File Reputation)
**Collection**: `file_rep`  
**Purpose**: Store VirusTotal file scan results  
**Shard Location**: r01-r06 (~900GB each)  
**10MB Sample Record Count**: ~9,005 records

```json
{
  "_id": "SHA1 hash (40 chars) or MD5 hash (32 chars)",
  "_class": "com.cybereason.sage.services.external.virustotal.VirusTotalFileClassification",
  "formatVersion": 1,                    // optional, data format version
  "expiration": NumberLong,              // expiration timestamp
  "response": "unknown(-1.0,-1.0);NONE.null | indifferent(-1.0,-1.0);NONE.null",
  "firstSeen": NumberLong,               // first seen timestamp
  "lastUpdate": NumberLong,              // last update timestamp
  
  // VT Classifier V2 classification result (optional, exists only when VT scan results are present)
  "vtClassifierV2Classification": {
    "taskUUID": Binary,                  // task UUID (Base64)
    "buildVersion": "prod-master-72:vtc-1.1.40:plume-1.0.1",
    "algoVersion": "2.0",
    "classification": "indifferent|malware|whitelist"
  },
  
  "value": {
    "_class": "com.cybereason.sage.integration.virustotal.VirusTotalFileReport",
    "resource": "SHA1 hash",
    "response_code": 0|1,                // 0=not found, 1=has results
    "verbose_msg": "scan status message",
    
    // Following fields exist only when response_code=1
    "scan_id": "sha256-timestamp",
    "sha1": "SHA1 hash",
    "sha256": "SHA256 hash",
    "md5": "MD5 hash",
    "scan_date": "2020-10-19 19:28:09",
    "permalink": "https://www.virustotal.com/...",
    "positives": Number,                 // number of engines detecting malware
    "total": Number,                     // total scan engines
    "type": "Win32 DLL|PE32 executable|...",
    "size": NumberLong,                  // file size (bytes)
    "times_submitted": Number,           // submission count
    "first_seen": "2010-03-17 04:59:49",
    "last_seen": "2020-10-19 19:28:09",
    
    // Individual engine scan results
    "scans": {
      "EngineName": {
        "detected": true|false,
        "version": "version number",
        "update": "20201019",
        "result": "malware name"          // only when detected=true
      }
      // ... 60-70 engines
    },
    
    "submission_names": ["filename1", "filename2", ...],
    "ITW_urls": ["URLs where this file was found"],
    "tags": ["64bits", "assembly", "pedll", "trusted"],
    
    // Additional info
    "additional_info": {
      "exiftool": {
        "FileType": "Win64 DLL",
        "MachineType": "AMD AMD64",
        "OriginalFileName": "xxx.dll"
      },
      "first_seen_itw": "first seen in the wild timestamp",
      "magic": "PE32+ executable...",
      "sigcheck": {
        "internal name": "internal name",
        "link date": "link date"
      },
      "trid": "file type identification result",
      "trusted_verdict": {
        "filename": "filename",
        "organization": "Microsoft Corporation",
        "verdict": "goodware|malware"
      },
      "pe-machine-type": "34404",
      "suspicious-insight": true|false
    },
    
    "unique_sources": Number,            // unique source count
    "harmless_votes": Number,            // harmless vote count
    "malicious_votes": Number,           // malicious vote count
    "community_reputation": Number       // community reputation score
  }
}
```

### Response Field Format Description
- `unknown(-1.0,-1.0);NONE.null` - VT did not find this file
- `indifferent(-1.0,-1.0);NONE.null` - VT scan result is benign/neutral
- `malware(0.5,0.8);TROJAN.Win32` - VT detected malware

---

## 3. domain_classification (VirusTotal Domain Classification)
**Collection**: `domain_classification`  
**Purpose**: Store VirusTotal domain reputation and WHOIS information  
**Shard Location**: r01-r06 (~80GB each)  
**10MB Sample Record Count**: ~17,848 records

```json
{
  "_id": "domain (e.g., example.com or sub.example.com)",
  "_class": "com.cybereason.sage.services.external.virustotal.VirusTotalDomainClassification",
  "expiration": NumberLong,              // expiration timestamp
  "response": "maliciousClassification=indifferent|malware|whitelist|unknown",
  "firstSeen": NumberLong,               // first seen timestamp
  "lastUpdate": NumberLong,              // last update timestamp
  
  "value": {
    "_class": "com.cybereason.sage.integration.virustotal.VirusTotalDomainReport",
    "responseCode": 0|1,                 // 0=not found, 1=has data
    "verboseMessage": "Domain found in dataset|Domain not found",
    "uniqueIdentifier": "domain",
    
    // Following fields may exist when responseCode=1
    "resolutions": [                     // DNS resolution history
      { 
        "lastResolved": "2019-09-28 12:40:09", 
        "ipAddress": "120.138.30.10" 
      }
    ],
    
    "detectedUrls": [                    // Malicious URLs detected under this domain
      { 
        "url": "http://example.com/malware.exe",
        "positives": 4,                  // engines that detected
        "total": 71,                     // total engines
        "scanDate": "2019-10-09 15:22:27"
      }
    ],
    
    "whois": "Full WHOIS info text...",  // Domain registration info
    "whoisTimestamp": NumberDouble,      // WHOIS query timestamp
    
    "categories": ["uncategorized", "business", "malware"],
    "subdomains": ["www.example.com", "mail.example.com"],
    "siblings": ["example.net", "example.org"]  // Sibling domains
  }
}
```

### Response Field Value Description
- `maliciousClassification=indifferent` - Neutral/Unknown threat
- `maliciousClassification=malware` - Known malicious domain
- `maliciousClassification=whitelist` - Whitelisted domain
- `maliciousClassification=unknown` - VT did not find this domain

---

## 4. domain_dns (Domain DNS Records)
**Collection**: `domain_dns`  
**Purpose**: Store domain DNS resolution results  
**Shard Location**: r01-r06 (~700GB each)  
**10MB Sample Record Count**: ~21,417 records

```json
{
  "_id": "domain (e.g., example.com or sub.example.com)",
  "_class": "com.cybereason.sage.services.external.virustotal.dns.DomainDnsClassification",
  "expiration": NumberLong,              // expiration timestamp
  "response": "maliciousClassification=indifferent|unresolved|unresolved.sldresolved",
  "firstSeen": NumberLong,               // first seen timestamp
  "lastUpdate": NumberLong,              // last update timestamp
  
  "value": {
    "_class": "com.cybereason.sage.services.external.virustotal.dns.DomainDnsReport",
    "isInternalDomain": false,           // whether internal domain
    "resolvedIpAddress": "104.16.12.194",  // resolved IP address (optional)
    "resolvedSecondLevelDomain": "64.38.131.58",  // second-level domain resolution (optional)
    "nameServers": [                     // Name Server list (optional)
      "ns1.example.com",
      "ns2.example.com"
    ],
    "reversedDomain": "ptr.reverse.dns.com",  // Reverse DNS record (optional)
    "sinkholeIdentifierInfo": {          // Sinkhole identification info (optional)
      // Exists when domain is identified as sinkhole
    }
  }
}
```

### Response Field Value Description
- `maliciousClassification=indifferent` - DNS resolves normally
- `maliciousClassification=unresolved` - DNS cannot resolve
- `maliciousClassification=unresolved.sldresolved` - Second-level domain resolves but current domain doesn't

---

## 5. sage_configurations (Sage System Configuration)
**Collection**: `sage_configurations`  
**Purpose**: Store Classification Provider configuration and decision priorities  
**Shard Location**: r02

### CPCommonConfigurationDataElement (CP Common Configuration)
```json
{
  "_id": "config ID",
  "_class": "CPCommonConfigurationDataElement",
  "order": Number,
  "cpType": "TOKEN|VIRUS_TOTAL|REVERSING_LABS|OPSWAT|DNS_RESOLVER|ISIGHT",
  "isBlocking": false,
  "isMandatory": false|true,
  "determinedClassifications": ["malware", "whitelist"],
  "isEnable": true|false,
  "scope": "INTERNAL|EXTERNAL",
  "serverId": Number,
  "mongoVersion": 1
}
```

### DecisionPriorityDataElement (Decision Priority)
```json
{
  "_id": "files_decision_priority_key|domains_decision_priority_key|ips_decision_priority_key",
  "_class": "FilesDecisionPriorityDataElement|DomainsDecisionPriorityDataElement|IpsDecisionPriorityDataElement",
  "cpPrioritiesList": [
    {
      "_id": Number,
      "cpType": "TOKEN|VIRUS_TOTAL|...",
      "maliciousType": "ransomware|malware|whitelist|...",
      "priority": Number
    }
  ],
  "mongoVersion": 1
}
```

---

## 6. cp_server_configuration (CP Server Configuration)
**Collection**: `cp_server_configuration`  
**Purpose**: Store Classification Provider server connection information  
**Shard Location**: r03

```json
{
  "_id": Number,  // serverId
  "_class": "CPServerConfigurationDataElement",
  "cpType": "TOKEN|VIRUS_TOTAL|REVERSING_LABS|OPSWAT|DNS_RESOLVER|ISIGHT",
  "siteName": "service name",
  "url": "service URL",
  "proxyUrl": "proxy URL",
  "proxyUsername": "proxy username",
  "proxyPassword": "proxy password (encrypted)",
  "lastUpdate": NumberLong
}
```

---

## 7. state_properties (State Properties)
**Collection**: `state_properties`  
**Purpose**: Store system runtime state, such as VT Feed processing progress, SQS queue names, etc.  
**Shard Location**: r03

```json
{
  "_id": "property key name",
  "_class": "com.cyber.persistence.properties.PersistedStatePropertyModel",
  "value": "property value"
}
```

**Common Properties**:
- `latest_successful_vt_feed_package`: Last successfully processed VT Feed package
- `latest_failed_vt_feed_package`: Last failed VT Feed package
- `response_queue_name_*`: SQS response queue names for each Sage instance

---

## 8. PORT_CLASSIFICATION (Port Classification)
**Collection**: `PORT_CLASSIFICATION`  
**Purpose**: Store port number classification information (service/malware)  
**Shard Location**: r02

```json
{
  "_id": {
    "port": Number,
    "protocol": "TCP|UDP"
  },
  "_class": "com.cybereason.sage.model.dataset.port.PortClassificationRecord",
  "value": [
    {
      "_class": "com.cybereason.sage.model.dataset.port.PortInfo",
      "sources": ["IANA", "Wikipedia", "SANS"],
      "type": "SERVICE|MALWARE|NONE",
      "shortDescription": "port description",
      "longDescription": "detailed description"
    }
  ]
}
```

---

## 9. SINKHOLE_IDENTIFIERS (Sinkhole Identifiers)
**Collection**: `SINKHOLE_IDENTIFIERS`  
**Purpose**: Store known sinkhole IP addresses  
**Shard Location**: r02

```json
{
  "_id": { "identifier": "IP address" },
  "_class": "com.cybereason.sage.model.dataset.sinkhole.SinkholeIdentifierRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.sinkhole.SinkholeIdentifierInfo",
    "type": "IP",
    "entity": "operating organization name"
  }
}
```

---

## 10. FILE_EXTENSION_CLASSIFICATION (File Extension Classification)
**Collection**: `FILE_EXTENSION_CLASSIFICATION`  
**Purpose**: Store file extension type classification  
**Shard Location**: r04

```json
{
  "_id": { "extension": "extension" },
  "_class": "com.cybereason.sage.model.dataset.extension.FileExtensionClassificationRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.extension.FileExtensionInfo",
    "sources": ["dotwhat.net", "wikipedia.org"],
    "description": "file type description",
    "type": "DOCUMENT_AUDIO|DOCUMENT_VIDEO|ARCHIVE_COMPRESSED|SYSTEM_WINDOWS|..."
  }
}
```

---

## 11. FILE_CLASSIFICATION (File/Process Classification)
**Collection**: `FILE_CLASSIFICATION`  
**Purpose**: Store known process/executable file classification information  
**Shard Location**: r05

```json
{
  "_id": { "name": "process.exe" },
  "_class": "com.cybereason.sage.model.dataset.process.ProcessClassificationRecord",
  "value": [
    {
      "_class": "com.cybereason.sage.model.dataset.process.PeProductInfo",
      "name": "process.exe",
      "title": "product title",
      "productName": "product name",
      "companyName": "company name",
      "fileDescription": "file description",
      "path": "full path",
      "canonizedPath": "canonized path (%APPDATA%\\...)",
      "processType": "BROWSER|MAIL|SHARING|...",
      "isSigned": true|false
    }
  ]
}
```

---

## 12. PRODUCT_CLASSIFICATION (Product Classification)
**Collection**: `PRODUCT_CLASSIFICATION`  
**Purpose**: Store software product type classification (antivirus, browser, etc.)  
**Shard Location**: r05

```json
{
  "_id": { "name": "executable.exe" },
  "_class": "com.cybereason.sage.model.dataset.file.ProductClassificationRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.file.VtProductInfo",
    "signer": ["signer name"],
    "type": "ANTI_VIRUS|BROWSER|MS_OFFICE|P2P|...",
    "title": "product title"
  }
}
```

---

## 13. MALOP_CONSTANTS (Malop Constants)
**Collection**: `MALOP_CONSTANTS`  
**Purpose**: Store constant data used in Malop detection  
**Shard Location**: r03

```json
{
  "_id": { "name": "constant name" },
  "_class": "com.cybereason.sage.model.dataset.constants.ConstantsClassificationRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.constants.ConstantsInfo",
    "data": ["value1", "value2", "..."]
  }
}
```

**Common Constants**:
- `POWERSHELL_COMPRESSED_ENCODED`: PowerShell compressed encoding patterns
- `NETWORK_SCANNERS`: Network scanner tool list
- `ACCESSIBILITY_TOOLS`: Accessibility tools
- `OS_PROCESSES_WITH_COMPANY`: System process list

---

## 14. DLL_OFFSETS (DLL Offsets)
**Collection**: `DLL_OFFSETS`  
**Purpose**: Store DLL symbol offset information (for memory analysis)  
**Shard Location**: r01-r06

```json
{
  "_id": { "name": "DLL hash identifier" },
  "_class": "com.cybereason.sage.model.dataset.dlloffsets.DllOffsetsRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.dlloffsets.DllOffsetsInfo",
    "dllName": "DLL filename",
    "data": [
      {
        "symbolName": "symbol name",
        "offset": Number,
        "size": Number,
        "isPointer": 0|1
      }
    ]
  }
}
```

---

## 15. PROCESS_HIERARCHY (Process Hierarchy)
**Collection**: `PROCESS_HIERARCHY`  
**Purpose**: Store normal Windows process parent-child relationships  
**Shard Location**: r01

```json
{
  "_id": { "name": "process.exe" },
  "_class": "com.cybereason.sage.model.dataset.process.ProcessHierarchyRecord",
  "value": [
    {
      "_class": "com.cybereason.sage.model.dataset.process.ProcessHierarchyInfo",
      "parent": "parent_process.exe"
    }
  ]
}
```

---

## 16. TTL (TTL Configuration)
**Collection**: `TTL`  
**Purpose**: Store cache TTL configuration parameters  
**Shard Location**: r05

```json
{
  "_id": "config key",
  "_class": "com.cybereason.sage.model.dataset.file.TtlRecord",
  "value": Number
}
```

**Configuration Items**:
- `DEFAULT`: Default TTL (30 days)
- `MAX`: Maximum TTL (30 days)
- `RECHECK`: Recheck interval (7 days)
- `UNKNOWN`: Unknown status TTL (1 day)

---

## 17. ENGINES (Engine Configuration)
**Collection**: `ENGINES`  
**Purpose**: Store VirusTotal and other engine scoring weight configuration  
**Shard Location**: r06

```json
{
  "_id": "VirusTotal",
  "_class": "com.cybereason.sage.model.dataset.engines.EnginesRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.engines.Engines",
    "generation_date": "generation date",
    "detection_score_threshold": Number,
    "true_positive_type_factors": {
      "malware": Number,
      "unwanted": Number,
      "hacktool": Number,
      "maltool": Number,
      "suspicious": Number
    },
    "classification_type_factors": { /* same as above */ },
    "additional_score_for_signed_file": { /* same as above */ },
    "anti_virus_engine_factors": {
      "engine name": Number
    }
  }
}
```

---

## 18. QUOTA_LIMITS (Quota Limits)
**Collection**: `QUOTA_LIMITS`  
**Purpose**: Store VirusTotal API quota for each host  
**Shard Location**: r06

```json
{
  "_id": "VirusTotal",
  "_class": "com.cybereason.sage.model.dataset.quota.QuotaLimitsRecord",
  "value": {
    "_class": "com.cybereason.sage.model.dataset.quota.QuotaLimits",
    "defaultQuota": Number,
    "hostToQuota": {
      "host name pattern": Number
    }
  }
}
```

---

## 19. alerts (System Alerts)
**Collection**: `alerts`  
**Purpose**: Store Sage system runtime alerts  
**Shard Location**: r04

```json
{
  "_id": NumberLong,  // timestamp
  "_class": "com.cybereason.sage.common.alerts.SageAlert",
  "dateTime": "alert time string",
  "level": "Critical|Warning|Info",
  "message": "alert message"
}
```

---

## 20. properties (System Properties)
**Collection**: `properties`  
**Purpose**: Store system configuration properties  
**Shard Location**: r01

Contains multiple configuration types:
- `MalopReportModel`: Malop report configuration
- `SmtpInfoModel`: SMTP email configuration

---

## Data Volume Statistics

| Collection | Per-Shard Size | 6-Shard Total |
|------------|----------------|---------------|
| file_rep | ~950 GB | ~5.7 TB |
| domain_dns | ~700 GB | ~4.2 TB |
| domain_classification | ~80 GB | ~480 GB |
| Small Collections | < 10 MB | < 60 MB |
| **Total** | ~1.7 TB | **~10.4 TB** |

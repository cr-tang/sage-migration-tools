# Phoenix Flink TI Enrichment - 数据源与迁移方案

> 最后更新: 2026-02-03
> 基于 Sage、VT Feeder Suite、MongoDB Snapshot 的分析

---

## 一、数据源架构总览

### 1.1 Sage 数据源层次结构

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           Sage 数据源架构                                            │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 1: 外部数据源 (Source of Truth)                                         │  │
│  │                                                                               │  │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │  │
│  │   │ VirusTotal   │  │ Reversing    │  │ OPSWAT       │  │ TAXII/STIX   │     │  │
│  │   │ Feed API     │  │ Labs API     │  │ MetaDefender │  │ Threat Feeds │     │  │
│  │   │ (Premium)    │  │              │  │              │  │              │     │  │
│  │   └──────┬───────┘  └──────────────┘  └──────────────┘  └──────────────┘     │  │
│  │          │                                                                    │  │
│  └──────────┼────────────────────────────────────────────────────────────────────┘  │
│             │                                                                       │
│             │ 每分钟拉取全量数据 (VT Feed API)                                       │
│             ▼                                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 2: VT Feeder Suite (GCS 存储)                                           │  │
│  │                                                                               │  │
│  │   ┌──────────────────────────────────────────────────────────────────────┐   │  │
│  │   │ vt-file-feeder/latest-reports/{sha1}  ← File 按 hash 索引 (实时查询) │   │  │
│  │   │ vt-file-feeder-by-date/{date}/{ts}    ← File 按日期归档             │   │  │
│  │   └──────────────────────────────────────────────────────────────────────┘   │  │
│  │   ┌──────────────────────────────────────────────────────────────────────┐   │  │
│  │   │ broccoli-enricher/latest-reports/{sha1} ← ML 分类结果               │   │  │
│  │   └──────────────────────────────────────────────────────────────────────┘   │  │
│  │   ┌──────────────────────────────────────────────────────────────────────┐   │  │
│  │   │ vt-url-feeder-by-date/{date}/{ts}     ← URL 按日期归档 (无实时查询) │   │  │
│  │   │ → BigQuery                            ← URL 数据最终存储           │   │  │
│  │   └──────────────────────────────────────────────────────────────────────┘   │  │
│  │                                                                               │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
│             │                                                                       │
│             │ Sage 查询时使用                                                        │
│             ▼                                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 3: MongoDB (缓存层)                                                     │  │
│  │                                                                               │  │
│  │   file_rep (5.6 TB)           ← VT 文件扫描结果缓存                          │  │
│  │   domain_classification (446 GB) ← VT 域名分类缓存                           │  │
│  │   domain_dns (3.85 TB)        ← DNS 解析结果缓存                             │  │
│  │   TOKENS (890 KB)             ← 内部威胁情报                                 │  │
│  │   SINKHOLE_IDENTIFIERS (456 KB) ← Sinkhole IP 列表                          │  │
│  │   FILE_EXTENSION_CLASSIFICATION (105 KB) ← 文件扩展名分类                   │  │
│  │                                                                               │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 关键发现: File vs Domain vs URL vs IP 的数据流差异

| 数据类型 | VT Feeder (GCS) | VT API | MongoDB 缓存 | BigQuery |
|---------|----------------|--------|-------------|----------|
| **File Hash** | ✅ `vt-file-feeder/latest-reports/{sha1}` | Fallback | `file_rep` | ❌ |
| **Domain** | ❌ 不支持 | ✅ 主要数据源 | `domain_classification` | ❌ |
| **URL** | ❌ 仅按日期归档 | ✅ 主要数据源 | - | ✅ 主要存储 |
| **IP** | ❌ 不支持 | ❌ 不支持 | `SINKHOLE_IDENTIFIERS`, `TOKENS` | ❌ |

**注意**: IP 数据主要来自:
- **SINKHOLE_IDENTIFIERS**: 已知 Sinkhole IP 列表 (用于检测被 sinkhole 的恶意域名)
- **TOKENS**: 内部威胁情报中的恶意 IP

**原因分析**:

| 因素 | File Hash | Domain/URL |
|-----|----------|------------|
| **标识符长度** | 固定 (SHA1=40字符) | 可变 (URL 可能很长) |
| **GCS 作为 Key** | ✅ 适合 | ⚠️ 不适合 |
| **查询频率** | 非常高 | 相对较低 |
| **存储方式** | 按 SHA1 索引 | 按时间归档 |

---

## 二、VT Feeder Suite 详解

### 2.1 什么是 VT Feed API？

**VT Feed API** 是 VirusTotal 的 **Premium/Enterprise 功能**，提供全球所有扫描结果的实时数据流。

```
全球 VT 用户 (每分钟数千次扫描)
       │
       ▼
VirusTotal 平台 (扫描并生成报告)
       │
       │ Feed API (每分钟打包)
       ▼
tar.bz2 包 (~50MB/分钟)
       │
       │ VT Feeder Suite 拉取
       ▼
GCS Buckets (vt-file-feeder, etc.)
```

**API 端点**:
```
https://www.virustotal.com/vtapi/v2/{file|url}/feed?apikey={apikey}&package={timestamp}
```

### 2.2 VT Feeder 配置对比

**File Feeder** (支持实时查询):
```properties
bucket.name=vt-file-feeder
should.store.latest.by.identifier=true   # ← 按 SHA1 存储
gcp.bq.enable=false                       # ← 不存 BigQuery
```

**URL Feeder** (不支持实时查询):
```properties
bucket.name=vt-url-feeder
should.store.latest.by.identifier=false  # ← 不按 URL 存储
gcp.bq.enable=true                        # ← 存入 BigQuery
```

### 2.3 Broccoli ML 分类服务

**Broccoli** 是 Sage 的 ML 分类服务，分析 VT 扫描结果并输出最终分类。

```
VT Raw Report (70+ AV 引擎结果，可能冲突)
       │
       │ Broccoli ML 模型
       ▼
Classification: malware/ransomware/indifferent/etc.
       │
       │ 存储到 GCS
       ▼
broccoli-enricher/latest-reports/{sha1}
```

---

## 三、Sage 查询流程

### 3.1 File Hash 查询流程

```java
// VirusTotalWebService.java
public VirusTotalFileReport scanFileHash(String hash) {
    // 1. 优先使用 VT Feeder (GCS)
    if (vtFeederWebService.isEnable()) {
        return vtFeederWebService.scanFileHash(hash);
        // → 读取 vt-file-feeder/latest-reports/{sha1}
        // → 读取 broccoli-enricher/latest-reports/{sha1}
    }
    
    // 2. Fallback: 直接调用 VT API
    // POST /vtapi/v2/file/report?resource={hash}
}
```

### 3.2 Domain 查询流程

```java
// VirusTotalWebService.java
public VirusTotalDomainReport scanDomain(String domainName) {
    // 直接调用 VT API - 无 VT Feeder!
    // GET /vtapi/v2/domain/report?domain={domain}
}
```

### 3.3 URL 查询流程

```java
// VirusTotalWebService.java
public FileReportBase scanURL(String url) {
    // 直接调用 VT API - 无 VT Feeder!
    // POST /vtapi/v2/url/report?resource={url}
}
```

---

## 四、MongoDB Snapshot 分析

### 4.1 数据来源

- **位置**: `gs://sage_prod_dump/`
- **日期**: 2020-11-05
- **总大小**: ~9.5 TB (6 shards)
- **性质**: Sage MongoDB **缓存快照**，不是全量数据

### 4.2 主要 Collection

| Collection | 大小 | 记录数 | 说明 |
|------------|------|-------|------|
| `file_rep` | 5.6 TB | ~99 亿 | VT 文件扫描结果 |
| `domain_dns` | 3.85 TB | ~21 亿 | DNS 解析结果 |
| `domain_classification` | 446 GB | ~8 亿 | VT 域名分类 |
| `TOKENS` | 890 KB | ~2,500 | 内部威胁情报 |
| `SINKHOLE_IDENTIFIERS` | 456 KB | ~3,000 | Sinkhole IP |
| `FILE_EXTENSION_CLASSIFICATION` | 105 KB | ~337 | 扩展名分类 |

### 4.3 file_rep 数据分布 (基于 r06 实际处理结果)

```
Total: ~16.5 亿条 (单 shard)
│
├── response_code=0 (VT 无数据): ~90%
│   └── 跳过
│
├── response_code=1 + classification=indifferent/unknown: ~9.99%
│   └── 跳过
│
└── response_code=1 + 有效恶意分类: ~0.009%
    └── 导入 → ~14.3 万条/shard

实际 r06 数据:
- 输入: 832 GB, 16.5 亿条
- 有效: 142,949 条 (0.0087%)
- 输出: 230 MB (gzip 压缩)
- 压缩比: 3617:1
- 处理时间: 5.15 小时
```

### 4.4 file_rep 记录类型

**Type A**: VT 无数据 (90%)
```json
{
  "_id": "sha1_hash",
  "response": "unknown(-1.0,-1.0);NONE.null",
  "value": {
    "response_code": 0,
    "verbose_msg": "The requested resource is not among the finished..."
  }
  // 无 vtClassifierV2Classification, 无 scans
}
```

**Type B**: VT 有数据 + 良性 (~9.99%)
```json
{
  "_id": "sha1_hash",
  "response": "indifferent(-1.0,-1.0);NONE.null",
  "vtClassifierV2Classification": {
    "classification": "indifferent"  // ML 分类: 良性
  },
  "value": {
    "response_code": 1,
    "positives": 0,
    "scans": { ... }
  }
}
```

**Type C**: VT 有数据 + 恶意 (~0.009%)
```json
{
  "_id": "sha1_hash",
  "response": "malware.virus.trojan(14.57,14.35);NONE.null",
  "vtClassifierV2Classification": {
    "classification": "malware"  // ML 分类: 恶意
  },
  "value": {
    "response_code": 1,
    "positives": 45,
    "scans": { ... }
  }
}
```

---

## 五、Phoenix Flink TI Enrichment 需求

### 5.1 核心接口

```kotlin
interface ThreatIntelService {
    // Phase 1: File Hash
    fun isKnownMalicious(hash: String, type: HashType): Boolean
    fun getFileClassification(hash: String, type: HashType): ClassificationResult?
    
    // Phase 2: Domain & IP
    fun getDomainClassification(domain: String): ClassificationResult?
    fun getIpClassification(ip: String): ClassificationResult?
    
    // Phase 3: Double Extension Detection
    fun getExtensionType(extension: String): ExtensionType?
}
```

### 5.2 TiDB 表结构

| Phase | 表名 | 主要字段 | 数据来源 |
|-------|------|---------|---------|
| 1 | `ioc_file_hashes` | sha256, sha1, md5, classification, source, detection_names | MongoDB `file_rep` |
| 2 | `ioc_domains` | domain, classification, source | MongoDB `domain_classification` |
| 2 | `ioc_ips` | ip, ip_version, classification, sinkhole_entity | MongoDB `SINKHOLE_IDENTIFIERS` |
| 3 | `file_extension_classification` | extension, extension_type, is_executable, is_document | MongoDB `FILE_EXTENSION_CLASSIFICATION` |
| 4 | `customer_ioc` | org_id, indicator_type, indicator_value, reputation | Phoenix Portal API |
| 5 | `ioc_tokens` | indicator, indicator_type, classification, source_campaign | MongoDB `TOKENS` |

### 5.3 Classification 枚举

```kotlin
enum class Classification {
    RANSOMWARE,   // 勒索软件 (最高优先级)
    MALTOOL,      // 恶意工具
    HACKTOOL,     // 黑客工具
    UNWANTED,     // 不需要的软件/PUP
    MALWARE,      // 通用恶意软件
    SUSPICIOUS,   // 可疑但未确认
    BLACKLIST,    // 客户黑名单
    AV_DETECTED,  // AV 报告检测
    SINKHOLED,    // Domain 解析到 Sinkhole IP
    UNRESOLVED,   // Domain 无法解析
    WHITELIST,    // 白名单
    INDIFFERENT,  // 中性/良性
    UNKNOWN       // 无数据
}
```

---

## 六、数据迁移方案

### 6.1 数据源时间线

```
         2020-11-05                    2020 - 2026                    Now
              │                              │                         │
              ▼                              ▼                         ▼
┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
│ MongoDB Snapshot        │  │ VT Feeder (持续拉取)    │  │ 实时查询               │
│                         │  │                         │  │                         │
│ • file_rep              │  │ • vt-file-feeder GCS   │  │ • VT Feeder (File)     │
│ • domain_classification │  │ • broccoli-enricher    │  │ • VT API (Domain/URL)  │
│ • domain_dns            │  │                         │  │                         │
└─────────────────────────┘  └─────────────────────────┘  └─────────────────────────┘
         │                              │                         │
         │                              │                         │
         ▼                              ▼                         ▼
    历史基线数据               增量数据 (GCS 中)              按需查询
    (一次性导入)               (可选: 定期同步)             (Flink 运行时)
```

### 6.2 File Hash 迁移流程

```
MongoDB file_rep (5.6 TB, 6 shards)
    │
    ▼ parallel_bson_processor.py
    │ - 过滤 response_code=0
    │ - 过滤 classification=indifferent/unknown
    │ - 保留 positives>0 或有效分类
    │ - 输出完整 value 对象
    ▼
file_rep_{shard}_full.ndjson.gz (~230 MB/shard)
    │
    ▼ tidb_importer.py
    │
    ▼
TiDB ioc_file_hashes (~14万条/shard, 总计 ~100万条)
```

### 6.3 IP 数据迁移

**数据来源**:

1. **SINKHOLE_IDENTIFIERS** (MongoDB r02, 456 KB, ~3,000 条)
   - Sinkhole IP 地址列表
   - 用于检测恶意域名是否被 sinkhole
   
   ```json
   {
     "_id": {"identifier": "104.236.245.219"},
     "value": {
       "type": "IP",
       "entity": "Georgia Institute of Technology / Damballa"
     }
   }
   ```

2. **TOKENS** (MongoDB r01, 部分 IP 记录)
   - 内部威胁情报中的恶意 IP
   
   ```json
   {
     "_id": "0.1.2.3",
     "response": "malware",
     "value": {
       "maliciousType": "malware",
       "source": "Example",
       "type": "IPv4"
     }
   }
   ```

**TiDB 目标表**: `ioc_ips`

| 字段 | 类型 | 说明 |
|-----|------|------|
| `ip` | VARBINARY(16) | IP 地址 (INET6_ATON) |
| `ip_version` | TINYINT | 4=IPv4, 6=IPv6 |
| `classification` | ENUM | SINKHOLED, MALWARE, etc. |
| `source` | ENUM | SINKHOLE_IDENTIFIERS, TOKENS |
| `sinkhole_entity` | VARCHAR(255) | Sinkhole 运营组织 |

### 6.4 小数据集迁移 (直接转换)

| 数据集 | 大小 | 记录数 | 目标表 | 迁移方式 |
|-------|------|-------|-------|---------|
| TOKENS | 890 KB | ~2,500 | `ioc_tokens` | JSON 转换导入 |
| SINKHOLE_IDENTIFIERS | 456 KB | ~3,000 | `ioc_ips` | JSON 转换导入 |
| FILE_EXTENSION_CLASSIFICATION | 105 KB | ~337 | `file_extension_classification` | JSON 转换导入 |
| TOKENS (IP 部分) | - | ~500 | `ioc_ips` | JSON 转换导入 |

### 6.4 Domain 迁移策略

**挑战**: Domain 没有 GCS 全量数据，2020 后需通过 VT API 实时查询。

**方案**:
1. **历史数据**: 从 MongoDB `domain_classification` 提取 (~446 GB)
2. **增量数据**: Flink 查询时写入 TiDB 作为缓存
3. **实时查询**: 缓存未命中时调用 Sage/VT API

---

## 七、当前进度

### 7.1 已完成

| 项目 | 状态 | 说明 |
|-----|------|------|
| TiDB Schema 设计 | ✅ | 6 个表已创建 |
| `parallel_bson_processor.py` | ✅ | File Hash 处理工具 |
| `tidb_importer.py` | ✅ | TiDB 导入工具 |
| Flink TI Enrichment 接口 | ✅ | `ThreatIntelService` |
| Flink TiDB Storage | ✅ | `TidbStorage` |
| r06 Shard 测试 | ✅ | 142,949 条, 230 MB |

### 7.2 进行中

| 项目 | 状态 | 说明 |
|-----|------|------|
| 其他 5 个 shard 处理 | 🔄 | 预计 ~25 小时 |

### 7.3 待开始

| 项目 | 状态 | 优先级 |
|-----|------|-------|
| Domain 处理脚本 | ⬜ | 中 |
| TOKENS 导入 | ⬜ | 高 (小数据集) |
| SINKHOLE_IDENTIFIERS 导入 | ⬜ | 高 (小数据集) |
| FILE_EXTENSION_CLASSIFICATION 导入 | ⬜ | 高 (小数据集) |
| `migrate-ti.sh seed` 运行 | ⬜ | 高 |
| Phoenix 直接访问 VT Feeder | ⬜ | 低 (长期优化) |

### 7.4 预估最终数据量

| TiDB 表 | 预估记录数 | 预估大小 |
|--------|----------|---------|
| `ioc_file_hashes` | ~100 万 | ~100 MB |
| `ioc_domains` | 待评估 | 待评估 |
| `ioc_ips` | ~3,500 | ~300 KB |
| `file_extension_classification` | ~337 | ~50 KB |
| `ioc_tokens` | ~2,500 | ~500 KB |
| `customer_ioc` | 按客户 | 变化 |

---

## 八、关键命令

### 8.1 File Hash 处理

```bash
# 处理单个 shard
python3 parallel_bson_processor.py --shard r06

# 处理所有 shard
python3 parallel_bson_processor.py

# 导入 TiDB
python3 tidb_importer.py --input file_rep_r06_full.ndjson.gz
```

### 8.2 查看处理进度

```bash
# 查看日志
tail -f bson_processor_r06.log

# 查看输出文件
zcat file_rep_r06_full.ndjson.gz | head -5
zcat file_rep_r06_full.ndjson.gz | wc -l
```

### 8.3 TiDB 查询

```bash
# 进入 TiDB
kubectl exec -it tidb-0 -n tidb -- mysql -u root -P 4000

# 查看数据
USE threat_intel;
SELECT COUNT(*) FROM ioc_file_hashes;
SELECT * FROM ioc_file_hashes LIMIT 5;
```

---

## 附录: 文件位置参考

| 文件 | 路径 |
|-----|------|
| BSON Processor | `tools/scripts/parallel-bson-processor/parallel_bson_processor.py` |
| TiDB Importer | `tools/scripts/parallel-bson-processor/tidb_importer.py` |
| TiDB Schema | `/Users/tangxin/work/Phoenix/migrations/mysql/up/` |
| Flink TI Service | `src/main/kotlin/com/cybereason/phoenix/rules/enrichment/` |
| 数据源文档 | `/Users/tangxin/work/sage-content-provider/mongo_dump_samples/` |
| VT Feeder Suite | `/Users/tangxin/work/vt-feeder-suite/` |
| Sage Content Provider | `/Users/tangxin/work/sage-content-provider/` |

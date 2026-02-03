# TiDB Connection and Queries

## Connection Info

| Environment | Host | Port | Database |
|-------------|------|------|----------|
| Dev | tidb-dev-us-ashburn-1.cybereason.net | 4000 | threat_intel |
| Stage | tidb-stg-ap-tokyo-1.cybereason.net | 4000 | threat_intel |
| Prod | tidb-prod-ap-tokyo-1.cybereason.net | 4000 | threat_intel |

## Connect via MySQL Client

```bash
# Stage
mysql -h tidb-stg-ap-tokyo-1.cybereason.net -P 4000 -u root -p threat_intel

# Using busybox pod in Kubernetes
kubectl exec -it busybox -n stgbusybox -- mysql -h tidb-stg-ap-tokyo-1 -P 4000 -u root -p threat_intel
```

## Python Connection

```python
import mysql.connector

conn = mysql.connector.connect(
    host='tidb-stg-ap-tokyo-1.cybereason.net',
    port=4000,
    user='root',
    password='your_password',
    database='threat_intel'
)
cursor = conn.cursor(dictionary=True)
cursor.execute("SELECT COUNT(*) FROM ioc_file_hashes")
print(cursor.fetchone())
```

## TI Tables Schema

### ioc_file_hashes
```sql
SELECT sha1, sha256, md5, classification, source, detection_names, positives, created_at
FROM ioc_file_hashes
WHERE sha1 = UNHEX('...');
```

### ioc_domains
```sql
SELECT domain, classification, source, max_positives, created_at
FROM ioc_domains
WHERE domain = '...';
```

### ioc_ips
```sql
SELECT INET6_NTOA(ip) as ip, ip_version, classification, source, sinkhole_entity
FROM ioc_ips
WHERE ip = INET6_ATON('...');
```

### ioc_tokens
```sql
SELECT indicator, indicator_type, classification, source_campaign, link
FROM ioc_tokens
WHERE indicator = '...';
```

### file_extension_classification
```sql
SELECT extension, extension_type
FROM file_extension_classification
WHERE extension = '...';
```

## Useful Queries

### Check Table Counts
```sql
SELECT 
    (SELECT COUNT(*) FROM ioc_file_hashes) as file_hashes,
    (SELECT COUNT(*) FROM ioc_domains) as domains,
    (SELECT COUNT(*) FROM ioc_ips) as ips,
    (SELECT COUNT(*) FROM ioc_tokens) as tokens,
    (SELECT COUNT(*) FROM file_extension_classification) as extensions;
```

### Check Recent Imports
```sql
SELECT DATE(created_at), COUNT(*) 
FROM ioc_file_hashes 
GROUP BY DATE(created_at) 
ORDER BY 1 DESC LIMIT 10;
```

### Migration Changelog
```sql
SELECT * FROM common.migration_changelog ORDER BY applied_at DESC LIMIT 10;
```

## Troubleshooting

### Connection Timeout
- Check VPN connection
- Verify Kubernetes cluster access
- Try using busybox pod if direct connection fails

### Permission Issues
- Verify user has access to threat_intel database
- Check with DBA for credentials

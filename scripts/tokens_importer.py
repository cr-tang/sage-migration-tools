#!/usr/bin/env python3
"""
TOKENS Importer - Import Cybereason curated IOCs from TOKENS.bson into TiDB.

The TOKENS table contains Cybereason's high-confidence threat intelligence
indicators with known campaign/APT attribution.

Indicator Types:
- SHA1, MD5, SHA256: File hashes → ioc_file_hashes
- DOMAIN: Domain names → ioc_domains
- IPv4: IP addresses → ioc_ips

Usage:
    # From local BSON file
    python3 tokens_importer.py --input TOKENS.bson

    # From GCS
    python3 tokens_importer.py --gcs gs://sage_prod_dump/cr-mongo-shard-r01.cybereason.net/cybereason/TOKENS.bson

    # Dry run (parse only)
    python3 tokens_importer.py --input TOKENS.bson --dry-run
"""
import argparse
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# BSON parser
try:
    import bson
except ImportError:
    print("Error: pymongo not installed. Run: pip install pymongo")
    sys.exit(1)

# MySQL connector
try:
    import mysql.connector
    from mysql.connector import pooling
except ImportError:
    print("Error: mysql-connector-python not installed. Run: pip install mysql-connector-python")
    sys.exit(1)


# ----------------------------
# Constants
# ----------------------------
SOURCE = "TOKENS"  # TiDB source ENUM value

# Classification mapping: Sage maliciousType → TiDB Classification ENUM
CLASSIFICATION_MAP = {
    "ransomware": "RANSOMWARE",
    "maltool": "MALTOOL",
    "hacktool": "HACKTOOL",
    "unwanted": "UNWANTED",
    "malware": "MALWARE",
    "suspicious": "SUSPICIOUS",
    "blacklist": "BLACKLIST",
    # Skip these
    "indifferent": None,
    "unknown": None,
    "whitelist": None,
    "no_type_found": None,
}

# Token types and their target tables
TOKEN_TYPE_CONFIG = {
    "SHA1": {"table": "ioc_file_hashes", "hash_type": "sha1"},
    "SHA256": {"table": "ioc_file_hashes", "hash_type": "sha256"},
    "MD5": {"table": "ioc_file_hashes", "hash_type": "md5"},
    "DOMAIN": {"table": "ioc_domains", "field": "domain"},
    "IPv4": {"table": "ioc_ips", "field": "ip"},
}


# ----------------------------
# Logging setup
# ----------------------------
def setup_logging(log_file: Optional[str] = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, mode='a'))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers,
    )
    return logging.getLogger(__name__)


# ----------------------------
# Data transformation
# ----------------------------
def hex_to_bytes(hex_str: Optional[str]) -> Optional[bytes]:
    """Convert hex string to bytes for BINARY column storage."""
    if not hex_str:
        return None
    try:
        return bytes.fromhex(hex_str.lower())
    except ValueError:
        return None


@dataclass
class TokenRecord:
    """Parsed TOKENS record."""
    indicator: str  # The indicator value (_id)
    indicator_type: str  # DOMAIN, SHA1, MD5, SHA256, IPv4
    classification: str  # Mapped TiDB classification
    source_campaign: str  # Original source/campaign name (e.g., "Locky", "Asian APT")
    link: Optional[str]  # Reference URL


def parse_token_record(doc: Dict[str, Any]) -> Optional[TokenRecord]:
    """Parse a BSON document into TokenRecord."""
    indicator = doc.get("_id")
    if not indicator:
        return None
    
    value = doc.get("value", {})
    token_type = value.get("type")
    malicious_type = value.get("maliciousType")
    source_campaign = value.get("source", "")
    link = value.get("link")
    
    # Validate token type
    if token_type not in TOKEN_TYPE_CONFIG:
        return None
    
    # Map classification
    classification = CLASSIFICATION_MAP.get(malicious_type.lower() if malicious_type else "unknown")
    if not classification:
        return None
    
    return TokenRecord(
        indicator=indicator,
        indicator_type=token_type,
        classification=classification,
        source_campaign=source_campaign,
        link=link,
    )


def read_bson_file(filepath: str, logger: logging.Logger) -> List[Dict[str, Any]]:
    """Read all documents from a BSON file."""
    documents = []
    with open(filepath, 'rb') as f:
        try:
            while True:
                doc = bson.decode_file_iter(f)
                for d in doc:
                    documents.append(d)
                break
        except Exception:
            # Try alternative approach - read entire file
            f.seek(0)
            data = f.read()
            try:
                # Try decode_all
                documents = bson.decode_all(data)
            except Exception as e:
                logger.error(f"Failed to parse BSON file: {e}")
                raise
    logger.info(f"Read {len(documents)} documents from BSON file")
    return documents


# ----------------------------
# GCS operations
# ----------------------------
def download_from_gcs(gcs_path: str, logger: logging.Logger) -> str:
    """Download file from GCS to temp location."""
    try:
        from google.cloud import storage
    except ImportError:
        logger.error("google-cloud-storage not installed. Run: pip install google-cloud-storage")
        sys.exit(1)
    
    # Parse GCS path: gs://bucket/path/to/file
    if not gcs_path.startswith("gs://"):
        raise ValueError(f"Invalid GCS path: {gcs_path}")
    
    parts = gcs_path[5:].split("/", 1)
    bucket_name = parts[0]
    blob_name = parts[1] if len(parts) > 1 else ""
    
    logger.info(f"Downloading from GCS: {gcs_path}")
    
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    
    # Download to temp file
    temp_file = tempfile.NamedTemporaryFile(suffix=".bson", delete=False)
    blob.download_to_filename(temp_file.name)
    
    logger.info(f"Downloaded to: {temp_file.name}")
    return temp_file.name


# ----------------------------
# TiDB operations
# ----------------------------
class TiDBImporter:
    def __init__(self, host: str, port: int, user: str, password: str, database: str, pool_size: int = 3):
        self.config = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "database": database,
        }
        self.pool = pooling.MySQLConnectionPool(
            pool_name="tokens_pool",
            pool_size=pool_size,
            **self.config
        )
        self.logger = logging.getLogger(__name__)
    
    def test_connection(self) -> bool:
        """Test database connection."""
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def insert_file_hash(self, records: List[TokenRecord]) -> Tuple[int, int]:
        """Insert file hash records into ioc_file_hashes."""
        if not records:
            return 0, 0
        
        # Group by hash type
        by_type = {"sha1": [], "sha256": [], "md5": []}
        for r in records:
            hash_type = TOKEN_TYPE_CONFIG[r.indicator_type]["hash_type"]
            by_type[hash_type].append(r)
        
        total_inserted = 0
        total_skipped = 0
        
        for hash_type, type_records in by_type.items():
            if not type_records:
                continue
            
            # Build INSERT with only the relevant hash column
            sql = f"""
                INSERT IGNORE INTO ioc_file_hashes 
                ({hash_type}, classification, source, detection_names)
                VALUES (%s, %s, %s, %s)
            """
            
            values = []
            for r in type_records:
                hash_bytes = hex_to_bytes(r.indicator)
                if not hash_bytes:
                    total_skipped += 1
                    continue
                # Store campaign name in detection_names field
                detection_names = f"source:{r.source_campaign}"
                if r.link:
                    detection_names += f";link:{r.link}"
                values.append((hash_bytes, r.classification, SOURCE, detection_names))
            
            if values:
                inserted, skipped = self._batch_execute(sql, values)
                total_inserted += inserted
                total_skipped += skipped
        
        return total_inserted, total_skipped
    
    def insert_domains(self, records: List[TokenRecord]) -> Tuple[int, int]:
        """Insert domain records into ioc_domains."""
        if not records:
            return 0, 0
        
        sql = """
            INSERT IGNORE INTO ioc_domains 
            (domain, classification, source)
            VALUES (%s, %s, %s)
        """
        
        values = []
        for r in records:
            domain = r.indicator.lower().lstrip(".")  # Remove leading dots
            values.append((domain, r.classification, SOURCE))
        
        return self._batch_execute(sql, values)
    
    def insert_ips(self, records: List[TokenRecord]) -> Tuple[int, int]:
        """Insert IP records into ioc_ips."""
        if not records:
            return 0, 0
        
        sql = """
            INSERT IGNORE INTO ioc_ips 
            (ip, classification, source)
            VALUES (INET6_ATON(%s), %s, %s)
        """
        
        values = []
        for r in records:
            values.append((r.indicator, r.classification, SOURCE))
        
        return self._batch_execute(sql, values)
    
    def _batch_execute(self, sql: str, values: List[tuple]) -> Tuple[int, int]:
        """Execute batch insert."""
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.executemany(sql, values)
            conn.commit()
            inserted = cursor.rowcount
            skipped = len(values) - inserted
            cursor.close()
            conn.close()
            return inserted, skipped
        except Exception as e:
            self.logger.error(f"Batch insert failed: {e}")
            raise
    
    def get_counts(self) -> Dict[str, int]:
        """Get current record counts."""
        counts = {}
        tables = ["ioc_file_hashes", "ioc_domains", "ioc_ips"]
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE source = %s", (SOURCE,))
                counts[table] = cursor.fetchone()[0]
            cursor.close()
            conn.close()
        except Exception as e:
            self.logger.error(f"Count query failed: {e}")
        return counts


# ----------------------------
# Main import logic
# ----------------------------
def import_tokens(
    importer: TiDBImporter,
    documents: List[Dict[str, Any]],
    logger: logging.Logger,
    dry_run: bool = False,
) -> Dict[str, int]:
    """Import TOKENS documents into TiDB."""
    stats = {
        "total": len(documents),
        "parsed": 0,
        "skipped": 0,
        "file_hashes": {"parsed": 0, "inserted": 0, "skipped": 0},
        "domains": {"parsed": 0, "inserted": 0, "skipped": 0},
        "ips": {"parsed": 0, "inserted": 0, "skipped": 0},
    }
    
    # Parse and categorize records
    file_hash_records = []
    domain_records = []
    ip_records = []
    
    for doc in documents:
        record = parse_token_record(doc)
        if not record:
            stats["skipped"] += 1
            continue
        
        stats["parsed"] += 1
        
        if record.indicator_type in ("SHA1", "SHA256", "MD5"):
            file_hash_records.append(record)
            stats["file_hashes"]["parsed"] += 1
        elif record.indicator_type == "DOMAIN":
            domain_records.append(record)
            stats["domains"]["parsed"] += 1
        elif record.indicator_type == "IPv4":
            ip_records.append(record)
            stats["ips"]["parsed"] += 1
    
    logger.info(f"Parsed {stats['parsed']} records, skipped {stats['skipped']}")
    logger.info(f"  File hashes: {stats['file_hashes']['parsed']}")
    logger.info(f"  Domains: {stats['domains']['parsed']}")
    logger.info(f"  IPs: {stats['ips']['parsed']}")
    
    if dry_run:
        logger.info("DRY RUN - skipping database operations")
        # Show sample records
        for category, records in [("File Hash", file_hash_records[:3]), 
                                   ("Domain", domain_records[:3]), 
                                   ("IP", ip_records[:3])]:
            for r in records:
                logger.info(f"  Sample {category}: {r.indicator} -> {r.classification} ({r.source_campaign})")
        return stats
    
    # Insert into TiDB
    if file_hash_records:
        inserted, skipped = importer.insert_file_hash(file_hash_records)
        stats["file_hashes"]["inserted"] = inserted
        stats["file_hashes"]["skipped"] = skipped
        logger.info(f"File hashes: inserted {inserted}, skipped {skipped}")
    
    if domain_records:
        inserted, skipped = importer.insert_domains(domain_records)
        stats["domains"]["inserted"] = inserted
        stats["domains"]["skipped"] = skipped
        logger.info(f"Domains: inserted {inserted}, skipped {skipped}")
    
    if ip_records:
        inserted, skipped = importer.insert_ips(ip_records)
        stats["ips"]["inserted"] = inserted
        stats["ips"]["skipped"] = skipped
        logger.info(f"IPs: inserted {inserted}, skipped {skipped}")
    
    return stats


def main():
    parser = argparse.ArgumentParser(description="Import TOKENS.bson into TiDB")
    parser.add_argument("--input", type=str, help="Local BSON file path")
    parser.add_argument("--gcs", type=str, help="GCS path (gs://bucket/path/to/TOKENS.bson)")
    parser.add_argument("--host", type=str, default="localhost", help="TiDB host (default: localhost)")
    parser.add_argument("--port", type=int, default=4000, help="TiDB port (default: 4000)")
    parser.add_argument("--user", type=str, default="root", help="TiDB user (default: root)")
    parser.add_argument("--password", type=str, default="", help="TiDB password")
    parser.add_argument("--database", type=str, default="threat_intel", help="TiDB database (default: threat_intel)")
    parser.add_argument("--dry-run", action="store_true", help="Parse only, don't insert")
    args = parser.parse_args()
    
    # Validate input
    if not args.input and not args.gcs:
        parser.error("Either --input or --gcs is required")
    
    # Setup logging
    logger = setup_logging("tokens_importer.log")
    logger.info("Starting TOKENS importer")
    
    # Get BSON file
    bson_file = args.input
    temp_file = None
    
    if args.gcs:
        temp_file = download_from_gcs(args.gcs, logger)
        bson_file = temp_file
    
    try:
        # Read BSON
        logger.info(f"Reading BSON file: {bson_file}")
        documents = read_bson_file(bson_file, logger)
        
        if args.dry_run:
            # Dry run - just parse and show stats
            stats = import_tokens(None, documents, logger, dry_run=True)
        else:
            # Connect to TiDB
            importer = TiDBImporter(
                host=args.host,
                port=args.port,
                user=args.user,
                password=args.password,
                database=args.database,
            )
            
            if not importer.test_connection():
                logger.error("Failed to connect to TiDB")
                sys.exit(1)
            
            logger.info(f"Connected to TiDB at {args.host}:{args.port}/{args.database}")
            
            # Show initial counts
            counts = importer.get_counts()
            logger.info(f"Current TOKENS records in TiDB:")
            for table, count in counts.items():
                logger.info(f"  {table}: {count}")
            
            # Import
            start_time = time.time()
            stats = import_tokens(importer, documents, logger)
            elapsed = time.time() - start_time
            
            # Show final counts
            final_counts = importer.get_counts()
            logger.info("=" * 50)
            logger.info("Import complete!")
            logger.info(f"Time: {elapsed:.1f} seconds")
            logger.info(f"Final TOKENS records in TiDB:")
            for table, count in final_counts.items():
                prev = counts.get(table, 0)
                logger.info(f"  {table}: {count} (+{count - prev})")
    
    finally:
        # Cleanup temp file
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)


if __name__ == "__main__":
    main()

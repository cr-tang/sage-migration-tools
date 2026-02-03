#!/usr/bin/env python3
"""
Sinkhole IP Importer - Import SINKHOLE_IDENTIFIERS and TOKENS IPs to TiDB ioc_ips table.

Data Sources:
1. SINKHOLE_IDENTIFIERS (MongoDB/BSON) - Known sinkhole IPs (~3,000 records)
2. TOKENS (from TiDB ioc_tokens) - IP entries with type='IPV4'

Usage:
    # Import from local BSON file
    python3 sinkhole_importer.py --sinkhole-file SINKHOLE_IDENTIFIERS.bson

    # Import from GCS
    python3 sinkhole_importer.py --sinkhole-file gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson

    # Also import TOKENS IPs from ioc_tokens table
    python3 sinkhole_importer.py --sinkhole-file SINKHOLE_IDENTIFIERS.bson --include-tokens

    # Dry run (no database writes)
    python3 sinkhole_importer.py --sinkhole-file SINKHOLE_IDENTIFIERS.bson --dry-run
"""

import argparse
import json
import logging
import socket
import struct
import sys
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Third-party imports
try:
    import bson
except ImportError:
    print("Error: bson package required. Install with: pip install pymongo")
    sys.exit(1)

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:
    print("Error: mysql-connector-python required. Install with: pip install mysql-connector-python")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class IocIpRecord:
    """Represents a record for ioc_ips table."""
    ip: str
    ip_version: int
    classification: str
    source: str
    sinkhole_entity: Optional[str] = None


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False


def get_ip_version(ip: str) -> int:
    """Return IP version (4 or 6) or 0 if invalid."""
    if is_valid_ipv4(ip):
        return 4
    elif is_valid_ipv6(ip):
        return 6
    return 0


def normalize_classification(classification: str) -> str:
    """Normalize classification to match TiDB ENUM values."""
    mapping = {
        'malware': 'MALWARE',
        'ransomware': 'RANSOMWARE',
        'hacktool': 'HACKTOOL',
        'maltool': 'MALTOOL',
        'unwanted': 'UNWANTED',
        'suspicious': 'SUSPICIOUS',
        'whitelist': 'WHITELIST',
        'blacklist': 'BLACKLIST',
        'sinkholed': 'SINKHOLED',
    }
    return mapping.get(classification.lower(), 'MALWARE')


def read_bson_file(file_path: str) -> List[Dict[str, Any]]:
    """Read BSON file and return list of documents."""
    records = []
    
    # Check if it's a GCS path
    if file_path.startswith('gs://'):
        logger.info(f"Downloading from GCS: {file_path}")
        try:
            from google.cloud import storage
            
            # Parse GCS path
            parts = file_path[5:].split('/', 1)
            bucket_name = parts[0]
            blob_name = parts[1] if len(parts) > 1 else ''
            
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(blob_name)
            
            # Download to memory
            data = blob.download_as_bytes()
            logger.info(f"Downloaded {len(data):,} bytes")
            
        except Exception as e:
            logger.error(f"Failed to download from GCS: {e}")
            raise
    else:
        # Read local file
        logger.info(f"Reading local file: {file_path}")
        with open(file_path, 'rb') as f:
            data = f.read()
    
    # Parse BSON documents
    offset = 0
    while offset < len(data):
        try:
            # Read document length (4 bytes, little-endian)
            if offset + 4 > len(data):
                break
            doc_len = struct.unpack('<I', data[offset:offset+4])[0]
            
            if doc_len < 5 or offset + doc_len > len(data):
                logger.warning(f"Invalid document length at offset {offset}: {doc_len}")
                break
            
            # Decode BSON document
            doc_data = data[offset:offset+doc_len]
            doc = bson.decode(doc_data)
            records.append(doc)
            
            offset += doc_len
            
        except Exception as e:
            logger.warning(f"Error parsing BSON at offset {offset}: {e}")
            break
    
    logger.info(f"Parsed {len(records):,} BSON documents")
    return records


def parse_sinkhole_records(records: List[Dict[str, Any]]) -> List[IocIpRecord]:
    """Parse SINKHOLE_IDENTIFIERS records to IocIpRecord list."""
    results = []
    skipped = 0
    
    for record in records:
        try:
            # Extract IP from _id.identifier
            _id = record.get('_id', {})
            if isinstance(_id, dict):
                ip = _id.get('identifier', '')
            else:
                ip = str(_id)
            
            if not ip:
                skipped += 1
                continue
            
            # Get IP version
            ip_version = get_ip_version(ip)
            if ip_version == 0:
                logger.debug(f"Invalid IP: {ip}")
                skipped += 1
                continue
            
            # Extract entity from value
            value = record.get('value', {})
            entity = value.get('entity', '') if isinstance(value, dict) else ''
            
            results.append(IocIpRecord(
                ip=ip,
                ip_version=ip_version,
                classification='SINKHOLED',
                source='SINKHOLE_IDENTIFIERS',
                sinkhole_entity=entity if entity else None
            ))
            
        except Exception as e:
            logger.warning(f"Error parsing sinkhole record: {e}")
            skipped += 1
    
    logger.info(f"Parsed {len(results):,} sinkhole IPs, skipped {skipped}")
    return results


def fetch_tokens_ips(conn) -> List[IocIpRecord]:
    """Fetch IP entries from ioc_tokens table."""
    results = []
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Query for IPv4 type indicators
        query = """
            SELECT indicator, classification, source_campaign
            FROM ioc_tokens
            WHERE indicator_type = 'IPV4'
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            ip = row['indicator']
            ip_version = get_ip_version(ip)
            
            if ip_version == 0:
                logger.debug(f"Invalid IP from TOKENS: {ip}")
                continue
            
            classification = row.get('classification', 'MALWARE')
            
            results.append(IocIpRecord(
                ip=ip,
                ip_version=ip_version,
                classification=classification,
                source='TOKENS',
                sinkhole_entity=None
            ))
        
        cursor.close()
        logger.info(f"Fetched {len(results):,} IP entries from ioc_tokens")
        
    except MySQLError as e:
        logger.error(f"Database error fetching TOKENS IPs: {e}")
    
    return results


def import_to_tidb(conn, records: List[IocIpRecord], dry_run: bool = False) -> Tuple[int, int]:
    """Import IocIpRecord list to TiDB ioc_ips table."""
    if not records:
        return 0, 0
    
    inserted = 0
    duplicates = 0
    
    cursor = conn.cursor()
    
    # Use INSERT IGNORE to handle duplicates
    insert_query = """
        INSERT IGNORE INTO ioc_ips 
        (ip, ip_version, classification, source, sinkhole_entity, created_at)
        VALUES (INET6_ATON(%s), %s, %s, %s, %s, %s)
    """
    
    batch_size = 1000
    now = datetime.now()
    
    for i in range(0, len(records), batch_size):
        batch = records[i:i+batch_size]
        
        values = [
            (r.ip, r.ip_version, r.classification, r.source, r.sinkhole_entity, now)
            for r in batch
        ]
        
        if dry_run:
            inserted += len(batch)
            logger.info(f"[DRY RUN] Would insert batch {i//batch_size + 1}: {len(batch)} records")
        else:
            try:
                cursor.executemany(insert_query, values)
                conn.commit()
                affected = cursor.rowcount
                inserted += affected
                duplicates += len(batch) - affected
                logger.info(f"Inserted batch {i//batch_size + 1}: {affected} new, {len(batch) - affected} duplicates")
            except MySQLError as e:
                logger.error(f"Error inserting batch: {e}")
                conn.rollback()
    
    cursor.close()
    return inserted, duplicates


def get_db_connection(host: str, port: int, user: str, password: str, database: str):
    """Create MySQL/TiDB connection."""
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            autocommit=False
        )
        logger.info(f"Connected to {host}:{port}/{database}")
        return conn
    except MySQLError as e:
        logger.error(f"Failed to connect to database: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description='Import SINKHOLE_IDENTIFIERS and TOKENS IPs to TiDB ioc_ips table',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Input options
    parser.add_argument('--sinkhole-file', required=True,
                        help='Path to SINKHOLE_IDENTIFIERS.bson (local or gs://)')
    parser.add_argument('--include-tokens', action='store_true',
                        help='Also import IP entries from ioc_tokens table')
    
    # Database options
    parser.add_argument('--host', default='localhost',
                        help='TiDB host (default: localhost)')
    parser.add_argument('--port', type=int, default=4000,
                        help='TiDB port (default: 4000)')
    parser.add_argument('--user', default='root',
                        help='TiDB user (default: root)')
    parser.add_argument('--password', default='',
                        help='TiDB password')
    parser.add_argument('--database', default='threat_intel',
                        help='Database name (default: threat_intel)')
    
    # Other options
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse data but do not write to database')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse sinkhole records
    logger.info("=== Sinkhole IP Importer ===")
    logger.info(f"Sinkhole file: {args.sinkhole_file}")
    logger.info(f"Include TOKENS: {args.include_tokens}")
    logger.info(f"Dry run: {args.dry_run}")
    
    # Read and parse SINKHOLE_IDENTIFIERS
    bson_records = read_bson_file(args.sinkhole_file)
    sinkhole_ips = parse_sinkhole_records(bson_records)
    
    # Connect to database
    conn = None
    if not args.dry_run or args.include_tokens:
        conn = get_db_connection(
            args.host, args.port, args.user, args.password, args.database
        )
    
    # Fetch TOKENS IPs if requested
    tokens_ips = []
    if args.include_tokens and conn:
        tokens_ips = fetch_tokens_ips(conn)
    
    # Combine all records
    all_records = sinkhole_ips + tokens_ips
    logger.info(f"Total records to import: {len(all_records):,}")
    
    # Import to TiDB
    if all_records:
        if args.dry_run:
            logger.info("[DRY RUN] Would import the following:")
            logger.info(f"  - Sinkhole IPs: {len(sinkhole_ips):,}")
            logger.info(f"  - TOKENS IPs: {len(tokens_ips):,}")
            inserted, duplicates = len(all_records), 0
        else:
            if not conn:
                conn = get_db_connection(
                    args.host, args.port, args.user, args.password, args.database
                )
            inserted, duplicates = import_to_tidb(conn, all_records, args.dry_run)
    else:
        inserted, duplicates = 0, 0
    
    # Cleanup
    if conn:
        conn.close()
    
    # Summary
    logger.info("=== Import Summary ===")
    logger.info(f"Sinkhole IPs processed: {len(sinkhole_ips):,}")
    logger.info(f"TOKENS IPs processed: {len(tokens_ips):,}")
    logger.info(f"Total inserted: {inserted:,}")
    logger.info(f"Duplicates skipped: {duplicates:,}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

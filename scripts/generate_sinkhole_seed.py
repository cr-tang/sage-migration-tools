#!/usr/bin/env python3
"""
Generate SQL seed file for SINKHOLE_IDENTIFIERS from BSON dump.

This creates a seed file that can be committed to Phoenix repo:
  Phoenix/migrations/mysql/seed/data/20260130000000_sinkhole_identifiers.sql

Usage:
    python3 generate_sinkhole_seed.py --input gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson
    python3 generate_sinkhole_seed.py --input SINKHOLE_IDENTIFIERS.bson --output sinkhole_seed.sql
"""

import argparse
import struct
import sys
from datetime import datetime
from typing import List, Tuple

try:
    import bson
except ImportError:
    print("Error: bson package required. Install with: pip install pymongo")
    sys.exit(1)


def read_bson_file(file_path: str) -> List[dict]:
    """Read BSON file and return list of documents."""
    # Check if it's a GCS path
    if file_path.startswith('gs://'):
        try:
            from google.cloud import storage
            parts = file_path[5:].split('/', 1)
            bucket_name = parts[0]
            blob_name = parts[1] if len(parts) > 1 else ''
            
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(blob_name)
            data = blob.download_as_bytes()
            print(f"Downloaded {len(data):,} bytes from GCS")
        except Exception as e:
            print(f"Error downloading from GCS: {e}")
            raise
    else:
        with open(file_path, 'rb') as f:
            data = f.read()
        print(f"Read {len(data):,} bytes from local file")
    
    # Parse BSON documents
    records = []
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            break
        doc_len = struct.unpack('<I', data[offset:offset+4])[0]
        if doc_len < 5 or offset + doc_len > len(data):
            break
        doc_data = data[offset:offset+doc_len]
        doc = bson.decode(doc_data)
        records.append(doc)
        offset += doc_len
    
    print(f"Parsed {len(records):,} BSON documents")
    return records


def is_valid_ip(s: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    import socket
    # Try IPv4
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except socket.error:
        pass
    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except socket.error:
        pass
    return False


def parse_sinkhole_records(records: List[dict]) -> List[Tuple[str, str]]:
    """Parse SINKHOLE_IDENTIFIERS records to (ip, entity) tuples.
    
    Note: SINKHOLE_IDENTIFIERS contains both IPs and domains.
    - Domains are used by Sage to match reverse domains and name servers
    - IPs are used to match resolved IP addresses
    
    We only extract valid IP addresses for ioc_ips table.
    """
    results = []
    skipped_domains = 0
    
    for record in records:
        try:
            _id = record.get('_id', {})
            identifier = _id.get('identifier', '') if isinstance(_id, dict) else str(_id)
            
            if not identifier:
                continue
            
            # Only keep valid IP addresses, skip domains
            if not is_valid_ip(identifier):
                skipped_domains += 1
                continue
            
            value = record.get('value', {})
            entity = value.get('entity', '') if isinstance(value, dict) else ''
            
            results.append((identifier, entity))
        except Exception as e:
            print(f"Warning: Error parsing record: {e}")
    
    print(f"Extracted {len(results)} IPs, skipped {skipped_domains} domains")
    return results


def escape_sql_string(s: str) -> str:
    """Escape string for SQL."""
    if not s:
        return 'NULL'
    # Escape single quotes
    escaped = s.replace("'", "''")
    return f"'{escaped}'"


def generate_sql(records: List[Tuple[str, str]], output_file: str):
    """Generate SQL seed file."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open(output_file, 'w') as f:
        f.write(f"""-- =============================================================================
-- Seed Data: Sinkhole IP Identifiers
-- Version: {timestamp}
-- Date: {date_str}
-- =============================================================================
-- Source: SAGE SINKHOLE_IDENTIFIERS collection
-- Generated from: gs://sage_prod_dump/r02/cybereason/SINKHOLE_IDENTIFIERS.bson
-- Total: {len(records)} sinkhole IPs
--
-- Change History:
--   {date_str} - Initial seed data for sinkhole detection
--
-- To regenerate from BSON:
--   python3 generate_sinkhole_seed.py --input SINKHOLE_IDENTIFIERS.bson

USE threat_intel;

-- Clear existing sinkhole data
DELETE FROM ioc_ips WHERE source = 'SINKHOLE_IDENTIFIERS';

INSERT INTO ioc_ips (ip, ip_version, classification, source, sinkhole_entity) VALUES
""")
        
        # Sort by IP for consistent output
        sorted_records = sorted(records, key=lambda x: x[0])
        
        values = []
        for ip, entity in sorted_records:
            # Determine IP version
            ip_version = 6 if ':' in ip else 4
            entity_sql = escape_sql_string(entity) if entity and entity != '?' else 'NULL'
            
            values.append(f"(INET6_ATON('{ip}'), {ip_version}, 'SINKHOLED', 'SINKHOLE_IDENTIFIERS', {entity_sql})")
        
        # Write values with proper formatting
        f.write(',\n'.join(values))
        f.write(';\n')
        
        f.write(f"""
-- Verify seed data
SELECT 'ioc_ips (sinkhole)' AS table_name, COUNT(*) AS count 
FROM ioc_ips 
WHERE source = 'SINKHOLE_IDENTIFIERS';
""")
    
    print(f"Generated SQL seed file: {output_file}")
    print(f"Total records: {len(records)}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate SQL seed file for SINKHOLE_IDENTIFIERS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--input', required=True,
                        help='Input BSON file path (local or gs://)')
    parser.add_argument('--output', default='sinkhole_identifiers_seed.sql',
                        help='Output SQL file path')
    
    args = parser.parse_args()
    
    # Read and parse BSON
    records = read_bson_file(args.input)
    sinkhole_data = parse_sinkhole_records(records)
    
    if not sinkhole_data:
        print("No valid sinkhole records found!")
        return 1
    
    # Generate SQL
    generate_sql(sinkhole_data, args.output)
    
    print(f"\nTo use this seed file:")
    print(f"1. Copy to Phoenix repo:")
    print(f"   cp {args.output} ~/work/Phoenix/migrations/mysql/seed/data/")
    print(f"2. Run migration:")
    print(f"   ./scripts/migrate-ti.sh seed")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

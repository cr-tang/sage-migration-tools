#!/usr/bin/env python3
"""
Generate SQL seed file for TOKENS data.

This script reads TOKENS.bson and generates INSERT statements for the ioc_tokens table,
including all indicator types: DOMAIN, MD5, SHA1, SHA256, and IPv4.

Usage:
    python3 generate_tokens_sql.py --input TOKENS.bson --output ./
"""

import argparse
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import List

try:
    import bson
except ImportError:
    print("Error: bson package required. Install with: pip install pymongo")
    sys.exit(1)


def escape_sql(s: str) -> str:
    """Escape string for SQL INSERT."""
    if s is None:
        return "NULL"
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"


def read_bson_file(filepath: str) -> List[dict]:
    """Read all documents from a BSON file."""
    records = []
    with open(filepath, 'rb') as f:
        data = f.read()
    
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            break
        doc_len = struct.unpack('<I', data[offset:offset+4])[0]
        if doc_len < 5 or offset + doc_len > len(data):
            break
        doc = bson.decode(data[offset:offset+doc_len])
        records.append(doc)
        offset += doc_len
    
    return records


def parse_tokens(records: List[dict]) -> List[dict]:
    """
    Parse TOKENS records for ioc_tokens table.
    
    All indicator types go to ioc_tokens: DOMAIN, MD5, SHA1, SHA256, IPv4
    (IPv4 is cached in TokensCache for fast in-memory lookups)
    
    Returns: list of token records
    """
    tokens_list = []
    
    # Mapping from TOKENS type to ioc_tokens indicator_type
    # Note: BSON types can be mixed case (e.g., 'Domain', 'DOMAIN')
    type_mapping = {
        'domain': 'DOMAIN',
        'md5': 'MD5',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'ipv4': 'IPV4',
        'url': 'URL',
    }
    
    # Mapping from maliciousType to classification
    # Must match database ENUM values
    classification_mapping = {
        'malware': 'MALWARE',
        'ransomware': 'RANSOMWARE',
        'pup': 'UNWANTED',       # PUP -> UNWANTED
        'adware': 'UNWANTED',    # Adware -> UNWANTED
        'hacking_tool': 'HACKTOOL',
        'hacktool': 'HACKTOOL',
        'phishing': 'MALWARE',   # Phishing -> MALWARE
        'suspicious': 'SUSPICIOUS',
    }
    
    for record in records:
        try:
            indicator = record.get('_id', '')
            if not indicator:
                continue
            
            value = record.get('value', {})
            if not isinstance(value, dict):
                continue
            
            token_type = value.get('type', '')
            malicious_type = value.get('maliciousType', 'malware')
            source = value.get('source', '')
            link = value.get('link')
            
            token_type_lower = token_type.lower() if token_type else ''
            
            if token_type_lower not in type_mapping:
                # Skip unknown types
                continue
            
            # Map classification
            classification = classification_mapping.get(
                malicious_type.lower() if malicious_type else 'malware',
                'MALWARE'
            )
            
            tokens_list.append({
                'indicator': indicator,
                'indicator_type': type_mapping[token_type_lower],
                'classification': classification,
                'source': source,
                'link': link,
            })
            
        except Exception as e:
            print(f"Warning: Error parsing record: {e}")
            continue
    
    return tokens_list


def generate_tokens_sql(tokens_list: List[dict], output_path: Path, timestamp: str):
    """Generate SQL file for ioc_tokens table."""
    if not tokens_list:
        print("No tokens to generate")
        return None
    
    filename = output_path / f"{timestamp}_tokens.sql"
    
    # Count by type for summary
    type_counts = {}
    for token in tokens_list:
        t = token['indicator_type']
        type_counts[t] = type_counts.get(t, 0) + 1
    
    with open(filename, 'w') as f:
        f.write("-- =============================================================================\n")
        f.write("-- Seed Data: TOKENS (Cybereason Curated Threat Intelligence)\n")
        f.write(f"-- Version: {timestamp}\n")
        f.write(f"-- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-- =============================================================================\n")
        f.write("-- Source: SAGE TOKENS collection\n")
        f.write(f"-- Total: {len(tokens_list)} indicators\n")
        f.write("--\n")
        f.write("-- Breakdown by type:\n")
        for t, count in sorted(type_counts.items()):
            f.write(f"--   {t}: {count}\n")
        f.write("--\n")
        f.write("-- Note: IPv4 entries are loaded into TokensCache for fast in-memory lookups.\n")
        f.write("--       Other IP sources (VT, sinkhole) go to ioc_ips table separately.\n")
        f.write("--\n")
        f.write("-- To regenerate from BSON:\n")
        f.write("--   python3 generate_tokens_sql.py --input TOKENS.bson --output ./\n")
        f.write("\n")
        f.write("USE threat_intel;\n\n")
        f.write("-- Clear existing curated IOC data\n")
        f.write("DELETE FROM cr_curated_ioc WHERE 1=1;\n\n")
        f.write("-- Insert curated IOC data (all types: DOMAIN, MD5, SHA1, SHA256, IPV4)\n")
        f.write("INSERT INTO cr_curated_ioc (indicator, indicator_type, classification, source, link)\n")
        f.write("VALUES\n")
        
        for i, token in enumerate(tokens_list):
            indicator = escape_sql(token['indicator'])
            indicator_type = escape_sql(token['indicator_type'])
            classification = escape_sql(token['classification'])
            source = escape_sql(token['source']) if token['source'] else "NULL"
            link = escape_sql(token['link']) if token['link'] else "NULL"
            
            comma = "," if i < len(tokens_list) - 1 else ";"
            f.write(f"  ({indicator}, {indicator_type}, {classification}, {source}, {link}){comma}\n")
    
    print(f"Generated: {filename}")
    print(f"  Total: {len(tokens_list)} records")
    for t, count in sorted(type_counts.items()):
        print(f"    {t}: {count}")
    
    return filename


def main():
    parser = argparse.ArgumentParser(description='Generate SQL seed file for TOKENS data')
    parser.add_argument('--input', '-i', required=True, help='Path to TOKENS.bson file')
    parser.add_argument('--output', '-o', required=True, help='Output directory for SQL file')
    parser.add_argument('--timestamp', '-t', help='Timestamp for filename (default: current time)')
    args = parser.parse_args()
    
    input_path = Path(args.input)
    output_path = Path(args.output)
    
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = args.timestamp or datetime.now().strftime('%Y%m%d%H%M%S')
    
    print(f"Reading BSON file: {input_path}")
    records = read_bson_file(str(input_path))
    print(f"Total records: {len(records)}")
    
    print("Parsing tokens...")
    tokens_list = parse_tokens(records)
    
    generate_tokens_sql(tokens_list, output_path, timestamp)
    
    print("\nDone!")


if __name__ == '__main__':
    main()

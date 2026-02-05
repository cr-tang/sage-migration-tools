#!/usr/bin/env python3
"""
Domain Importer - Import processed domain_classification NDJSON.gz into ioc_domains table.

Usage:
    python3 domain_importer.py --input domain_classification_all.ndjson.gz
    python3 domain_importer.py --input domain_classification_all.ndjson.gz --host localhost --password phoenix123
"""
import gzip
import json
import sys
import argparse
import logging
from typing import Optional, List, Tuple

try:
    import pymysql
except ImportError:
    print("Error: pymysql not installed. Run: pip install pymysql")
    sys.exit(1)


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


def import_domains(
    input_file: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    batch_size: int,
    logger: logging.Logger,
) -> Tuple[int, int, int]:
    """
    Import domains from NDJSON.gz file into ioc_domains table.
    Returns: (total, inserted, duplicates)
    """
    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        autocommit=False,
    )
    cursor = conn.cursor()
    
    INSERT_SQL = """
        INSERT IGNORE INTO ioc_domains (domain, classification, source)
        VALUES (%s, %s, %s)
    """
    
    total = 0
    inserted = 0
    batch = []
    
    logger.info(f"Opening {input_file}...")
    
    with gzip.open(input_file, 'rt') as f:
        for line in f:
            total += 1
            rec = json.loads(line.strip())
            
            domain = rec.get('domain', '').lower()[:253]  # Max DNS length
            classification = rec.get('classification', 'MALWARE').upper()
            source = rec.get('source', 'VIRUS_TOTAL').upper()
            
            if not domain:
                continue
            
            batch.append((domain, classification, source))
            
            if len(batch) >= batch_size:
                cursor.executemany(INSERT_SQL, batch)
                inserted += cursor.rowcount
                conn.commit()
                batch = []
                
                if total % 10000 == 0:
                    logger.info(f"Progress: {total:,} records processed, {inserted:,} inserted")
        
        # Final batch
        if batch:
            cursor.executemany(INSERT_SQL, batch)
            inserted += cursor.rowcount
            conn.commit()
    
    cursor.close()
    conn.close()
    
    duplicates = total - inserted
    return total, inserted, duplicates


def main():
    parser = argparse.ArgumentParser(
        description='Import domain_classification NDJSON.gz into TiDB/MySQL ioc_domains table'
    )
    parser.add_argument('--input', required=True, help='Input NDJSON.gz file')
    parser.add_argument('--host', default='localhost', help='Database host')
    parser.add_argument('--port', type=int, default=3306, help='Database port')
    parser.add_argument('--user', default='root', help='Database user')
    parser.add_argument('--password', default='', help='Database password')
    parser.add_argument('--database', default='threat_intel', help='Database name')
    parser.add_argument('--batch-size', type=int, default=1000, help='Batch size for inserts')
    parser.add_argument('--log-file', help='Log file path')
    
    args = parser.parse_args()
    logger = setup_logging(args.log_file)
    
    logger.info("=" * 60)
    logger.info("Domain Importer")
    logger.info("=" * 60)
    logger.info(f"Input: {args.input}")
    logger.info(f"Database: {args.host}:{args.port}/{args.database}")
    
    total, inserted, duplicates = import_domains(
        input_file=args.input,
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
        batch_size=args.batch_size,
        logger=logger,
    )
    
    logger.info("=" * 60)
    logger.info("Import Complete")
    logger.info(f"Total records: {total:,}")
    logger.info(f"Inserted: {inserted:,}")
    logger.info(f"Duplicates/Skipped: {duplicates:,}")
    logger.info("=" * 60)
    
    # Verify
    conn = pymysql.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
    )
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ioc_domains")
    count = cursor.fetchone()[0]
    logger.info(f"Domains in database: {count:,}")
    
    cursor.execute("SELECT classification, COUNT(*) FROM ioc_domains GROUP BY classification ORDER BY COUNT(*) DESC")
    logger.info("Classification breakdown:")
    for row in cursor.fetchall():
        logger.info(f"  {row[0]}: {row[1]:,}")
    
    cursor.close()
    conn.close()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

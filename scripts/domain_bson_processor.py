#!/usr/bin/env python3
"""
Domain BSON Processor - Extract domain reputation from domain_classification BSON dumps.

Processes MongoDB BSON dumps from GCS, extracts domain classification records,
and outputs compressed NDJSON files suitable for TiDB import.

Features:
- Parallel chunked download from GCS
- Checkpoint/resume support for fault tolerance
- Filters out unknown/indifferent classifications
- Keeps domains with malicious URLs (positives > 0)

Filtering:
- SKIP: response contains "maliciousClassification=unknown" (VT has no data)
- SKIP: response contains "maliciousClassification=indifferent" (neutral)
- KEEP: malicious classification (malware, whitelist, etc.)
- KEEP: detectedUrls with positives > 0

Output: domain_classification_{shard}.ndjson.gz

Usage:
    python3 domain_bson_processor.py --shard r01
    python3 domain_bson_processor.py --shard r01 --resume
    python3 domain_bson_processor.py  # Process all 6 shards
"""
import struct
import gzip
import json
import os
import sys
import argparse
import signal
import threading
import time
import queue
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple

# Configure logging
def setup_logging(log_file: Optional[str] = None, name: str = __name__):
    """Setup logging to both console and file. Returns a logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(console)
    
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)
    
    return logger


# Third-party imports
try:
    import bson
except ImportError:
    print("Error: bson package required. Install with: pip install pymongo")
    sys.exit(1)

try:
    import orjson
except ImportError:
    print("Error: orjson package required. Install with: pip install orjson")
    sys.exit(1)

try:
    from google.cloud import storage
except ImportError:
    print("Error: google-cloud-storage required. Install with: pip install google-cloud-storage")
    sys.exit(1)


# ----------------------------
# Data structures
# ----------------------------
@dataclass
class RangeInfo:
    worker_id: int
    start: int
    end: int
    is_first: bool
    is_last: bool
    logical_end: int


@dataclass
class ProcessingStats:
    total_docs: int = 0
    valid_docs: int = 0
    filtered_unknown: int = 0
    filtered_indifferent: int = 0
    decode_errors: int = 0
    bytes_read: int = 0
    # Classification breakdown
    malware_count: int = 0
    av_detected_count: int = 0
    whitelist_count: int = 0
    other_count: int = 0


@dataclass
class Checkpoint:
    completed_ranges: List[Tuple[int, int]] = field(default_factory=list)
    stats: ProcessingStats = field(default_factory=ProcessingStats)


# ----------------------------
# Classification extraction
# ----------------------------
CLASSIFICATIONS_TO_SKIP = {'unknown', 'indifferent'}

def extract_classification(response: str) -> Optional[str]:
    """Extract classification from response string like 'maliciousClassification=malware'."""
    if not response:
        return None
    
    for part in response.split(';'):
        if 'maliciousClassification=' in part:
            # Extract value after '='
            value = part.split('=', 1)[-1].strip().lower()
            return value
    return None


def has_detected_urls_with_positives(value: Dict[str, Any]) -> bool:
    """Check if domain has detectedUrls with positives > 0."""
    detected_urls = value.get('detectedUrls', [])
    if not detected_urls:
        return False
    
    for url_entry in detected_urls:
        positives = url_entry.get('positives', 0)
        if isinstance(positives, dict):
            positives = positives.get('$numberInt', 0)
        if int(positives) > 0:
            return True
    return False


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
        'unresolved': 'UNRESOLVED',
        'av_detected': 'AV_DETECTED',  # indifferent domains with positive detections
        'indifferent': 'INDIFFERENT',
    }
    return mapping.get(classification.lower(), 'MALWARE')


def filter_and_extract(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Filter and extract relevant fields from a domain_classification document.
    Returns None if document should be skipped.
    """
    response = doc.get('response', '')
    value = doc.get('value', {})
    
    # Extract classification from response
    classification = extract_classification(response)
    
    # Skip unknown classifications
    if classification == 'unknown':
        return None
    
    # Skip indifferent unless it has detected URLs
    if classification == 'indifferent':
        if not has_detected_urls_with_positives(value):
            return None
        # If has positives, upgrade to AV_DETECTED
        classification = 'av_detected'
    
    # Get domain from _id
    domain = doc.get('_id', '')
    if not domain:
        return None
    
    # Normalize and validate domain length (max 253 per DNS RFC)
    domain = domain.lower().strip()
    if len(domain) > 253:
        return None
    
    # Build output record
    result = {
        'domain': domain,
        'classification': normalize_classification(classification),
        'source': 'VIRUS_TOTAL',
    }
    
    # Optionally include detected URLs summary
    detected_urls = value.get('detectedUrls', [])
    if detected_urls:
        max_positives = 0
        for url_entry in detected_urls:
            positives = url_entry.get('positives', 0)
            if isinstance(positives, dict):
                positives = int(positives.get('$numberInt', 0))
            max_positives = max(max_positives, int(positives))
        if max_positives > 0:
            result['max_positives'] = max_positives
    
    return result


def to_ndjson_line(record: Dict[str, Any]) -> bytes:
    """Convert record to NDJSON line (bytes)."""
    return orjson.dumps(record) + b'\n'


# ----------------------------
# GCS utilities
# ----------------------------
def get_gcs_file_size(bucket_name: str, blob_name: str) -> int:
    """Get the size of a GCS blob in bytes."""
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    blob.reload()
    return blob.size


def download_gcs_range(bucket_name: str, blob_name: str, start: int, end: int) -> bytes:
    """Download a byte range from GCS."""
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    return blob.download_as_bytes(start=start, end=end-1)  # GCS range is inclusive


# ----------------------------
# BSON processing
# ----------------------------
class DomainProcessor:
    """Process domain_classification BSON data with filtering."""
    
    def __init__(self, logger):
        self.logger = logger
        self.stats = ProcessingStats()
        self._lock = threading.Lock()  # Thread-safe stats updates
    
    def process_chunk(self, data: bytes, offset: int = 0) -> Tuple[List[bytes], int]:
        """
        Process a chunk of BSON data and return (output_lines, bytes_consumed).
        """
        output_lines = []
        pos = 0
        
        while pos + 4 <= len(data):
            # Read document length
            doc_len = struct.unpack('<I', data[pos:pos+4])[0]
            
            if doc_len < 5:
                self.logger.warning(f"Invalid doc length {doc_len} at pos {pos}")
                break
            
            if pos + doc_len > len(data):
                # Incomplete document, return what we have
                break
            
            # Decode document
            try:
                doc_data = data[pos:pos+doc_len]
                doc = bson.decode(doc_data)
                
                # Filter and extract
                result = filter_and_extract(doc)
                
                # Thread-safe stats update
                with self._lock:
                    self.stats.total_docs += 1
                    if result is None:
                        # Track why we filtered
                        response = doc.get('response', '')
                        classification = extract_classification(response)
                        if classification == 'unknown':
                            self.stats.filtered_unknown += 1
                        elif classification == 'indifferent':
                            self.stats.filtered_indifferent += 1
                    else:
                        output_lines.append(to_ndjson_line(result))
                        self.stats.valid_docs += 1
                
            except Exception as e:
                with self._lock:
                    self.stats.decode_errors += 1
                self.logger.debug(f"Decode error at pos {pos}: {e}")
            
            pos += doc_len
        
        self.stats.bytes_read += pos
        return output_lines, pos


# ----------------------------
# Main processor
# ----------------------------
class ParallelDomainProcessor:
    """Parallel processor for domain_classification BSON files."""
    
    def __init__(
        self,
        input_file: str,
        output_file: str,
        log_file: Optional[str] = None,
        num_workers: int = 20,
        chunk_size: int = 256 * 1024 * 1024,  # 256MB chunks
    ):
        self.input_file = input_file
        self.output_file = output_file
        self.num_workers = num_workers
        self.chunk_size = chunk_size
        self.checkpoint_file = output_file + '.checkpoint'
        
        self.logger = setup_logging(log_file, 'domain_processor')
        self.processor = DomainProcessor(self.logger)
        
        self.output_queue = queue.Queue(maxsize=100)
        self.shutdown_flag = threading.Event()
        self.bytes_downloaded = 0
        self.bytes_written = 0
        self.start_time = None
        
        # Parse GCS path
        if input_file.startswith('gs://'):
            parts = input_file[5:].split('/', 1)
            self.bucket_name = parts[0]
            self.blob_name = parts[1] if len(parts) > 1 else ''
            self.is_gcs = True
        else:
            self.is_gcs = False
    
    def get_file_size(self) -> int:
        """Get total file size."""
        if self.is_gcs:
            return get_gcs_file_size(self.bucket_name, self.blob_name)
        else:
            return os.path.getsize(self.input_file)
    
    def load_checkpoint(self) -> Optional[Checkpoint]:
        """Load checkpoint from file."""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    data = json.load(f)
                return Checkpoint(
                    completed_ranges=[(r[0], r[1]) for r in data.get('completed_ranges', [])],
                    stats=ProcessingStats(**data.get('stats', {}))
                )
            except Exception as e:
                self.logger.warning(f"Failed to load checkpoint: {e}")
        return None
    
    def save_checkpoint(self, checkpoint: Checkpoint):
        """Save checkpoint to file."""
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump({
                    'completed_ranges': checkpoint.completed_ranges,
                    'stats': asdict(checkpoint.stats)
                }, f)
        except Exception as e:
            self.logger.warning(f"Failed to save checkpoint: {e}")
    
    def writer_thread(self, output_file: str):
        """Background thread to write output."""
        # Use 'wb' mode to create fresh file each run
        with gzip.open(output_file, 'wb') as f:
            batch = []
            batch_size = 0
            FLUSH_THRESHOLD = 1024 * 1024  # 1MB
            
            while not self.shutdown_flag.is_set():
                try:
                    data = self.output_queue.get(timeout=1.0)
                    if data is None:
                        # Flush remaining data
                        if batch:
                            f.write(b''.join(batch))
                        break
                    batch.append(data)
                    batch_size += len(data)
                    self.bytes_written += len(data)
                    
                    # Batch write for efficiency
                    if batch_size >= FLUSH_THRESHOLD:
                        f.write(b''.join(batch))
                        f.flush()
                        batch = []
                        batch_size = 0
                except queue.Empty:
                    # Flush any pending data
                    if batch:
                        f.write(b''.join(batch))
                        f.flush()
                        batch = []
                        batch_size = 0
                    continue
    
    def process_range(self, range_info: RangeInfo) -> Tuple[int, int, List[bytes]]:
        """Process a byte range and return (start, end, output_lines)."""
        # Download data
        if self.is_gcs:
            data = download_gcs_range(self.bucket_name, self.blob_name, range_info.start, range_info.end)
        else:
            with open(self.input_file, 'rb') as f:
                f.seek(range_info.start)
                data = f.read(range_info.end - range_info.start)
        
        self.bytes_downloaded += len(data)
        
        # Process BSON documents
        output_lines, _ = self.processor.process_chunk(data, range_info.start)
        
        return range_info.start, range_info.end, output_lines
    
    def run(self, resume: bool = False):
        """Run the parallel processing."""
        self.start_time = time.time()
        
        # Get file size
        total_size = self.get_file_size()
        self.logger.info(f"Input file: {self.input_file}")
        self.logger.info(f"Total size: {total_size / (1024**3):.2f} GB")
        self.logger.info(f"Workers: {self.num_workers}")
        
        # Load checkpoint if resuming
        checkpoint = None
        if resume:
            checkpoint = self.load_checkpoint()
            if checkpoint:
                self.logger.info(f"Resuming from checkpoint: {len(checkpoint.completed_ranges)} ranges completed")
                self.processor.stats = checkpoint.stats
        
        # Calculate ranges
        ranges = []
        completed_set = set(checkpoint.completed_ranges) if checkpoint else set()
        
        pos = 0
        worker_id = 0
        while pos < total_size:
            end = min(pos + self.chunk_size, total_size)
            
            if (pos, end) not in completed_set:
                ranges.append(RangeInfo(
                    worker_id=worker_id,
                    start=pos,
                    end=end,
                    is_first=(pos == 0),
                    is_last=(end == total_size),
                    logical_end=end
                ))
            
            pos = end
            worker_id += 1
        
        self.logger.info(f"Ranges to process: {len(ranges)}")
        
        if not ranges:
            self.logger.info("All ranges already completed!")
            return
        
        # Start writer thread
        writer = threading.Thread(target=self.writer_thread, args=(self.output_file,))
        writer.start()
        
        # Process ranges in parallel
        completed_ranges = list(completed_set)
        
        try:
            with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
                futures = {executor.submit(self.process_range, r): r for r in ranges}
                
                for future in as_completed(futures):
                    range_info = futures[future]
                    
                    try:
                        start, end, output_lines = future.result()
                        
                        # Queue output for writing
                        for line in output_lines:
                            self.output_queue.put(line)
                        
                        completed_ranges.append((start, end))
                        
                        # Save checkpoint periodically
                        if len(completed_ranges) % 10 == 0:
                            self.save_checkpoint(Checkpoint(
                                completed_ranges=completed_ranges,
                                stats=self.processor.stats
                            ))
                        
                        # Log progress
                        elapsed = time.time() - self.start_time
                        progress = self.bytes_downloaded / total_size * 100
                        rate = self.bytes_downloaded / (1024**2) / elapsed if elapsed > 0 else 0
                        
                        self.logger.info(
                            f"Progress: {progress:.1f}% | "
                            f"Valid: {self.processor.stats.valid_docs:,}/{self.processor.stats.total_docs:,} | "
                            f"Unknown: {self.processor.stats.filtered_unknown:,} | "
                            f"Indifferent: {self.processor.stats.filtered_indifferent:,} | "
                            f"Rate: {rate:.1f} MB/s"
                        )
                        
                    except Exception as e:
                        self.logger.error(f"Error processing range {range_info.start}-{range_info.end}: {e}")
        
        finally:
            # Signal writer to stop
            self.output_queue.put(None)
            writer.join()
            
            # Final checkpoint
            self.save_checkpoint(Checkpoint(
                completed_ranges=completed_ranges,
                stats=self.processor.stats
            ))
        
        # Summary
        elapsed = time.time() - self.start_time
        stats = self.processor.stats
        
        self.logger.info("=" * 60)
        self.logger.info("Processing Complete")
        self.logger.info(f"Total documents: {stats.total_docs:,}")
        self.logger.info(f"Valid documents: {stats.valid_docs:,}")
        self.logger.info(f"Filtered unknown: {stats.filtered_unknown:,}")
        self.logger.info(f"Filtered indifferent: {stats.filtered_indifferent:,}")
        self.logger.info(f"Decode errors: {stats.decode_errors:,}")
        self.logger.info(f"Extraction rate: {stats.valid_docs / stats.total_docs * 100:.4f}%" if stats.total_docs > 0 else "N/A")
        self.logger.info(f"Output file: {self.output_file}")
        self.logger.info(f"Output size: {self.bytes_written / (1024**2):.2f} MB")
        self.logger.info(f"Elapsed time: {elapsed / 60:.1f} minutes")


def main():
    parser = argparse.ArgumentParser(
        description='Process domain_classification BSON dumps',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--shard', choices=['r01', 'r02', 'r03', 'r04', 'r05', 'r06'],
                        help='Shard to process (e.g., r01)')
    parser.add_argument('--input-file',
                        help='Input BSON file path (local or gs://)')
    parser.add_argument('--output-file',
                        help='Output NDJSON.gz file path')
    parser.add_argument('--log-file',
                        help='Log file path')
    parser.add_argument('--workers', type=int, default=20,
                        help='Number of parallel workers (default: 20)')
    parser.add_argument('--chunk-size', type=int, default=256,
                        help='Chunk size in MB (default: 256)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume from checkpoint')
    parser.add_argument('--all', action='store_true',
                        help='Process all shards (r01-r06)')
    
    args = parser.parse_args()
    
    # Determine which shards to process
    ALL_SHARDS = ['r01', 'r02', 'r03', 'r04', 'r05', 'r06']
    
    if args.all:
        shards_to_process = ALL_SHARDS
    elif args.shard:
        shards_to_process = [args.shard]
    elif args.input_file:
        shards_to_process = None  # Use custom input file
    else:
        # Default: process all shards
        shards_to_process = ALL_SHARDS
        print(f"No shard specified, processing all shards: {shards_to_process}")
    
    # Process custom input file
    if shards_to_process is None:
        input_file = args.input_file
        output_file = args.output_file or 'domain_classification.ndjson.gz'
        log_file = args.log_file
        
        processor = ParallelDomainProcessor(
            input_file=input_file,
            output_file=output_file,
            log_file=log_file,
            num_workers=args.workers,
            chunk_size=args.chunk_size * 1024 * 1024
        )
        processor.run(resume=args.resume)
        return 0
    
    # Process shards
    for shard in shards_to_process:
        print(f"\n{'='*60}")
        print(f"Processing shard: {shard}")
        print(f"{'='*60}\n")
        
        # GCS path: gs://sage_prod_dump/cr-mongo-shard-{shard}.cybereason.net/cybereason/domain_classification.bson
        input_file = f'gs://sage_prod_dump/cr-mongo-shard-{shard}.cybereason.net/cybereason/domain_classification.bson'
        output_file = f'domain_classification_{shard}.ndjson.gz'
        log_file = f'domain_processor_{shard}.log'
        
        # Override with explicit args (only for single shard)
        if len(shards_to_process) == 1:
            if args.output_file:
                output_file = args.output_file
            if args.log_file:
                log_file = args.log_file
        
        processor = ParallelDomainProcessor(
            input_file=input_file,
            output_file=output_file,
            log_file=log_file,
            num_workers=args.workers,
            chunk_size=args.chunk_size * 1024 * 1024
        )
        
        processor.run(resume=args.resume)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

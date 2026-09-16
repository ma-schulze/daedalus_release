#!/usr/bin/env python3
"""
Report Merger Module

Merges multiple symbolic execution reports (from parallel runs) into a single
consolidated report. This is useful when analyzing a TA with different initial
commands in parallel.

Usage:
    python reporting/merge_reports.py <binary_name> [--ta-report-dir <path>] [--output <output_name>]
    python reporting/merge_reports.py --pattern "report_myapp*.json" [--output merged]
    
Examples:
    # Merge all runs for one TA folder
    python reporting/merge_reports.py my_ta.elf --ta-report-dir A/B/my_ta.elf

    # Merge every reports/<path>/my_ta.elf folder separately
    python reporting/merge_reports.py my_ta.elf
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict

# Add project root to path for standalone execution
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logging_config import setup_logging, get_logger
from jinja2 import Environment, FileSystemLoader

logger = get_logger(__name__)


def discover_ta_report_dirs(reports_dir: Path, binary_name: str) -> List[Path]:
    """
    Find all TA report directories that contain JSON reports for a binary.

    Each directory corresponds to one TA instance (same name, different paths
    are kept separate).
    """
    pattern = f"report_{binary_name}_*.json"
    dirs = {path.parent for path in reports_dir.rglob(pattern)}
    return sorted(dirs)


def resolve_ta_report_dir(ta_report_dir: Path, reports_dir: Path) -> Path:
    """Resolve a TA report directory relative to the reports root when needed."""
    if ta_report_dir.is_absolute():
        return ta_report_dir.resolve()
    return (reports_dir / ta_report_dir).resolve()


def find_report_files(binary_name: str, ta_report_dir: Path) -> List[Path]:
    """
    Find all JSON report files for a given binary in one TA report directory.

    Only searches the given directory (not the whole reports tree), so TAs that
    share a basename but live under different paths stay separate. Handles both
    old and new filename formats:
    - Old: report_binary_YYYYMMDD_HHMMSS.json
    - New: report_binary_run_id_YYYYMMDD_HHMMSS_ffffff.json

    Args:
        binary_name: Name of the binary (e.g., "my_ta.elf" or "02662e8e-e126-11e5-b86d9a79f06e9478.ta")
        ta_report_dir: Directory containing that TA's reports (e.g. reports/A/B/some_ta.ta/)

    Returns:
        List of paths to JSON report files, sorted by modification time
    """
    pattern = f"report_{binary_name}_*.json"
    files = list(ta_report_dir.glob(pattern))
    
    # Sort by the timestamp in the filename for consistency
    # Extract timestamp from filename and sort by it
    def extract_timestamp(path: Path) -> datetime:
        name = path.stem  # filename without extension
        # Try to extract timestamp - could be YYYYMMDD_HHMMSS or YYYYMMDD_HHMMSS_ffffff
        import re
        # Match timestamp at the end: _YYYYMMDD_HHMMSS_ffffff or _YYYYMMDD_HHMMSS
        match = re.search(r'_(\d{8}_\d{6}(?:_\d+)?)$', name)
        if match:
            ts_str = match.group(1)
            try:
                # Try with microseconds first
                return datetime.strptime(ts_str, "%Y%m%d_%H%M%S_%f")
            except ValueError:
                try:
                    return datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                except ValueError:
                    pass
        # Fallback to file modification time
        return datetime.fromtimestamp(path.stat().st_mtime)
    
    files = sorted(files, key=extract_timestamp)
    return files


def find_report_files_by_pattern(pattern: str, reports_dir: Path) -> List[Path]:
    """
    Find JSON report files matching a glob pattern.
    
    Args:
        pattern: Glob pattern (e.g., "report_*.json")
        reports_dir: Directory containing reports
        
    Returns:
        List of paths to JSON report files, sorted by timestamp
    """
    import re
    files = list(reports_dir.glob(pattern))
    
    def extract_timestamp(path: Path) -> datetime:
        name = path.stem
        match = re.search(r'_(\d{8}_\d{6}(?:_\d+)?)$', name)
        if match:
            ts_str = match.group(1)
            try:
                return datetime.strptime(ts_str, "%Y%m%d_%H%M%S_%f")
            except ValueError:
                try:
                    return datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                except ValueError:
                    pass
        return datetime.fromtimestamp(path.stat().st_mtime)
    
    files = sorted(files, key=extract_timestamp)
    return files


def load_report_data(json_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load report data from a JSON file.
    
    Args:
        json_path: Path to the JSON report file
        
    Returns:
        Report data dictionary or None if loading failed
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {json_path}: {e}")
        return None


def merge_stats(all_stats: List[Dict[str, int]], all_visited_blocks: List[List[int]]) -> Dict[str, Any]:
    """
    Merge statistics from multiple reports.
    
    For most stats, we sum them. For max_depth, we take the maximum.
    Block coverage is computed from the union of all visited blocks.
    """
    merged = {
        'states_explored': 0,
        'targets_found': 0,
        'bugs_found': 0,
        'max_depth': 0,
        'functions_covered': 0,
        'unique_addresses': 0,
        'blocks_hit': 0,
        'blocks_reachable': 0,
        'block_coverage_pct': 0.0
    }
    
    # Merge basic stats
    for stats in all_stats:
        merged['states_explored'] += stats.get('states_explored', 0)
        merged['targets_found'] += stats.get('targets_found', 0)
        merged['max_depth'] = max(merged['max_depth'], stats.get('max_depth', 0))
    
    # Use the first non-zero blocks_reachable (should be same for all runs of same binary)
    for stats in all_stats:
        if stats.get('blocks_reachable', 0) > 0:
            merged['blocks_reachable'] = stats.get('blocks_reachable', 0)
            break
    
    # Compute unique blocks hit across all runs
    all_blocks_set = set()
    for blocks in all_visited_blocks:
        if blocks:
            all_blocks_set.update(blocks)

    if all_blocks_set:
        merged['blocks_hit'] = len(all_blocks_set)
    else:
        # Fallback for reports that don't include visited_blocks (or include an empty list).
        # We can't compute the union accurately without per-block data, but we can at least
        # avoid reporting 0 when individual runs reported coverage.
        merged['blocks_hit'] = max((s.get('blocks_hit', 0) for s in all_stats), default=0)
    
    # Calculate coverage percentage
    if merged['blocks_reachable'] > 0:
        merged['block_coverage_pct'] = round((merged['blocks_hit'] / merged['blocks_reachable']) * 100, 1)
    
    return merged, list(all_blocks_set)


def merge_bugs(all_bugs: List[List[Dict]]) -> List[Dict]:
    """
    Merge bugs from multiple reports, deduplicating by address and type.
    
    Bugs are considered duplicates if they have the same type and address.
    For duplicates, we keep the one with higher confidence.
    """
    seen_bugs = {}  # Key: (type, address) -> bug dict
    
    for bug_list in all_bugs:
        for bug in bug_list:
            key = (bug.get('type', ''), bug.get('address', ''))
            
            if key in seen_bugs:
                # Keep the one with higher confidence
                existing_confidence = seen_bugs[key].get('confidence', 0)
                new_confidence = bug.get('confidence', 0)
                if new_confidence > existing_confidence:
                    seen_bugs[key] = bug
            else:
                seen_bugs[key] = bug
    
    # Sort by criticality, then confidence
    criticality_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    merged_bugs = sorted(
        seen_bugs.values(),
        key=lambda b: (
            criticality_order.get(b.get('criticality', 'WARNING'), 1),
            -b.get('confidence', 50)
        )
    )
    
    return merged_bugs


def _merge_stub_functions(all_stub_functions: List[List[Dict]]) -> List[Dict]:
    """Merge stub function lists from multiple reports, deduplicating by name."""
    seen: Dict[str, Dict] = {}
    for stub_list in all_stub_functions:
        for entry in stub_list:
            name = entry.get("name", "")
            if name and name not in seen:
                seen[name] = {"name": name, "address": entry.get("address", "")}
    return list(seen.values())


def merge_syscall_stats(all_syscalls: List[Dict[str, int]]) -> Dict[str, int]:
    """
    Merge syscall statistics by summing counts.
    """
    merged = defaultdict(int)
    
    for syscall_stats in all_syscalls:
        for syscall, count in syscall_stats.items():
            merged[syscall] += count
    
    return dict(merged)


def merge_function_coverage(all_coverage: List[List[Dict]]) -> List[Dict]:
    """
    Merge function coverage by combining hit counts for the same function.
    """
    function_map = {}
    
    for coverage_list in all_coverage:
        for func in coverage_list:
            name = func.get('name', '<unknown>')
            if name in function_map:
                function_map[name]['hit_count'] += func.get('hit_count', 0)
                # Merge addresses
                existing_addrs = set(function_map[name]['addresses'])
                new_addrs = set(func.get('addresses', []))
                function_map[name]['addresses'] = list(existing_addrs | new_addrs)
            else:
                function_map[name] = {
                    'name': name,
                    'hit_count': func.get('hit_count', 0),
                    'addresses': list(func.get('addresses', []))
                }
    
    # Sort by hit count descending, then by name
    merged_coverage = sorted(
        function_map.values(),
        key=lambda x: (-x['hit_count'], x['name'])
    )
    
    return merged_coverage


def merge_reports(report_files: List[Path]) -> Optional[Dict[str, Any]]:
    """
    Merge multiple report JSON files into a single report data structure.
    
    Args:
        report_files: List of paths to JSON report files
        
    Returns:
        Merged report data dictionary
    """
    if not report_files:
        logger.error("No report files provided")
        return None
    
    # Load all reports
    reports = []
    for f in report_files:
        data = load_report_data(f)
        if data:
            reports.append(data)
            logger.info(f"Loaded: {f.name}")
    
    if not reports:
        logger.error("No valid reports loaded")
        return None
    
    logger.info(f"Merging {len(reports)} reports...")
    
    # Use first report as base for metadata
    base = reports[0]
    
    # Collect all data for merging
    all_stats = [r.get('stats', {}) for r in reports]
    all_bugs = [r.get('bugs', []) for r in reports]
    all_stub_functions = [r.get('stub_functions', []) for r in reports]
    all_syscalls = [r.get('syscall_stats', {}) for r in reports]
    all_coverage = [r.get('function_coverage', []) for r in reports]
    all_visited_blocks = [r.get('visited_blocks', []) for r in reports]
    
    # Merge each section
    merged_stats, merged_visited_blocks = merge_stats(all_stats, all_visited_blocks)
    merged_stub_functions = _merge_stub_functions(all_stub_functions)
    merged_bugs = merge_bugs(all_bugs)
    merged_syscalls = merge_syscall_stats(all_syscalls)
    merged_coverage = merge_function_coverage(all_coverage)
    
    # Update stats with merged coverage info
    merged_stats['functions_covered'] = len([f for f in merged_coverage if f['name'] != '<unknown>'])
    merged_stats['unique_addresses'] = sum(len(f['addresses']) for f in merged_coverage)
    merged_stats['bugs_found'] = len(merged_bugs)
    
    # Collect run_ids from all reports
    run_ids = []
    for r in reports:
        run_id = r.get('run_id', '')
        if run_id and run_id not in run_ids:
            run_ids.append(run_id)
    
    # Build merged report
    merged = {
        'binary_name': base.get('binary_name', 'unknown'),
        'binary_path': base.get('binary_path', ''),
        'execution_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'start_addr': 'multiple',
        'target_addr': base.get('target_addr', ''),
        'mem_base': base.get('mem_base', 0),
        'run_id': 'merged',  # Mark as merged report
        'run_ids_merged': run_ids,  # List of all run_ids that were merged
        'stats': merged_stats,
        'bugs': merged_bugs,
        'stub_functions': merged_stub_functions,
        'syscall_stats': merged_syscalls,
        'function_coverage': merged_coverage,
        'visited_blocks': merged_visited_blocks,
        'merged_from': [f.name for f in report_files],
        'num_runs_merged': len(reports)
    }
    
    logger.info(f"Merged stats: {merged_stats['states_explored']} states, "
                f"{merged_stats['bugs_found']} bugs, "
                f"{merged_stats['functions_covered']} functions, "
                f"{merged_stats['blocks_hit']}/{merged_stats['blocks_reachable']} blocks ({merged_stats['block_coverage_pct']}%)")
    
    return merged


def generate_merged_report(merged_data: Dict[str, Any], output_name: str, reports_dir: Path) -> str:
    """
    Generate HTML report from merged data.
    
    Args:
        merged_data: Merged report data dictionary
        output_name: Base name for output files (without extension)
        reports_dir: Directory to write reports to
        
    Returns:
        Path to generated HTML file
    """
    current_dir = Path(__file__).parent
    
    # Generate timestamp for filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_filename = f"{output_name}_{timestamp}.html"
    json_filename = f"{output_name}_{timestamp}.json"
    
    html_path = reports_dir / html_filename
    json_path = reports_dir / json_filename
    
    # Save JSON data
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(merged_data, f, indent=2, default=str)
    logger.info(f"Saved JSON data: {json_path}")
    
    # Generate HTML using template
    env = Environment(
        loader=FileSystemLoader(str(current_dir)),
        autoescape=True
    )
    template = env.get_template('report_template.html')
    
    # Build display name including merged run_ids if available
    run_ids_merged = merged_data.get('run_ids_merged', [])
    if run_ids_merged:
        runs_info = f"merged from {merged_data['num_runs_merged']} runs: {', '.join(run_ids_merged)}"
    else:
        runs_info = f"merged from {merged_data['num_runs_merged']} runs"
    
    html_content = template.render(
        binary_name=f"{merged_data['binary_name']} ({runs_info})",
        binary_path=merged_data['binary_path'],
        execution_time=merged_data['execution_time'],
        start_addr=merged_data['start_addr'],
        target_addr=merged_data['target_addr'],
        stats=merged_data['stats'],
        bugs=merged_data['bugs'],
        stub_functions=merged_data.get('stub_functions', []),
        syscall_stats=merged_data['syscall_stats'],
        function_coverage=merged_data['function_coverage']
    )
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info("=" * 60)
    logger.info(f"Merged HTML report generated: {html_path}")
    logger.info("=" * 60)
    
    return str(html_path)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Merge multiple symbolic execution reports into one',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Merge all runs for one TA folder
  python reporting/merge_reports.py my_ta.elf --ta-report-dir A/B/my_ta.elf

  # Merge every reports/<path>/my_ta.elf folder separately
  python reporting/merge_reports.py my_ta.elf
  
  # Merge with custom output name
  python reporting/merge_reports.py my_ta.elf --ta-report-dir A/B/my_ta.elf --output my_ta_merged
  
  # Merge using a glob pattern
  python reporting/merge_reports.py --pattern "report_myapp*.json"
  
  # Specify reports directory
  python reporting/merge_reports.py my_ta.elf --reports-dir ./custom_reports --ta-report-dir path/to/my_ta.elf
        """
    )
    
    parser.add_argument(
        'binary_name',
        nargs='?',
        help='Name of the binary to merge reports for (e.g., my_ta.elf)'
    )
    
    parser.add_argument(
        '--pattern',
        help='Glob pattern to match report JSON files (e.g., "report_*.json")'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='merged_report',
        help='Output filename base (without extension, default: merged_report_<binary>)'
    )
    
    parser.add_argument(
        '--reports-dir',
        default=None,
        help='Root directory containing reports (default: ./reports)'
    )

    parser.add_argument(
        '--ta-report-dir',
        default=None,
        help=(
            'TA report directory to merge (e.g. A/B/some_ta.ta under --reports-dir). '
            'When omitted, merges each matching directory separately.'
        ),
    )
    
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level (default: INFO)'
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Setup logging
    setup_logging(log_level=args.log_level)
    
    # Determine reports directory
    if args.reports_dir:
        reports_dir = Path(args.reports_dir)
    else:
        reports_dir = Path(__file__).parent.parent / "reports"
    
    if not reports_dir.exists():
        logger.error(f"Reports directory not found: {reports_dir}")
        sys.exit(1)
    
    if args.pattern:
        _merge_by_pattern(args, reports_dir)
    elif args.binary_name:
        _merge_by_binary_name(args, reports_dir)
    else:
        logger.error("Either binary_name or --pattern must be specified")
        sys.exit(1)


def _merge_one(args, binary_name: str, ta_report_dir: Path) -> bool:
    report_files = find_report_files(binary_name, ta_report_dir)
    if not report_files:
        logger.error("No report files found matching the criteria")
        logger.info(f"Searched in: {ta_report_dir}")
        logger.info(f"Pattern: report_{binary_name}_*.json")
        return False

    logger.info(f"Found {len(report_files)} report files to merge in {ta_report_dir}")

    merged_data = merge_reports(report_files)
    if not merged_data:
        logger.error("Failed to merge reports")
        return False

    if args.output == 'merged_report' and binary_name:
        output_name = f"merged_report_{binary_name}"
    else:
        output_name = args.output

    output_path = generate_merged_report(merged_data, output_name, ta_report_dir)
    logger.info(f"Successfully merged {len(report_files)} reports into: {output_path}")
    return True


def _merge_by_pattern(args, reports_dir: Path) -> None:
    report_files = find_report_files_by_pattern(args.pattern, reports_dir)
    if not report_files:
        logger.error("No report files found matching the criteria")
        logger.info(f"Searched in: {reports_dir}")
        sys.exit(1)

    logger.info(f"Found {len(report_files)} report files to merge")
    merged_data = merge_reports(report_files)
    if not merged_data:
        logger.error("Failed to merge reports")
        sys.exit(1)

    output_name = args.output
    generate_merged_report(merged_data, output_name, reports_dir)


def _merge_by_binary_name(args, reports_dir: Path) -> None:
    if args.ta_report_dir:
        ta_report_dirs = [resolve_ta_report_dir(Path(args.ta_report_dir), reports_dir)]
    else:
        ta_report_dirs = discover_ta_report_dirs(reports_dir, args.binary_name)

    if not ta_report_dirs:
        logger.error("No report files found matching the criteria")
        logger.info(f"Searched under: {reports_dir}")
        logger.info(f"Pattern: report_{args.binary_name}_*.json")
        sys.exit(1)

    if len(ta_report_dirs) > 1 and not args.ta_report_dir:
        logger.info(
            f"Found {len(ta_report_dirs)} TA report directories for {args.binary_name}; "
            "merging each separately"
        )

    failures = 0
    for ta_report_dir in ta_report_dirs:
        if len(ta_report_dirs) > 1:
            try:
                rel = ta_report_dir.relative_to(reports_dir)
            except ValueError:
                rel = ta_report_dir
            logger.info(f"--- merging {rel} ---")
        if not _merge_one(args, args.binary_name, ta_report_dir):
            failures += 1

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()

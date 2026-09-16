#!/usr/bin/env python3
"""
HTTP Server for Symbolic Execution Reports

Serves HTML reports on port 8080 with a simple web interface
to browse and view generated reports.

Features:
- Groups reports by binary (TA) analyzed
- Folders sorted by newest report timestamp
- Reports within folders sorted by date/time

Performance optimizations:
- No DNS reverse lookups (avoids 30s+ delays)
- Threaded server for concurrent requests
- Socket reuse for faster restart
"""

import csv
import io
import json
import time
import http.server
import socketserver
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, quote
from datetime import datetime
from collections import defaultdict

# Cache for report tree so index and CSV share one scan (no rescan on Export CSV)
_report_tree_cache = None
_report_tree_cache_time = 0.0
_REPORT_TREE_CACHE_TTL_SEC = 120

# Add project root to path for standalone script execution
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logging_config import get_logger

logger = get_logger(__name__)

PORT = 8081
REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Regex patterns to parse report filenames
# Formats supported:
#   report_<binary>_<run_id>_<timestamp_us>.html  (with run_id and microseconds)
#   report_<binary>_<timestamp_us>.html           (no run_id, with microseconds)
#   report_<binary>_<timestamp>.html              (no run_id, no microseconds)
#   merged_report_<binary>_<timestamp>.html       (merged reports)


def parse_report_filename(filename):
    """
    Parse a report filename to extract binary name, run_id, and timestamp.
    Accepts .html or .json extension (normalized to .html for parsing).

    Supports multiple filename formats:
    - With run_id: report_myapp.bin_TPM2_Startup_20260105_143522_123456.html
    - No run_id (microseconds): report_myapp.bin_20260105_143522_123456.html
    - No run_id (no microseconds): report_myapp.bin_20260105_143522.html
    - Merged: merged_report_myapp.bin_20260105_143522.html

    Args:
        filename: The report filename (.html or .json)

    Returns:
        Tuple of (binary_name, run_id, timestamp_str) or (None, None, None) if parsing fails
    """
    if filename.endswith(".json"):
        filename = filename[:-5] + ".html"
    # Handle merged reports first
    match = re.match(r'^merged_report_(.+)_(\d{8}_\d{6})\.html$', filename)
    if match:
        return match.group(1), "merged", match.group(2)
    
    # Must start with report_
    if not filename.startswith('report_') or not filename.endswith('.html'):
        return None, None, None
    
    # Remove prefix and suffix
    inner = filename[7:-5]  # Remove 'report_' and '.html'
    
    # Try to find timestamp with microseconds at the end: _YYYYMMDD_HHMMSS_ffffff
    match = re.search(r'_(\d{8}_\d{6}_\d+)$', inner)
    if match:
        timestamp = match.group(1)
        prefix = inner[:match.start()]  # Everything before _timestamp
        
        # Now try to separate binary_name from run_id in prefix
        # Binary names typically end with .bin, .elf, .ta, etc.
        # Look for the last occurrence of a known extension followed by _
        ext_match = re.search(r'(\.(?:bin|elf|ta|so))_(.+)$', prefix, re.IGNORECASE)
        if ext_match:
            # Found extension followed by something - that something is the run_id
            binary_name = prefix[:ext_match.end(1)]  # Include the extension
            run_id = ext_match.group(2)
            return binary_name, run_id, timestamp
        else:
            # No run_id detected, entire prefix is the binary name
            return prefix, None, timestamp
    
    # Try to find timestamp without microseconds at the end: _YYYYMMDD_HHMMSS
    match = re.search(r'_(\d{8}_\d{6})$', inner)
    if match:
        timestamp = match.group(1)
        prefix = inner[:match.start()]
        
        # Try to separate binary_name from run_id
        ext_match = re.search(r'(\.(?:bin|elf|ta|so))_(.+)$', prefix, re.IGNORECASE)
        if ext_match:
            binary_name = prefix[:ext_match.end(1)]
            run_id = ext_match.group(2)
            return binary_name, run_id, timestamp
        else:
            return prefix, None, timestamp
    
    return None, None, None


def timestamp_to_datetime(timestamp_str):
    """Convert timestamp string to datetime object.
    
    Supports formats:
    - YYYYMMDD_HHMMSS_ffffff (new format with microseconds)
    - YYYYMMDD_HHMMSS (old format)
    """
    if timestamp_str is None:
        return datetime.min
    
    # Try new format with microseconds first
    try:
        return datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S_%f")
    except ValueError:
        pass
    
    # Try old format without microseconds
    try:
        return datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
    except ValueError:
        return datetime.min


class ReportHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler for serving reports"""
    
    def __init__(self, *args, **kwargs):
        # Set the directory to serve
        super().__init__(*args, directory=str(REPORTS_DIR.parent), **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        path = unquote(self.path)
        
        # Root path - show TA path folders index
        if path == '/' or path == '':
            self.serve_index()
        # CSV export
        elif path == '/export/csv' or path.startswith('/export/csv?'):
            self.serve_csv_export()
        # TA path group: either subfolders (tas/vuln_tas) or report list
        elif path.startswith('/group/'):
            group_path = unquote(path[7:].lstrip('/'))  # Remove '/group/' prefix
            # Map reserved name to actual path (legacy = flat reports at root)
            if group_path == 'legacy':
                group_path = '.'
            self.serve_group(group_path)
        # Legacy: binary folder page (by binary name)
        elif path.startswith('/binary/'):
            binary_name = path[8:].rstrip('/')
            self.serve_binary_folder(binary_name)
        # Serve report files (under reports/...)
        elif path.startswith('/reports/'):
            super().do_GET()
        # Anything else - show index
        else:
            self.serve_index()
    
    def _report_entry(self, report_file, rel_path):
        """Build a report dict for a report file; rel_path is path relative to REPORTS_DIR for URL."""
        binary_name, run_id, timestamp_str = parse_report_filename(report_file.name)
        if binary_name is None:
            binary_name = "Other"
            run_id = None
            timestamp_str = "00000000_000000"
        stat = report_file.stat()
        timestamp_dt = timestamp_to_datetime(timestamp_str)
        report_url = '/reports/' + rel_path.as_posix() if hasattr(rel_path, 'as_posix') else '/reports/' + str(rel_path).replace('\\', '/')
        return {
            'name': report_file.name,
            'path': report_url,
            'size': self.format_size(stat.st_size),
            'modified': timestamp_dt.strftime('%Y-%m-%d %H:%M:%S'),
            'timestamp_dt': timestamp_dt,
            'timestamp_str': timestamp_str,
            'run_id': run_id
        }

    def get_reports_grouped_by_ta_path(self):
        """
        Get all reports grouped by TA path. Uses cache so index and CSV share one scan.
        Scan uses os.walk(followlinks=False) and does not stat() files (fast).
        Entries are lightweight: name, timestamp_dt, timestamp_str, run_id.
        """
        global _report_tree_cache, _report_tree_cache_time
        now = time.time()
        if _report_tree_cache is not None and (now - _report_tree_cache_time) < _REPORT_TREE_CACHE_TTL_SEC:
            return _report_tree_cache
        ta_tree = defaultdict(lambda: defaultdict(list))
        if not REPORTS_DIR.exists():
            return ta_tree
        for root, _dirs, files in os.walk(REPORTS_DIR, topdown=True, followlinks=False):
            root_path = Path(root)
            try:
                rel_root = root_path.relative_to(REPORTS_DIR)
            except ValueError:
                continue
            for f in files:
                if not f.endswith(".html") or not (f.startswith("report_") or f.startswith("merged_report_")):
                    continue
                parts = rel_root.parts + (f,)
                if len(parts) >= 4:
                    ta_root = "/".join(parts[:-3])
                    subfolder = parts[-3] + "/" + parts[-2]
                elif len(parts) == 3:
                    ta_root = parts[0]
                    subfolder = parts[1]
                elif len(parts) == 2:
                    ta_root = "."
                    subfolder = parts[0]
                else:
                    ta_root = "."
                    subfolder = "Legacy"
                _, run_id, timestamp_str = parse_report_filename(f)
                timestamp_dt = timestamp_to_datetime(timestamp_str)
                entry = {
                    "name": f,
                    "timestamp_dt": timestamp_dt,
                    "timestamp_str": timestamp_str or "00000000_000000",
                    "run_id": run_id,
                }
                ta_tree[ta_root][subfolder].append(entry)
        for ta_root in ta_tree:
            for subfolder in ta_tree[ta_root]:
                ta_tree[ta_root][subfolder].sort(key=lambda r: r["timestamp_dt"], reverse=True)
        _report_tree_cache = ta_tree
        _report_tree_cache_time = now
        return ta_tree

    def get_reports_grouped_by_binary(self):
        """
        Legacy: get all reports grouped by binary name (flat list in reports/).
        Used for backward compatibility when opening /binary/<name>.
        """
        binary_reports = defaultdict(list)
        if REPORTS_DIR.exists():
            for report_file in REPORTS_DIR.glob('*.html'):
                entry = self._report_entry(report_file, Path(report_file.name))
                binary_name, _, _ = parse_report_filename(report_file.name)
                key = binary_name if binary_name else "Other"
                binary_reports[key].append(entry)
        for key in binary_reports:
            binary_reports[key].sort(key=lambda r: r['timestamp_dt'], reverse=True)
        return binary_reports

    def _latest_reports_from_tree(self, ta_tree):
        """From cached report tree, build list of (path_inside, json_path, filename) for latest report per TA."""
        out = []
        for ta_root, subfolders in ta_tree.items():
            for subfolder, reports in subfolders.items():
                if not reports:
                    continue
                latest = reports[0]
                path_inside = (ta_root + "/" + subfolder) if ta_root != "." else subfolder
                if path_inside == "Legacy":
                    path_inside = "."
                json_name = latest["name"][:-5] + ".json"  # .html -> .json
                json_path = REPORTS_DIR / ta_root / subfolder / json_name
                out.append((path_inside, json_path, latest["name"]))
        return out

    @staticmethod
    def _collect_ta_latest_reports_minimal():
        """
        Minimal scan for CSV: one walk, one entry per TA directory (latest report by filename).
        Returns list of (path_inside, json_path, html_filename). No tree, no cache, no stat().
        """
        if not REPORTS_DIR.exists():
            return []
        out = []
        for root, _dirs, files in os.walk(REPORTS_DIR, topdown=True, followlinks=False):
            report_jsons = [
                f for f in files
                if f.endswith(".json") and (f.startswith("report_") or f.startswith("merged_report_"))
            ]
            if not report_jsons:
                continue
            # Latest by timestamp in filename (no stat)
            def ts_key(name):
                _, _, ts = parse_report_filename(name)
                return timestamp_to_datetime(ts)
            report_jsons.sort(key=lambda f: ts_key(f.replace(".json", ".html")), reverse=True)
            latest_json = report_jsons[0]
            root_path = Path(root)
            try:
                rel = root_path.relative_to(REPORTS_DIR)
            except ValueError:
                continue
            path_inside = str(rel).replace("\\", "/") if rel.parts else "."
            json_path = root_path / latest_json
            html_name = latest_json.replace(".json", ".html")
            out.append((path_inside, json_path, html_name))
        return out

    @staticmethod
    def _write_chunk(wfile, data: bytes):
        """Write one chunk in chunked encoding (hex length + CRLF + data + CRLF)."""
        if data:
            wfile.write(("%x\r\n" % len(data)).encode("ascii"))
            wfile.write(data)
            wfile.write(b"\r\n")

    def serve_csv_export(self):
        """Serve CSV with minimal I/O: one walk (one entry per TA dir), then one JSON read per TA."""
        try:
            latest_per_ta = self._collect_ta_latest_reports_minimal()
        except Exception as e:
            logger.exception("CSV export failed: %s", e)
            self.send_error(500, "Failed to build CSV")
            return
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        header = [
            "Path", "Filename", "Blocks Reached", "Reachable Blocks", "Percentage Reached",
            "Bug Found", "Stub Called"
        ]
        writer.writerow(header)
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="report_overview.csv"')
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            self._write_chunk(self.wfile, out.getvalue().encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.debug("CSV export: client disconnected before body: %s", e)
            return
        summary_by_folder = defaultdict(lambda: {"blocks_hit": 0, "blocks_reachable": 0})
        for path_inside, json_path, filename in latest_per_ta:
            blocks_hit = ""
            blocks_reachable = ""
            pct = ""
            bug = "N"
            stub = "N"
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.debug("Could not load report JSON %s: %s", json_path, e)
            else:
                stats = data.get("stats", {})
                blocks_hit = stats.get("blocks_hit", "")
                blocks_reachable = stats.get("blocks_reachable", "")
                if isinstance(blocks_hit, (int, float)) and isinstance(blocks_reachable, (int, float)) and blocks_reachable:
                    pct = f"{(blocks_hit / blocks_reachable * 100):.1f}%"
                if data.get("bugs"):
                    bug = "Y"
                if data.get("stub_functions"):
                    stub = "Y"
                if path_inside and path_inside != ".":
                    common = str(Path(path_inside).parent) if ("/" in path_inside or "\\" in path_inside) else path_inside
                    if isinstance(blocks_hit, (int, float)):
                        summary_by_folder[common]["blocks_hit"] += blocks_hit
                    if isinstance(blocks_reachable, (int, float)):
                        summary_by_folder[common]["blocks_reachable"] += blocks_reachable
            row = [path_inside, filename, str(blocks_hit), str(blocks_reachable), pct, bug, stub]
            out = io.StringIO(newline="")
            csv.writer(out).writerow(row)
            try:
                self._write_chunk(self.wfile, out.getvalue().encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                logger.debug("CSV export: client disconnected: %s", e)
                return
        out = io.StringIO(newline="")
        w = csv.writer(out)
        w.writerow([])
        w.writerow(["Summary (by common folder)"])
        w.writerow(["Path", "Total Blocks Hit", "Total Reachable Blocks"])
        for common_path in sorted(summary_by_folder.keys()):
            s = summary_by_folder[common_path]
            w.writerow([common_path, str(s["blocks_hit"]), str(s["blocks_reachable"])])
        try:
            self._write_chunk(self.wfile, out.getvalue().encode("utf-8"))
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.debug("CSV export: client disconnected: %s", e)
    
    def serve_index(self):
        """Serve the index page listing all TA path folders (e.g. test_binaries/taemu/teegris)"""
        ta_tree = self.get_reports_grouped_by_ta_path()
        folders = []
        total_reports = 0
        for ta_root, subfolders in ta_tree.items():
            all_reports = []
            newest = datetime.min
            for subfolder, reports in subfolders.items():
                all_reports.extend(reports)
                if reports and reports[0]['timestamp_dt'] > newest:
                    newest = reports[0]['timestamp_dt']
            total_reports += len(all_reports)
            display_name = ta_root if ta_root != '.' else 'Legacy (flat)'
            folders.append({
                'name': display_name,
                'ta_root': ta_root,
                'report_count': len(all_reports),
                'newest_timestamp': newest,
                'newest_date': newest.strftime('%Y-%m-%d %H:%M:%S') if newest != datetime.min else 'N/A',
            })
        folders.sort(key=lambda f: f['newest_timestamp'], reverse=True)
        html = self.generate_index_html(folders, total_reports)
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        try:
            self.wfile.write(html.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.debug("Index: client disconnected: %s", e)
    
    def serve_group(self, group_path):
        """Serve group page: either subfolders (tas/vuln_tas) or report list, sorted by timestamp."""
        if not group_path or not REPORTS_DIR.exists():
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
        full_dir = REPORTS_DIR / group_path
        if not full_dir.is_dir():
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
        # Check if this is a leaf folder (contains .html) or has subfolders
        subdirs = [c for c in full_dir.iterdir() if c.is_dir()]
        report_files = [c for c in full_dir.iterdir() if c.is_file() and c.suffix == '.html']
        if report_files:
            # Leaf folder (e.g. .../teegris/tas): list reports sorted by timestamp
            reports = []
            for report_file in report_files:
                rel_path = report_file.relative_to(REPORTS_DIR)
                reports.append(self._report_entry(report_file, rel_path))
            reports.sort(key=lambda r: r['timestamp_dt'], reverse=True)
            parent_path = group_path.rsplit('/', 1)[0] if '/' in group_path else ''
            back_href = '/group/' + quote(parent_path, safe='') if parent_path else '/'
            html = self.generate_binary_folder_html(group_path, reports, back_href=back_href, back_label='Back to subfolders')
        elif subdirs:
            # Parent folder (e.g. .../teegris): list tas and vuln_tas, sorted by newest
            subfolder_infos = []
            for d in subdirs:
                html_files = list(d.glob('*.html'))
                reports = []
                for report_file in html_files:
                    rel_path = report_file.relative_to(REPORTS_DIR)
                    reports.append(self._report_entry(report_file, rel_path))
                reports.sort(key=lambda r: r['timestamp_dt'], reverse=True)
                newest = reports[0]['timestamp_dt'] if reports else datetime.min
                subfolder_infos.append({
                    'name': d.name,
                    'report_count': len(reports),
                    'newest_timestamp': newest,
                    'newest_date': newest.strftime('%Y-%m-%d %H:%M:%S') if reports else 'N/A',
                    'url': '/group/' + quote((group_path + '/' + d.name).strip('/'), safe='')
                })
            subfolder_infos.sort(key=lambda x: x['newest_timestamp'], reverse=True)
            html = self.generate_group_subfolders_html(group_path, subfolder_infos)
        else:
            html = self.generate_group_subfolders_html(group_path, [])
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        try:
            self.wfile.write(html.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.debug("Group: client disconnected: %s", e)

    def serve_binary_folder(self, binary_name):
        """Legacy: serve the page listing all reports for a specific binary (flat structure)"""
        binary_reports = self.get_reports_grouped_by_binary()
        if binary_name not in binary_reports:
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
        reports = binary_reports[binary_name]
        html = self.generate_binary_folder_html(binary_name, reports)
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        try:
            self.wfile.write(html.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.debug("Binary folder: client disconnected: %s", e)
    
    def generate_index_html(self, folders, total_reports):
        """Generate the HTML for the main index page with binary folders"""
        folders_html = ""
        
        if folders:
            for i, folder in enumerate(folders):
                delay = i * 0.05
                # Use 'legacy' for flat/root so the URL is not normalized away by the browser
                group_url = '/group/legacy' if folder['ta_root'] == '.' else '/group/' + quote(folder['ta_root'], safe='')
                folders_html += f"""
                <a href="{group_url}" class="folder-card" style="animation-delay: {delay}s">
                    <div class="folder-icon">📁</div>
                    <div class="folder-info">
                        <div class="folder-name">{folder['name']}</div>
                        <div class="folder-meta">
                            <span class="meta-item">📄 {folder['report_count']} report(s)</span>
                            <span class="meta-item">🕐 {folder['newest_date']}</span>
                        </div>
                    </div>
                    <div class="folder-arrow">›</div>
                </a>
                """
        else:
            folders_html = """
            <div class="no-reports">
                <div class="empty-icon">📂</div>
                <p>No reports found</p>
                <p class="hint">Reports will appear here after running symbolic execution</p>
            </div>
            """
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TA Analysis Reports</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-green: #3fb950;
            --accent-purple: #a371f7;
            --accent-orange: #d29922;
        }}
        
        body {{
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 40px 20px;
            background-image: 
                radial-gradient(ellipse at top, rgba(88, 166, 255, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at bottom right, rgba(163, 113, 247, 0.05) 0%, transparent 50%);
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 50px;
            animation: fadeInDown 0.6s ease-out;
        }}
        
        @keyframes fadeInDown {{
            from {{
                opacity: 0;
                transform: translateY(-20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        @keyframes fadeInUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        .header h1 {{
            font-size: 2.8em;
            font-weight: 700;
            margin-bottom: 12px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.02em;
        }}
        
        .header p {{
            font-size: 1.15em;
            color: var(--text-secondary);
            font-weight: 300;
        }}
        
        .stats-bar {{
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-bottom: 40px;
            animation: fadeInUp 0.6s ease-out 0.2s both;
        }}
        
        .stat {{
            text-align: center;
        }}
        
        .stat-value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 2em;
            font-weight: 600;
            color: var(--accent-cyan);
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        
        .export-csv-btn {{
            display: inline-flex;
            align-items: center;
            padding: 12px 20px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--accent-cyan);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s ease;
        }}
        
        .export-csv-btn:hover {{
            background: rgba(88, 166, 255, 0.15);
            border-color: var(--accent-cyan);
        }}
        
        .folders-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        
        .folder-card {{
            display: flex;
            align-items: center;
            gap: 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px 24px;
            text-decoration: none;
            color: inherit;
            transition: all 0.25s ease;
            animation: fadeInUp 0.5s ease-out both;
        }}
        
        .folder-card:hover {{
            background: var(--bg-tertiary);
            border-color: var(--accent-cyan);
            transform: translateX(4px);
            box-shadow: 0 4px 20px rgba(88, 166, 255, 0.1);
        }}
        
        .folder-icon {{
            font-size: 2em;
            flex-shrink: 0;
        }}
        
        .folder-info {{
            flex: 1;
            min-width: 0;
        }}
        
        .folder-name {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.1em;
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 6px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .folder-meta {{
            display: flex;
            gap: 20px;
            font-size: 0.9em;
            color: var(--text-secondary);
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        
        .folder-arrow {{
            font-size: 1.8em;
            color: var(--text-secondary);
            transition: transform 0.25s ease, color 0.25s ease;
        }}
        
        .folder-card:hover .folder-arrow {{
            transform: translateX(4px);
            color: var(--accent-cyan);
        }}
        
        .no-reports {{
            text-align: center;
            padding: 80px 20px;
            color: var(--text-secondary);
            animation: fadeInUp 0.6s ease-out;
        }}
        
        .empty-icon {{
            font-size: 4em;
            margin-bottom: 20px;
            opacity: 0.5;
        }}
        
        .no-reports p {{
            font-size: 1.3em;
            margin-bottom: 8px;
        }}
        
        .no-reports .hint {{
            font-size: 1em;
            opacity: 0.6;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding-top: 30px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.9em;
            animation: fadeInUp 0.6s ease-out 0.4s both;
        }}
        
        .footer code {{
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-tertiary);
            padding: 2px 8px;
            border-radius: 4px;
            color: var(--accent-green);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 TA Analysis Reports</h1>
            <p>Symbolic execution results for Trusted Applications</p>
        </div>
        
        <div class="stats-bar">
            <div class="stat">
                <div class="stat-value">{len(folders)}</div>
                <div class="stat-label">TA Paths</div>
            </div>
            <div class="stat">
                <div class="stat-value">{total_reports}</div>
                <div class="stat-label">Total Reports</div>
            </div>
            <a href="/export/csv" class="export-csv-btn" download target="_blank" rel="noopener">Export CSV</a>
        </div>
        
        <div class="folders-list">
            {folders_html}
        </div>
        
        <div class="footer">
            <p>Server running at <code>http://localhost:{PORT}</code></p>
            <p style="margin-top: 8px; opacity: 0.6;">Press Ctrl+C to stop</p>
        </div>
    </div>
</body>
</html>
        """
    
    def generate_group_subfolders_html(self, group_path, subfolder_infos):
        """Generate the HTML for a TA path page listing tas/vuln_tas subfolders."""
        subfolders_html = ""
        for i, info in enumerate(subfolder_infos):
            delay = i * 0.05
            subfolders_html += f"""
                <a href="{info['url']}" class="folder-card" style="animation-delay: {delay}s">
                    <div class="folder-icon">📁</div>
                    <div class="folder-info">
                        <div class="folder-name">{info['name']}</div>
                        <div class="folder-meta">
                            <span class="meta-item">📄 {info['report_count']} report(s)</span>
                            <span class="meta-item">🕐 {info['newest_date']}</span>
                        </div>
                    </div>
                    <div class="folder-arrow">›</div>
                </a>
                """
        if not subfolders_html:
            subfolders_html = '<div class="no-reports"><p>No subfolders or reports here.</p></div>'
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports – {group_path}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        :root {{
            --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #21262d;
            --border-color: #30363d; --text-primary: #e6edf3; --text-secondary: #8b949e;
            --accent-cyan: #58a6ff; --accent-green: #3fb950; --accent-purple: #a371f7;
        }}
        body {{ font-family: 'Outfit', sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; padding: 40px 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .back-link {{ display: inline-flex; align-items: center; gap: 8px; color: var(--text-secondary); text-decoration: none; font-size: 0.95em; margin-bottom: 30px; }}
        .back-link:hover {{ color: var(--accent-cyan); }}
        .header {{ margin-bottom: 40px; }}
        .header h1 {{ font-family: 'JetBrains Mono', monospace; font-size: 1.4em; margin-bottom: 8px; }}
        .header p {{ color: var(--text-secondary); font-size: 1em; }}
        .folders-list {{ display: flex; flex-direction: column; gap: 12px; }}
        .folder-card {{ display: flex; align-items: center; gap: 16px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px 24px; text-decoration: none; color: inherit; transition: all 0.25s ease; }}
        .folder-card:hover {{ background: var(--bg-tertiary); border-color: var(--accent-cyan); transform: translateX(4px); }}
        .folder-icon {{ font-size: 2em; }}
        .folder-name {{ font-family: 'JetBrains Mono', monospace; font-size: 1.1em; margin-bottom: 6px; }}
        .folder-meta {{ font-size: 0.9em; color: var(--text-secondary); }}
        .folder-arrow {{ font-size: 1.8em; color: var(--text-secondary); }}
        .no-reports {{ text-align: center; padding: 40px; color: var(--text-secondary); }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link"><span>←</span> Back to TA paths</a>
        <div class="header">
            <h1>📁 {group_path}</h1>
            <p>Choose a subfolder (tas or vuln_tas)</p>
        </div>
        <div class="folders-list">{subfolders_html}</div>
    </div>
</body>
</html>
        """

    def generate_binary_folder_html(self, binary_name, reports, back_href='/', back_label='Back to TA paths'):
        """Generate the HTML for a binary-specific folder page (report list)"""
        reports_html = ""
        
        for i, report in enumerate(reports):
            delay = i * 0.03
            # Extract timestamp and run_id for display
            timestamp_display = report['modified']
            run_id = report.get('run_id')
            
            # Display run_id as a badge if present
            if run_id == "merged":
                run_id_badge = '<span class="run-id-badge merged">🔀 merged</span>'
                report_icon = "📑"
            elif run_id:
                run_id_badge = f'<span class="run-id-badge">{run_id}</span>'
                report_icon = "📊"
            else:
                run_id_badge = ""
                report_icon = "📊"
            
            report_filename = report.get('name', '')
            reports_html += f"""
            <a href="{report['path']}" class="report-card" style="animation-delay: {delay}s">
                <div class="report-icon">{report_icon}</div>
                <div class="report-info">
                    <div class="report-filename">{report_filename}</div>
                    <div class="report-header">
                        <div class="report-timestamp">{timestamp_display}</div>
                        {run_id_badge}
                    </div>
                    <div class="report-meta">
                        <span class="meta-item">📦 {report['size']}</span>
                    </div>
                </div>
                <div class="report-arrow">›</div>
            </a>
            """
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports - {binary_name}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-green: #3fb950;
            --accent-purple: #a371f7;
            --accent-orange: #d29922;
        }}
        
        body {{
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 40px 20px;
            background-image: 
                radial-gradient(ellipse at top, rgba(163, 113, 247, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at bottom left, rgba(88, 166, 255, 0.05) 0%, transparent 50%);
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        
        @keyframes fadeInDown {{
            from {{
                opacity: 0;
                transform: translateY(-20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        @keyframes fadeInUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        .back-link {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.95em;
            margin-bottom: 30px;
            transition: color 0.2s ease;
            animation: fadeInDown 0.4s ease-out;
        }}
        
        .back-link:hover {{
            color: var(--accent-cyan);
        }}
        
        .back-link span {{
            font-size: 1.2em;
        }}
        
        .header {{
            margin-bottom: 40px;
            animation: fadeInDown 0.5s ease-out 0.1s both;
        }}
        
        .header h1 {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.6em;
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text-primary);
            word-break: break-all;
        }}
        
        .header p {{
            font-size: 1.1em;
            color: var(--text-secondary);
        }}
        
        .report-count {{
            display: inline-block;
            background: var(--accent-purple);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
            margin-left: 12px;
        }}
        
        .reports-list {{
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        
        .report-card {{
            display: flex;
            align-items: center;
            gap: 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px 22px;
            text-decoration: none;
            color: inherit;
            transition: all 0.25s ease;
            animation: fadeInUp 0.4s ease-out both;
        }}
        
        .report-card:hover {{
            background: var(--bg-tertiary);
            border-color: var(--accent-purple);
            transform: translateX(4px);
            box-shadow: 0 4px 20px rgba(163, 113, 247, 0.1);
        }}
        
        .report-icon {{
            font-size: 1.6em;
            flex-shrink: 0;
        }}
        
        .report-info {{
            flex: 1;
            min-width: 0;
        }}
        
        .report-filename {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95em;
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 6px;
            word-break: break-all;
        }}
        
        .report-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 4px;
            flex-wrap: wrap;
        }}
        
        .report-timestamp {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.05em;
            font-weight: 500;
            color: var(--text-primary);
        }}
        
        .run-id-badge {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75em;
            font-weight: 500;
            background: var(--bg-tertiary);
            color: var(--accent-cyan);
            padding: 3px 10px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }}
        
        .run-id-badge.merged {{
            background: linear-gradient(135deg, rgba(163, 113, 247, 0.2), rgba(88, 166, 255, 0.2));
            color: var(--accent-purple);
            border-color: var(--accent-purple);
        }}
        
        .report-meta {{
            display: flex;
            gap: 16px;
            font-size: 0.85em;
            color: var(--text-secondary);
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .report-arrow {{
            font-size: 1.6em;
            color: var(--text-secondary);
            transition: transform 0.25s ease, color 0.25s ease;
        }}
        
        .report-card:hover .report-arrow {{
            transform: translateX(4px);
            color: var(--accent-purple);
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 25px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.9em;
            animation: fadeInUp 0.5s ease-out 0.3s both;
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="{back_href}" class="back-link">
            <span>←</span> {back_label}
        </a>
        
        <div class="header">
            <h1>📁 {binary_name}<span class="report-count">{len(reports)} reports</span></h1>
            <p>All analysis reports, sorted by date</p>
        </div>
        
        <div class="reports-list">
            {reports_html}
        </div>
        
        <div class="footer">
            <p>angr-trustzone symbolic execution framework</p>
        </div>
    </div>
</body>
</html>
        """
    
    @staticmethod
    def format_size(size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def log_message(self, format, *args):
        """Custom log message format (no DNS lookup for performance)"""
        # Use client_address directly instead of address_string() to avoid slow DNS lookups
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.debug(f"{client_ip} - {format % args}")


def main():
    """Start the HTTP server"""
    # Ensure reports directory exists
    REPORTS_DIR.mkdir(exist_ok=True)
    
    logger.info("="*60)
    logger.info("Symbolic Execution Reports Server")
    logger.info("="*60)
    logger.info(f"Reports directory: {REPORTS_DIR}")
    logger.info(f"Server address: http://localhost:{PORT}")
    logger.info(f"Server address (external): http://0.0.0.0:{PORT}")
    logger.info("Press Ctrl+C to stop the server")
    logger.info("="*60)
    
    # Create threaded server for better performance
    class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        # Allow socket reuse for faster restart
        allow_reuse_address = True
        # Daemon threads for clean shutdown
        daemon_threads = True
    
    with ThreadedHTTPServer(("0.0.0.0", PORT), ReportHTTPRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
            httpd.shutdown()
            logger.info("Server stopped.")


if __name__ == "__main__":
    main()

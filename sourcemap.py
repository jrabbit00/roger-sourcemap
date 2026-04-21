#!/usr/bin/env python3
"""
Roger SourceMap - Source map scanner for bug bounty hunting.
"""

import argparse
import concurrent.futures
import json
import re
import requests
import sys
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patterns to find in source content
ENDPOINT_PATTERNS = [
    r'/api/[a-zA-Z0-9_/\-]+',
    r'/v\d+/[a-zA-Z0-9_/\-]+',
    r'/graphql',
    r'/rest/[a-zA-Z0-9_/\-]+',
    r'/internal/[a-zA-Z0-9_/\-]+',
    r'/private/[a-zA-Z0-9_/\-]+',
    r'/debug/[a-zA-Z0-9_/\-]+',
    r'/admin/[a-zA-Z0-9_/\-]+',
    r'/staging/[a-zA-Z0-9_/\-]+',
]

SECRET_PATTERNS = [
    r'(?i)(api_key|apikey|API_KEY)\s*[=:]\s*["\']([^"\']+)["\']',
    r'(?i)(token|TOKEN)\s*[=:]\s*["\']([^"\']{16,})["\']',
    r'(?i)process\.env\.(\w+)',
]

class RogerSourceMap:
    def __init__(self, target, output=None, threads=10, depth=3, quiet=False):
        self.target = target.rstrip('/')
        self.output = output
        self.threads = threads
        self.depth = depth
        self.quiet = quiet
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        self.crawled = set()
        
    def is_sourcemap(self, url):
        """Check if URL is a source map."""
        return url.endswith('.map')
    
    def find_sourcemaps_in_html(self, html, base_url):
        """Find source map references in HTML."""
        sourcemaps = []
        
        # Look for sourceMappingURL in JS
        pattern = r'//# sourceMappingURL=(.+?)(?:\n|$)'
        matches = re.findall(pattern, html)
        sourcemaps.extend(matches)
        
        # Look for sourceMappingURL in data attributes
        soup = BeautifulSoup(html, 'html.parser')
        
        # Script tags with sourcemap
        for script in soup.find_all('script', {'data-src': True}):
            src = script.get('data-src', '')
            if src.endswith('.js'):
                sourcemaps.append(src + '.map')
        
        # Resolve relative URLs
        resolved = []
        for sm in sourcemaps:
            if sm.startswith('//'):
                sm = 'https:' + sm
            elif sm.startswith('/'):
                parsed = urlparse(base_url)
                sm = f"{parsed.scheme}://{parsed.netloc}{sm}"
            elif not sm.startswith('http'):
                sm = urljoin(base_url, sm)
            
            if sm not in resolved:
                resolved.append(sm)
        
        return resolved
    
    def find_sourcemaps_in_js(self, js_content, base_url):
        """Find source map references in JS files."""
        return self.find_sourcemaps_in_html(js_content, base_url)
    
    def parse_sourcemap(self, url):
        """Parse a source map file."""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                sm = response.json()
                
                result = {
                    "url": url,
                    "sources": sm.get('sources', []),
                    "mappings": sm.get('mappings', ''),
                    "file": sm.get('file', ''),
                }
                return result
        except json.JSONDecodeError:
            if not self.quiet:
                print(f"[!] Invalid JSON: {url}")
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error: {url} - {e}")
        
        return None
    
    def extract_findings(self, sourcemap_data):
        """Extract endpoints and secrets from source map data."""
        findings = []
        
        # Source file paths
        if sourcemap_data.get('sources'):
            for source in sourcemap_data['sources']:
                # Look for interesting paths
                if any(keyword in source.lower() for keyword in ['admin', 'api', 'debug', 'private', 'internal', 'config', 'secret']):
                    findings.append(("Path", source))
                
                # Check for file extensions
                if source.endswith('.ts') or source.endswith('.vue') or source.endswith('.jsx'):
                    findings.append(("Source File", source))
        
        # Look for endpoints in the file field
        if sourcemap_data.get('file'):
            file_path = sourcemap_data['file']
            for pattern in ENDPOINT_PATTERNS:
                matches = re.findall(pattern, file_path)
                for match in matches:
                    findings.append(("Endpoint", match))
        
        return findings
    
    def crawl(self, url, current_depth=0):
        """Recursively crawl pages to find source maps."""
        if current_depth >= self.depth:
            return
        
        if url in self.crawled:
            return
        
        self.crawled.add(url)
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                content_type = response.headers.get('Content-Type', '')
                
                # Check if this is a JS file
                if 'javascript' in content_type or url.endswith('.js'):
                    sourcemaps = self.find_sourcemaps_in_js(content, url)
                    for sm in sourcemaps:
                        self.process_sourcemap(sm)
                
                # Check if this is HTML
                elif 'html' in content_type:
                    sourcemaps = self.find_sourcemaps_in_html(content, url)
                    for sm in sourcemaps:
                        self.process_sourcemap(sm)
                    
                    # Find links to crawl
                    soup = BeautifulSoup(content, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        parsed = urlparse(full_url)
                        
                        # Stay on same domain
                        if parsed.netloc != urlparse(self.target).netloc:
                            continue
                        
                        if full_url not in self.crawled:
                            self.crawl(full_url, current_depth + 1)
                
                # Check for direct .map files
                elif url.endswith('.map'):
                    self.process_sourcemap(url)
                    
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error crawling {url}: {e}")
    
    def process_sourcemap(self, url):
        """Process a single source map."""
        if not self.quiet:
            print(f"[*] Found source map: {url}")
        
        sm_data = self.parse_sourcemap(url)
        if sm_data:
            findings = self.extract_findings(sm_data)
            
            if findings:
                for finding_type, finding_value in findings:
                    if not self.quiet:
                        print(f"  [{finding_type}] {finding_value}")
                    self.findings.append({
                        "sourcemap": url,
                        "type": finding_type,
                        "value": finding_value
                    })
    
    def scan(self):
        """Run the source map scanner."""
        print(f"[*] Starting source map scan on: {self.target}")
        print(f"[*] Max depth: {self.depth}")
        print("=" * 60)
        
        # Start crawling from target
        print("[*] Crawling pages to find source maps...")
        self.crawl(self.target, 0)
        
        print()
        print("=" * 60)
        print(f"[*] Scan complete!")
        print(f"[*] Source maps found: {len(set([f['sourcemap'] for f in self.findings]))}")
        print(f"[*] Total findings: {len(self.findings)}")
        
        # Save results
        if self.output:
            with open(self.output, 'w') as f:
                f.write(f"# Source Map Findings for {self.target}\n\n")
                for finding in self.findings:
                    f.write(f"[{finding['type']}] {finding['value']}\n")
                    f.write(f"  Source: {finding['sourcemap']}\n\n")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger SourceMap - Source map scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL (e.g., https://target.com)")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Max crawl depth")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    scanner = RogerSourceMap(
        target=args.target,
        output=args.output,
        threads=args.threads,
        depth=args.depth,
        quiet=args.quiet
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()
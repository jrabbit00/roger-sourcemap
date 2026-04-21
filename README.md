# Roger SourceMap 🐰

Source map (.map) scanner for bug bounty reconnaissance. Discovers hidden endpoints, debug routes, and source file paths through source map analysis.

## Why Source Maps?

Source maps are JSON files that map minified JavaScript back to original source code. They often contain:
- Full API endpoints not exposed in the UI
- Debug and development endpoints
- Source file paths revealing internal structure
- Variable/function names that hint at vulnerabilities

## Features

- Recursively find all .map files on a target
- Parse source map JSON to extract mappings
- Find hidden endpoints and debug routes
- Extract source file paths
- Analyze source content for secrets
- Multi-threaded scanning

## Installation

```bash
git clone https://github.com/jrabbit00/roger-sourcemap.git
cd roger-sourcemap
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 sourcemap.py https://target.com

# Save results
python3 sourcemap.py target.com -o results.txt

# Deep scan (more pages)
python3 sourcemap.py target.com --depth 5
```

## Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output results to file |
| `-t, --threads` | Number of threads (default: 10) |
| `-d, --depth` | Max crawl depth (default: 3) |
| `-q, --quiet` | Quiet mode |

## What It Finds

- `/api/debug/*`, `/api/admin/*`
- Internal endpoints (`/internal/*`, `/private/*`)
- Source file paths
- Environment variables
- API keys in source (sometimes)

## Examples

```bash
# Full scan
python3 sourcemap.py https://example.com

# Quiet mode with output
python3 sourcemap.py example.com -q -o findings.txt
```

## License

MIT License
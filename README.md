# Roger SourceMap 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Source map (.map) scanner for bug bounty reconnaissance.**

Discovers hidden endpoints, debug routes, internal source file paths, and potential secrets through source map analysis.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

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

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger SourceMap helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)
# Sanitizr - URL Cleaner

[![Python Tests](https://github.com/Jordonh18/sanitizr/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Jordonh18/sanitizr/actions/workflows/python-tests.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![PyPI](https://img.shields.io/pypi/v/sanitizr.svg)](https://pypi.org/project/sanitizr/)
[![cover](https://codecov.io/gh/Jordonh18/sanitizr/branch/main/graph/badge.svg)](https://codecov.io/gh/Jordonh18/sanitizr)
![GitHub last commit](https://img.shields.io/github/last-commit/Jordonh18/sanitizr)

A powerful and modular URL cleaning library and CLI tool that removes tracking parameters and decodes redirects.

## Features

- 🧹 Clean URLs by removing tracking parameters
- 🔄 Decode redirect URLs (Google, Facebook, etc.)
- ⚙️ Customizable parameter whitelisting/blacklisting
- 🧰 Supports both Python API and CLI usage
- 📋 Process URLs from clipboard, files, or standard input
- 🔧 Configurable via JSON or YAML files

## Installation

You can install Sanitizr from PyPI:

```bash
pip install sanitizr
```

For development setup:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Command Line

```bash
# Clean a single URL
sanitizr -u "https://example.com?id=123&utm_source=newsletter"

# Clean URLs from a file
sanitizr -i urls.txt -o cleaned_urls.txt

# Clean URLs from stdin
cat urls.txt | sanitizr > cleaned_urls.txt

# Use verbose output to see the changes
sanitizr -u "https://example.com?id=123&utm_source=newsletter" -v

# Show version information
sanitizr --version  # or simply: sanitizr -V

# Interactive mode - just run without arguments
sanitizr
```

#### Interactive Mode

Running `sanitizr` without arguments starts an interactive session:

```text
╔═══════════════════════════════════╗
║ Sanitizr URL Cleaner v1.0.1       ║
║ Clean URLs by removing trackers   ║
╚═══════════════════════════════════╝

Enter URLs to clean (one per line). Press Ctrl+C to exit.
Type 'help' for instructions or 'exit' to quit.

URL> https://example.com?utm_source=newsletter&utm_medium=email
https://example.com
URL> help

Sanitizr URL Cleaner Help:
  Enter a URL to clean tracking parameters and decode redirects
  Commands:
    help - Show this help message
    exit/quit - Exit the program

URL> exit
```

### Python API

```python
from sanitizr.sanitizr import URLCleaner

cleaner = URLCleaner()
clean_url = cleaner.clean_url("https://example.com?id=123&utm_source=newsletter")
print(clean_url)  # https://example.com?id=123
```

## Configuration

Sanitizr can be configured via JSON or YAML files:

```yaml
# config.yaml
tracking_params:
  - custom_tracker
  - another_tracker
redirect_params:
  custom.com:
    - redirect
    - goto
whitelist_params:
  - keep_this_param
blacklist_params:
  - remove_this_param
```

Use the configuration with the `--config` option:

```bash
sanitizr -u "https://example.com?id=123&custom_tracker=abc" --config config.yaml
```

## License

Sanitizr is licensed under the GNU General Public License v3.0 or later - see the [LICENSE](LICENSE) file for details.
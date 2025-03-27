# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202-green)

<!-- END BADGIE TIME -->

DragonSec is an advanced security scanner that combines traditional static analysis with AI-powered code review.

[中文文档](./README_zh.md)

## Features

- **Multiple AI Models Support**:
  - OpenAI GPT-4
  - Google Gemini
  - Deepseek R1 (Aliyun)
  - Grok
  - Local AI Models (via Ollama)

- **Static Analysis**:
  - Integrated with Semgrep for reliable static code analysis
  - Custom security rules and patterns
  - Support for multiple programming languages

- **Hybrid Analysis**:
  - Combines AI insights with static analysis results
  - Reduces false positives through cross-validation
  - Provides comprehensive security scoring

- Asynchronous parallel processing

## Installation

```bash
pip install dragonsec
```
## Quick Start

1. Set up your API keys:
```bash
export OPENAI_API_KEY="your-openai-key"  # For OpenAI models
export GEMINI_API_KEY="your-gemini-key"  # For Google Gemini
export DEEPSEEK_API_KEY="your-deepseek-key"  # For Deepseek R1(Aliyun)
```

2. Run a scan:
```bash
# Using OpenAI GPT-4
dragonsec scan --path /path/to/code --mode openai --api-key $OPENAI_API_KEY

# Using Google Gemini
dragonsec scan --path /path/to/code --mode gemini --api-key $GEMINI_API_KEY

# Using Deepseek R1 (Aliyun)
dragonsec scan --path /path/to/code --mode deepseek --api-key $DEEPSEEK_API_KEY

# Using Local AI Model via Ollama
dragonsec scan --path /path/to/code --mode local --local-url http://localhost:11434 --local-model deepseek-r1:32b

# Using only Semgrep (no API key needed)
dragonsec scan --path /path/to/code --mode semgrep
```

## Configuration

DragonSec uses a default configuration that can be customized:

```python
# Custom configuration
DEFAULT_CONFIG = {
    'skip_dirs': {'node_modules', 'build', ...},
    'batch_size': 4,
    'batch_delay': 0.1,
    ...
}
```

You can override these settings using command line options:
- `--batch-size`: Number of files to process in parallel
- `--batch-delay`: Delay between batches in seconds
- `--include-tests`: Include test files in scan
- `--verbose`: Show detailed progress
- `--output-dir`: Custom directory for scan results

## Supported Languages

- Python
- JavaScript
- Java
- Go
- PHP
- Dockerfile

## Output

Results are saved in JSON format with:
- Detailed vulnerability descriptions
- Severity ratings
- Line numbers
- Risk analysis
- Remediation recommendations
- Overall security score

## Command Line Usage

DragonSec provides several commands and options:

### Main Commands

```bash
dragonsec scan   # Run security scan
dragonsec rules  # List available security rules
```

### Scan Command Options

```bash
dragonsec scan [OPTIONS]

Required:
  --path PATH               Path to scan (file or directory)

Scan Mode:
  --mode MODE              Scanning mode [default: semgrep]
                          Choices:
                          - semgrep (basic static analysis)
                          - openai (OpenAI enhanced)
                          - gemini (Google Gemini enhanced)
                          - deepseek (Deepseek R1 on Aliyun)
                          - local (Local AI model)

Authentication:
  --api-key KEY            API key for AI service (required for AI modes)

Performance:
  --batch-size N          Files to process per batch [default: 4]
  --batch-delay SECONDS   Delay between batches [default: 0.1]

File Selection:
  --include-tests         Include test files in scan [default: False]

Output:
  --output-dir DIR        Directory for scan results [default: ~/.dragonsec/scan_results]
  --verbose, -v          Show detailed progress [default: False]
```

### Example Commands

```bash
# Basic scan with default settings
dragonsec scan --path ./myproject

# AI-enhanced scan
dragonsec scan \
  --path ./myproject \
  --mode openai \
  --api-key $OPENAI_API_KEY \
  --batch-size 4 \
  --batch-delay 0.2 \
  --include-tests \
  --verbose

# View available security rules
dragonsec rules
```

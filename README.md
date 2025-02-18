# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202-green)  

<!-- END BADGIE TIME -->

DragonSec is an advanced security scanner that combines traditional static analysis with AI-powered code review.

## Features

- **Multiple AI Models Support**:
  - OpenAI GPT-4o
  - Google Gemini-1.5-flash
  - Deepseek R1 (Aliyun)
  - More models coming soon...

- **Static Analysis**:
  - Integrated with Semgrep for reliable static code analysis
  - Custom security rules and patterns
  - Support for multiple programming languages

- **Hybrid Analysis**:
  - Combines AI insights with static analysis results
  - Reduces false positives through cross-validation
  - Provides comprehensive security scoring

## Installation

```bash
pip install dragonsec
```

## Quick Start

1. Set up your API keys:
```bash
export OPENAI_API_KEY="your-openai-key"  # For GPT-4
export GEMINI_API_KEY="your-gemini-key"  # For Gemini
export DEEPSEEK_API_KEY="your-deepseek-key"  # For Deepseek
```

2. Run a scan:
```bash
# Using OpenAI GPT-4
dragonsec scan --path /path/to/code --mode openai --api-key $OPENAI_API_KEY

# Using Google Gemini-1.5-flash
dragonsec scan --path /path/to/code --mode gemini --api-key $GEMINI_API_KEY

# Using Deepseek R1 (Aliyun)
dragonsec scan --path /path/to/code --mode deepseek --api-key $DEEPSEEK_API_KEY

# Using only Semgrep (no API key needed)
dragonsec scan --path /path/to/code --mode semgrep
```

## Configuration

- `--batch-size`: Number of files to process in parallel (default: 4)
- `--batch-delay`: Delay between batches in seconds (default: 0.1)
- `--include-tests`: Include test files in scan (default: False)
- `--verbose`: Show detailed progress information
- `--output-dir`: Custom directory for scan results (default: ~/.dragonsec/scan_results)

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

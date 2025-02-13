# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202-green)  

<!-- END BADGIE TIME -->

DragonSec is a tool that combines Semgrep's static analysis with AI-powered code review to identify security vulnerabilities in your code.

## Features
- Intelligent rule selection based on file types:
  - Language-specific rules (Python, JavaScript, Go, Java)
  - OWASP Top 10 checks
  - Secrets Detection
  - Container Security (Docker, Kubernetes)
- AI-powered analysis:
  - OpenAI GPT-4 integration
  - Google Gemini Pro support
  - Context-aware code review
- Performance optimizations:
  - Parallel file processing
  - Result caching
  - Smart rule selection

## Prerequisites

1. Install the package:
```bash
pip install -e .
```

2. Install Semgrep:
```bash
pip install semgrep
```

## Usage

1. Basic security scan (using Semgrep only):
```bash
dragonsec scan --path <path_to_your_project> --mode semgrep
```

2. AI-enhanced scan:
```bash
# Using OpenAI
dragonsec scan --path <path_to_your_project> --mode openai --api-key <your_openai_api_key>

# Using Google Gemini
dragonsec scan --path <path_to_your_project> --mode gemini --api-key <your_gemini_api_key>
```

3. View available security rules:
```bash
dragonsec rules --list
```

4. Additional options:
```bash
# Include test files in scan
dragonsec scan --path <path> --include-tests

# Adjust parallel processing
dragonsec scan --path <path> --workers 4

# Enable verbose output
dragonsec scan --path <path> --verbose
```

Scan results are saved in `~/.dragonsec/scan_results` by default.

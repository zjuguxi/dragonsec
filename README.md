# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202-green)  

<!-- END BADGIE TIME -->

DragonSec is a tool that scans your code for security vulnerabilities using Semgrep and AI.

## Features
- Multiple security rule sets:
  - OWASP Top 10
  - CI/CD Security
  - Supply Chain Security
  - JWT Security
  - Secrets Detection
  - Language-specific rules (Python, JavaScript, Go, Java)
  - Container Security (Docker, Kubernetes)
- Automatic rule updates (every 7 days)
- AI-powered analysis (OpenAI GPT-4 and Gemini 1.5 Pro)

## Rule Sets
DragonSec automatically manages and updates its security rule sets. The rules are:
- Updated every 7 days
- Stored in `~/.dragonsec/rules`
- Include multiple specialized security checks

You can check the rule status with:
```bash
dragonsec-scan --list-rules
```

## Usage

1. Install the package
```bash
cd dragonsec
pip install -e .
```

2. Manage security rules
```bash
# List available rule sets
dragonsec rules --list
```

3. Run security scans
```bash
# Basic security scan
dragonsec scan --path <path_to_your_project> --mode semgrep

# AI-enhanced scan
dragonsec scan --path <path_to_your_project> --mode <openai|gemini> --api-key <your_api_key>
```

4. Check the results in the `~/.dragonsec/scan_results` directory.
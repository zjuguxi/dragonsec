# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)  

<!-- END BADGIE TIME -->

DragonSec is a tool that scans your code for security vulnerabilities using Semgrep and AI.

## Features
Now supports OpenAI gpt-4o and Gemini 1.5 pro.

## Usage
1. Install the package
```bash
cd dragonsec
pip install -e .
```
2. Run the scanner
```bash
dragonsec-scan --path <path_to_your_project> --mode <openai|gemini> --api-key <your_api_key>
dragonsec-scan --path <path_to_your_project> --mode semgrep
```
3. Check the results in the `dragonsec/scan_results` directory.
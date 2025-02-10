# DragonSec

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
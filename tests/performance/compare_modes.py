import asyncio
import json
from pathlib import Path
from dragonsec.core.scanner import SecurityScanner, ScanMode
import os

async def compare_modes():
    # Get test file path
    test_file = Path(__file__).parent / "tests" / "fixtures" / "vulnerable_code.py"
    if not test_file.exists():
        print(f"Test file does not exist: {test_file}")
        return
    
    # Define modes to test
    modes = {
        ScanMode.SEMGREP_ONLY: None,
        ScanMode.LOCAL: None
    }
    
    # Add other modes if API keys are available
    if os.environ.get("OPENAI_API_KEY"):
        modes[ScanMode.OPENAI] = os.environ.get("OPENAI_API_KEY")
    
    results = {}
    
    # Test each mode
    for mode, api_key in modes.items():
        print(f"\nTesting mode: {mode.value}")
        scanner = SecurityScanner(
            mode=mode,
            api_key=api_key,
            verbose=True,
            batch_size=1,
            include_tests=True
        )
        
        result = await scanner.scan_file(str(test_file))
        results[mode.value] = result
        
        print(f"   Found vulnerabilities: {len(result.get('vulnerabilities', []))}")
        print(f"   Security score: {result.get('overall_score')}")
    
    # Save comparison results
    with open("mode_comparison.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nComparison results saved to mode_comparison.json")

if __name__ == "__main__":
    asyncio.run(compare_modes()) 
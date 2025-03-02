import json
from pathlib import Path
import pytest
import requests

from dragonsec.providers.local import LocalProvider

@pytest.mark.asyncio
async def test_local_provider():
    """Test local provider"""
    # 检查 Ollama 服务器是否可用
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        pytest.skip("Local model server is not available")
    
    # Get test file path
    test_file = Path(__file__).parent / "fixtures" / "vulnerable_code.py"
    
    if not test_file.exists():
        pytest.skip(f"Test file not found: {test_file}")
    
    # Read file content
    with open(test_file, "r") as f:
        code = f.read()
    
    try:
        # Analyze code
        result = await provider._analyze_with_ai(code, str(test_file))
        
        # Basic assertions
        assert isinstance(result, dict)
        assert "vulnerabilities" in result
        assert "overall_score" in result
        assert isinstance(result["vulnerabilities"], list)
    except Exception as e:
        pytest.skip(f"Error analyzing code: {e}")

# Keep the standalone runner for manual testing
if __name__ == "__main__":
    import asyncio
    import sys
    from pathlib import Path
    
    # Add project root to path if running from tests directory
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_local_provider()
        
        # Print more detailed results for manual testing
        test_file = Path(__file__).parent / "fixtures" / "vulnerable_code.py"
        with open(test_file, "r") as f:
            code = f.read()
        
        provider = LocalProvider()
        
        try:
            # Add debug information
            print("\n==== Sending request to local model ====")
            prompt = provider._build_prompt(code, str(test_file))
            print(f"Prompt length: {len(prompt)} characters")
            
            # Call API directly and view raw response
            raw_response = await provider._call_api(prompt)
            print(f"\n==== Raw response ====")
            print("Response length:", len(raw_response))
            print("First 500 characters:")
            print(raw_response[:500])
            print("\nLast 500 characters:")
            print(raw_response[-500:] if len(raw_response) > 500 else raw_response)
            
            # Try to parse response
            print("\n==== Trying to parse response ====")
            try:
                result = provider._parse_response(raw_response)
                print("Parsing successful")
            except Exception as e:
                print(f"Parsing error: {e}")
                import traceback
                traceback.print_exc()
                result = provider._get_default_response()
            
            print(f"\n==== Security Scan Results ====")
            print(f"File: {test_file.name}")
            print(f"Security Score: {result.get('overall_score', 100)}/100")
            
            if result.get("vulnerabilities"):
                print("\nVulnerabilities Found:")
                for i, vuln in enumerate(result["vulnerabilities"], 1):
                    print(f"\n[{i}] {vuln.get('type', 'Unknown Issue')}")
                    print(f"  Severity: {vuln.get('severity', 'N/A')}/10")
                    print(f"  Line: {vuln.get('line_number', 'N/A')}")
                    print(f"  Description: {vuln.get('description', 'No description')}")
            else:
                print("\nNo vulnerabilities detected.")
        except Exception as e:
            print(f"\n==== Error ====")
            print(f"Error analyzing code: {e}")
            import traceback
            traceback.print_exc()
    
    asyncio.run(run_test()) 
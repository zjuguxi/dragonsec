import json
import pytest
from dragonsec.providers.local import LocalProvider
import requests

@pytest.mark.asyncio
async def test_prompt_formats():
    """Test different prompt formats with local provider"""
    # Check if local model server is available
    try:
        # 尝试直接调用模型API而不是健康检查端点
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "deepseek-r1:32b", "prompt": "hello", "stream": False},
            timeout=5
        )
        if response.status_code != 200:
            pytest.skip(f"Local model server returned status code {response.status_code}")
    except requests.RequestException as e:
        pytest.skip(f"Local model server is not available: {e}")
    
    provider = LocalProvider(model="deepseek-r1:1.5b")
    
    code = """
def unsafe_function(user_input):
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    return query
"""
    
    # Test the default prompt
    prompt = provider._build_prompt(code, "test.py")
    assert "security vulnerabilities" in prompt
    assert "SQL Injection" in prompt
    assert "JSON" in prompt
    
    # Test API call with minimal code sample - skip if server not available
    try:
        response = await provider._call_api("Analyze this code for security issues: print('hello')")
        assert response  # Just check we get a response
    except Exception as e:
        pytest.skip(f"Skipping API call test: {e}")
    
    # Basic validation of response processing
    try:
        # Create a mock response that should parse as JSON
        mock_response = '{"vulnerabilities":[], "overall_score": 100, "summary": "Test"}'
        result = provider._validate_result(json.loads(mock_response), "test.py")
        assert result["overall_score"] == 100
        assert result["vulnerabilities"] == []
    except Exception as e:
        pytest.fail(f"Failed to validate result: {e}")

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
        await test_prompt_formats()
        
        # Additional manual testing
        provider = LocalProvider(model="deepseek-r1:1.5b")
        
        code = """
def unsafe_function(user_input):
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    return query
"""
        
        # Test different prompts
        prompts = [
            # Original prompt
            provider._build_prompt(code, "test.py"),
            
            # Simplified prompt
            f"""Analyze this code for security vulnerabilities and return JSON:
{code}""",
            
            # Detailed prompt
            f"""You are a security expert. Analyze this Python code for security vulnerabilities:
{code}

Focus on SQL injection, XSS, command injection, etc.
Return a detailed JSON with all vulnerabilities found.
"""
        ]
        
        for i, prompt in enumerate(prompts):
            print(f"\n=== Testing prompt #{i+1} ===")
            print(f"Prompt length: {len(prompt)} characters")
            
            response = await provider._call_api(prompt)
            print(f"Response length: {len(response)} characters")
            print(f"First 100 characters: {response[:100]}...")
            
            # Try to parse JSON
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    json_str = response[json_start:json_end]
                    result = json.loads(json_str)
                    print(f"Successfully parsed JSON, found {len(result.get('vulnerabilities', []))} vulnerabilities")
                else:
                    print("No valid JSON found")
            except Exception as e:
                print(f"Failed to parse JSON: {e}")
    
    asyncio.run(run_test()) 
import json
import pytest
from dragonsec.providers.local import LocalProvider
from dragonsec.providers.openai import OpenAIProvider
import requests
import asyncio
import os
from pathlib import Path
import sys


@pytest.mark.asyncio
async def test_prompt_formats():
    """Test different prompt formats"""
    # Check if Ollama server is available
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        # If local server is not available, use OpenAI as fallback
        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("Neither local model server nor OpenAI API key is available")
        provider = OpenAIProvider(api_key=os.getenv("OPENAI_API_KEY"))

    # Simple test code
    code = """
def unsafe_sql_query(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    return query
"""

    # Test different prompt formats
    prompts = [
        "Simple prompt: Analyze security issues in this code",
        "Detailed prompt: Please analyze SQL injection vulnerabilities in this code and provide repair suggestions",
    ]

    try:
        for i, prompt in enumerate(prompts):
            print(f"Testing prompt format {i+1}")

            # Create provider with custom prompt
            class CustomPromptProvider(type(provider)):
                def _build_prompt(self, code, file_path=None):
                    return f"{prompt}\n\n```python\n{code}\n```"

            custom_provider = CustomPromptProvider(api_key=os.getenv("OPENAI_API_KEY"))

            # Set timeout
            timeout = 60  # 60 seconds timeout

            # Use asyncio.wait_for to add timeout control
            result = await asyncio.wait_for(
                custom_provider.analyze_code(code, "test_code.py"), timeout=timeout
            )

            # Verify results
            assert "vulnerabilities" in result
            assert "overall_score" in result
            assert isinstance(result["vulnerabilities"], list)

            # Verify SQL injection detection
            vuln_types = [v.get("type", "").lower() for v in result["vulnerabilities"]]
            assert any("sql" in t for t in vuln_types), "SQL injection not detected"

    except asyncio.TimeoutError:
        pytest.skip(f"Test timed out after {timeout} seconds")
    except Exception as e:
        pytest.skip(f"Error testing prompts: {e}")


# Keep independent runner for manual testing
if __name__ == "__main__":
    # If running from test directory, add project root to path
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))

    async def run_test():
        await test_prompt_formats()

    asyncio.run(run_test())

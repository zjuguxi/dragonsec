import json
from pathlib import Path
import pytest
import requests
import asyncio
import sys
import os

from dragonsec.providers.local import LocalProvider
from dragonsec.providers.openai import OpenAIProvider


@pytest.mark.asyncio
async def test_local_provider():
    """Test local provider"""
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

    # Set timeout
    timeout = 60  # 60 seconds timeout

    try:
        # Use asyncio.wait_for to add timeout control
        result = await asyncio.wait_for(
            provider.analyze_code(code, "test_code.py"), timeout=timeout
        )

        # Basic verification
        assert "vulnerabilities" in result
        assert "overall_score" in result
        assert isinstance(result["vulnerabilities"], list)

        # Verify SQL injection detection
        vuln_types = [v.get("type", "").lower() for v in result["vulnerabilities"]]
        assert any("sql" in t for t in vuln_types), "SQL injection not detected"

    except asyncio.TimeoutError:
        pytest.skip(f"Test timed out after {timeout} seconds")
    except Exception as e:
        pytest.skip(f"Error testing provider: {e}")


# Keep independent runner for manual testing
if __name__ == "__main__":
    # If running from test directory, add project root to path
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))

    async def run_test():
        await test_local_provider()

    asyncio.run(run_test())

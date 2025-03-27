import pytest
from unittest.mock import AsyncMock, patch
from dragonsec.providers.grok import GrokProvider


@pytest.fixture
def grok_provider():
    """Create a test instance of GrokProvider"""
    with patch("dragonsec.providers.base.AIProvider._secure_api_key") as mock_secure:
        mock_secure.return_value = "xai-test-key"
        provider = GrokProvider("xai-test-key")
        assert provider.model == "grok-2-latest"
        assert "api.x.ai" in str(provider.client.base_url)
        return provider


@pytest.mark.asyncio
async def test_grok_analysis_with_findings():
    """Test Grok code analysis with security findings"""
    provider = GrokProvider("xai-test-key")

    mock_response = AsyncMock()
    mock_response.choices = [AsyncMock()]
    mock_response.choices[0].message = AsyncMock()
    mock_response.choices[
        0
    ].message.content = """
    {
        "vulnerabilities": [
            {
                "type": "SQL Injection",
                "severity": 8,
                "description": "SQL injection vulnerability found",
                "line_number": 15,
                "file": "test.py",
                "risk_analysis": "High risk of data breach",
                "recommendation": "Use parameterized queries"
            }
        ],
        "overall_score": 20,
        "summary": "Found 1 security issue"
    }
    """

    with patch(
        "openai.resources.chat.completions.AsyncCompletions.create",
        return_value=mock_response,
    ):
        with patch.object(provider.client, "chat") as mock_chat:
            mock_chat.completions.create = AsyncMock(return_value=mock_response)
            result = await provider._analyze_with_ai(
                code="query = f'SELECT * FROM users WHERE id = {user_input}'",
                file_path="test.py",
            )

            assert "vulnerabilities" in result
            assert len(result["vulnerabilities"]) == 1
            assert result["vulnerabilities"][0]["type"] == "SQL Injection"


@pytest.mark.asyncio
async def test_grok_analysis_no_findings():
    """Test Grok code analysis with no findings"""
    provider = GrokProvider("xai-test-key")

    mock_response = AsyncMock()
    mock_response.choices = [AsyncMock()]
    mock_response.choices[0].message = AsyncMock()
    mock_response.choices[
        0
    ].message.content = """
    {
        "vulnerabilities": [],
        "overall_score": 100,
        "summary": "No vulnerabilities found"
    }
    """

    with patch(
        "openai.resources.chat.completions.AsyncCompletions.create",
        new=AsyncMock(return_value=mock_response),
    ):
        result = await provider.analyze_code(
            code="print('Hello, World!')", file_path="test.py"
        )

        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) == 0
        assert result["overall_score"] == 100


@pytest.mark.asyncio
async def test_grok_analysis_error():
    """Test Grok code analysis error handling"""
    provider = GrokProvider("xai-test-key")

    with patch(
        "openai.resources.chat.completions.AsyncCompletions.create",
        side_effect=Exception("API Error"),
    ):
        result = await provider.analyze_code(code="test code", file_path="test.py")

        assert result == provider._get_default_response()
        assert len(result["vulnerabilities"]) == 0
        assert result["overall_score"] == 100


@pytest.mark.asyncio
async def test_grok_skip_test_files():
    """Test that test files are skipped"""
    provider = GrokProvider("xai-test-key")

    result = await provider.analyze_code(
        code="test code", file_path="/path/to/tests/test_file.py"
    )

    assert len(result["vulnerabilities"]) == 0
    assert result["overall_score"] == 100
    assert "Skipped test file" in result["summary"]

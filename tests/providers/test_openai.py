import pytest
from dragonsec.providers.openai import OpenAIProvider
from unittest.mock import AsyncMock, patch


@pytest.fixture
def openai_provider():
    """Create a test instance of OpenAIProvider"""
    with patch("dragonsec.providers.base.AIProvider._secure_api_key") as mock_secure:
        mock_secure.return_value = (
            "test_key_1234567890123456789012345678901"  # 32 characters
        )
        return OpenAIProvider("test_key_1234567890123456789012345678901")


@pytest.mark.asyncio
async def test_analyze_code_success(openai_provider):
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
                "severity": 9,
                "description": "Potential SQL injection vulnerability",
                "line_number": 15,
                "file": "src/db.py",
                "risk_analysis": "High risk of data breach",
                "recommendation": "Use parameterized queries"
            }
        ],
        "overall_score": 80,
        "summary": "Found critical vulnerability"
    }
    """

    async def mock_create(*args, **kwargs):
        return mock_response

    with patch(
        "openai.resources.chat.completions.AsyncCompletions.create", new=mock_create
    ):
        result = await openai_provider.analyze_code(
            code='SELECT * FROM users WHERE id = "' + "123" + '"',
            file_path="/test/src/db.py",
        )

        assert result["vulnerabilities"][0]["type"] == "SQL Injection"
        assert result["vulnerabilities"][0]["severity"] == 9


@pytest.mark.asyncio
async def test_analyze_code_error(openai_provider):
    with patch(
        "openai.resources.chat.completions.AsyncCompletions.create",
        side_effect=Exception("API Error"),
    ):
        result = await openai_provider.analyze_code(
            code="test code", file_path="test.py"
        )
        assert result == openai_provider._get_default_response()


def test_merge_results(openai_provider):
    semgrep_results = [
        {
            "check_id": "python.lang.security.audit.exec-use",
            "path": "test.py",
            "start": {"line": 10},
            "extra": {"severity": "ERROR"},
        }
    ]

    ai_results = {
        "vulnerabilities": [
            {
                "type": "Command Injection",
                "severity": 8,
                "line_number": 15,
                "file": "test.py",
            }
        ]
    }

    result = openai_provider.merge_results(semgrep_results, ai_results)
    assert len(result["vulnerabilities"]) == 2
    assert result["vulnerabilities"][0]["source"] == "semgrep"
    assert result["vulnerabilities"][1]["source"] == "ai"


@pytest.mark.asyncio
async def test_openai_streaming():
    """Test streaming response handling"""
    provider = OpenAIProvider("test_key")
    code = """
    def unsafe_function(user_input):
        eval(user_input)
    """

    result = await provider.analyze_code(code, "test.py", stream=True)
    assert isinstance(result, dict)
    assert "vulnerabilities" in result


@pytest.mark.asyncio
async def test_openai_context_handling():
    """Test context handling in analysis"""
    provider = OpenAIProvider("test_key")
    context = {"imports": ["os", "sys"], "related_files": ["utils.py"]}

    result = await provider.analyze_code("print('test')", "test.py", context=context)
    assert isinstance(result, dict)

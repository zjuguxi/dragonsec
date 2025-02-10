import pytest
from dragonsec.providers.openai import OpenAIProvider
from unittest.mock import AsyncMock, patch

@pytest.fixture
def openai_provider():
    return OpenAIProvider("test_key")

@pytest.mark.asyncio
async def test_analyze_code_success(openai_provider):
    mock_response = {
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
    
    with patch('openai.AsyncOpenAI.chat.completions.create', new_callable=AsyncMock) as mock_create:
        mock_create.return_value.choices[0].message.content = str(mock_response)
        result = await openai_provider.analyze_code(
            code="SELECT * FROM users WHERE id = " + user_id,
            file_path="/test/src/db.py"
        )
        
        assert result["vulnerabilities"][0]["type"] == "SQL Injection"
        assert result["vulnerabilities"][0]["severity"] == 9

@pytest.mark.asyncio
async def test_analyze_code_error(openai_provider):
    with patch('openai.AsyncOpenAI.chat.completions.create', side_effect=Exception("API Error")):
        result = await openai_provider.analyze_code(
            code="test code",
            file_path="test.py"
        )
        assert result == openai_provider._get_default_response()

def test_merge_results(openai_provider):
    semgrep_results = [
        {
            "check_id": "python.lang.security.audit.exec-use",
            "path": "test.py",
            "start": {"line": 10},
            "extra": {"severity": "ERROR"}
        }
    ]
    
    ai_results = {
        "vulnerabilities": [
            {
                "type": "Command Injection",
                "severity": 8,
                "line_number": 15,
                "file": "test.py"
            }
        ]
    }
    
    result = openai_provider.merge_results(semgrep_results, ai_results)
    assert len(result["vulnerabilities"]) == 2
    assert result["vulnerabilities"][0]["source"] == "semgrep"
    assert result["vulnerabilities"][1]["source"] == "ai" 
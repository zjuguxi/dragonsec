import pytest
from dragonsec.providers.gemini import GeminiProvider
from unittest.mock import AsyncMock, patch

@pytest.fixture
def gemini_provider():
    return GeminiProvider("test_key")

@pytest.mark.asyncio
async def test_analyze_code_success(gemini_provider):
    mock_response = AsyncMock()
    mock_response.text = '''
    {
        "vulnerabilities": [
            {
                "type": "XSS",
                "severity": 7,
                "description": "Potential XSS vulnerability",
                "line_number": 25,
                "file": "src/app.js",
                "risk_analysis": "Medium risk of script injection",
                "recommendation": "Use proper output encoding"
            }
        ],
        "overall_score": 85,
        "summary": "Found security issues"
    }
    '''
    
    with patch('google.generativeai.GenerativeModel.generate_content_async', 
              return_value=mock_response) as mock_generate:
        result = await gemini_provider.analyze_code(
            code="document.write(userInput)",
            file_path="/test/src/app.js"
        )
        
        assert result["vulnerabilities"][0]["type"] == "XSS"
        assert result["vulnerabilities"][0]["severity"] == 7

@pytest.mark.asyncio
async def test_analyze_code_error(gemini_provider):
    with patch('google.generativeai.GenerativeModel.generate_content_async', 
              side_effect=Exception("API Error")):
        result = await gemini_provider.analyze_code(
            code="test code",
            file_path="test.py"
        )
        assert result == gemini_provider._get_default_response() 
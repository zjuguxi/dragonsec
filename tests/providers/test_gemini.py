import pytest
from dragonsec.providers.gemini import GeminiProvider
from unittest.mock import AsyncMock, patch

@pytest.fixture
def gemini_provider():
    with patch('dragonsec.providers.base.AIProvider._secure_api_key') as mock_secure:
        mock_secure.return_value = "test_key"
        provider = GeminiProvider("test_key")
        return provider

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
            file_path="/test/src/app.js",
            context={}
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

@pytest.mark.asyncio
async def test_analyze_code_with_context():
    """Test code analysis with context"""
    with patch('dragonsec.providers.base.AIProvider._secure_api_key') as mock_secure:
        mock_secure.return_value = "test_key"
        provider = GeminiProvider("test_key")
        code = """
def process_payment(amount, card_number):
    print(f"Processing payment of {amount} with card {card_number}")
    return True
"""
        context = {
            "content": code,
            "imports": ["os", "sys"],
            "functions": ["process_payment"],
            "classes": []
        }
        
        mock_response = AsyncMock()
        mock_response.text = '''
    {
        "vulnerabilities": [
            {
                "type": "sensitive_data_exposure",
                "severity": 8,
                "description": "Card number is logged",
                "line_number": 2,
                "risk_analysis": "High risk of exposing sensitive data",
                "recommendation": "Do not log card numbers"
            }
        ]
    }
    '''
        
        with patch('google.generativeai.GenerativeModel.generate_content_async', 
                  return_value=mock_response):
            results = await provider.analyze_code(code, "payment.py", context)
            assert isinstance(results, dict)
            assert "vulnerabilities" in results
            assert len(results["vulnerabilities"]) > 0

@pytest.mark.asyncio
async def test_merge_results():
    """Test merging semgrep and AI results"""
    with patch('dragonsec.providers.base.AIProvider._secure_api_key') as mock_secure:
        mock_secure.return_value = "test_key"
        provider = GeminiProvider("test_key")
        semgrep_results = [
            {
                "source": "semgrep",
                "type": "sql_injection",
                "severity": 8
            }
        ]
        ai_results = {
            "vulnerabilities": [
                {
                    "source": "ai",
                    "type": "hardcoded_secret",
                    "severity": 7
                }
            ]
        }
        
        merged = provider.merge_results(semgrep_results, ai_results)
        assert len(merged["vulnerabilities"]) == 2
        assert merged["vulnerabilities"][0]["source"] == "semgrep"
        assert merged["vulnerabilities"][1]["source"] == "ai" 
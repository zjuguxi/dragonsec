import pytest
from dragonsec.providers.gemini import GeminiProvider
from unittest.mock import AsyncMock, patch


@pytest.fixture
def gemini_provider():
    with patch("dragonsec.providers.base.AIProvider._secure_api_key") as mock_secure:
        mock_secure.return_value = "test_key"
        provider = GeminiProvider("test_key")
        return provider


@pytest.mark.asyncio
async def test_analyze_code_success(gemini_provider):
    mock_response = AsyncMock()
    mock_response.text = """
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
    """

    mock_generate = AsyncMock(return_value=mock_response)

    with patch(
        "google.generativeai.GenerativeModel.generate_content", new=mock_generate
    ):
        with patch("google.auth.credentials.Credentials") as mock_creds:
            with patch(
                "google.auth._default._get_explicit_environ_credentials",
                return_value=mock_creds,
            ):
                result = await gemini_provider._analyze_with_ai(
                    code="document.write(userInput)", file_path="/test/src/app.js"
                )

                assert result["vulnerabilities"][0]["type"] == "XSS"


@pytest.mark.asyncio
async def test_analyze_code_error(gemini_provider):
    with patch(
        "google.generativeai.GenerativeModel.generate_content_async",
        side_effect=Exception("API Error"),
    ):
        result = await gemini_provider.analyze_code(
            code="test code", file_path="test.py"
        )
        assert result == gemini_provider._get_default_response()


@pytest.mark.asyncio
async def test_analyze_code_with_context():
    """Test code analysis with context"""
    with patch("dragonsec.providers.base.AIProvider._secure_api_key") as mock_secure:
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
            "classes": [],
        }

        mock_response = AsyncMock()
        mock_response.text = """
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
        """

        mock_generate = AsyncMock(return_value=mock_response)

        with patch(
            "google.generativeai.GenerativeModel.generate_content", new=mock_generate
        ):
            with patch("google.auth.credentials.Credentials") as mock_creds:
                with patch(
                    "google.auth._default._get_explicit_environ_credentials",
                    return_value=mock_creds,
                ):
                    results = await provider._analyze_with_ai(
                        code=code, file_path="payment.py"
                    )
                    assert isinstance(results, dict)
                    assert "vulnerabilities" in results
                    assert len(results["vulnerabilities"]) > 0


@pytest.mark.asyncio
async def test_merge_results():
    """Test merging semgrep and AI results"""
    with patch("dragonsec.providers.base.AIProvider._secure_api_key") as mock_secure:
        mock_secure.return_value = "test_key"
        provider = GeminiProvider("test_key")
        semgrep_results = [
            {"source": "semgrep", "type": "sql_injection", "severity": 8}
        ]
        ai_results = {
            "vulnerabilities": [
                {"source": "ai", "type": "hardcoded_secret", "severity": 7}
            ]
        }

        merged = provider.merge_results(semgrep_results, ai_results)
        assert len(merged["vulnerabilities"]) == 2
        assert merged["vulnerabilities"][0]["source"] == "semgrep"
        assert merged["vulnerabilities"][1]["source"] == "ai"


@pytest.mark.asyncio
async def test_gemini_analyze_batch():
    """Test batch analysis with Gemini"""
    provider = GeminiProvider("test_key")
    files = [
        (
            "def unsafe_sql(user_input):\n    return f'SELECT * FROM users WHERE id = {user_input}'",
            "app.py",
        ),
        ("const password = 'hardcoded_secret';", "config.js"),
    ]

    results = await provider.analyze_batch(files)
    assert isinstance(results, list)
    assert len(results) == 2
    assert all("vulnerabilities" in r for r in results)


@pytest.mark.asyncio
async def test_gemini_error_handling():
    """Test error handling in Gemini provider"""
    provider = GeminiProvider("test_key")

    # Test with invalid input
    result = await provider.analyze_code(None, "test.py")
    assert result["vulnerabilities"] == []

    # Test with empty code
    result = await provider.analyze_code("", "test.py")
    assert result["vulnerabilities"] == []

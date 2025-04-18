import pytest
from dragonsec.providers.gemini import GeminiProvider
from unittest.mock import AsyncMock, patch, MagicMock
import json


@pytest.fixture
def gemini_provider():
    provider = GeminiProvider("test_key")
    provider.client = MagicMock() # Mock the client instance
    return provider


@pytest.mark.asyncio
# Add back mock for the now correctly called _parse_response
@patch.object(GeminiProvider, '_parse_response', new_callable=AsyncMock)
async def test_analyze_code_success(mock_parse_response, gemini_provider):
    """Test analyze_code success path, assuming source bug is fixed"""
    # Mock the response object from generate_content
    mock_api_response_object = MagicMock()
    mock_api_response_text = json.dumps({
        "vulnerabilities": [
            {
                "type": "XSS", "severity": 7,
                "description": "Potential XSS vulnerability", "line_number": 25
            }
        ],
        "overall_score": 85,
        "summary": "Found security issues"
    })
    mock_api_response_object.text = mock_api_response_text
    mock_api_response_object.parts = []
    gemini_provider.client.generate_content = AsyncMock(return_value=mock_api_response_object)

    # Configure the mock for _parse_response
    expected_final_result = {
        "vulnerabilities": [{
            "type": "XSS", "severity": 7,
            "description": "Parsed XSS", "line_number": 25, "file": "/test/src/app.js"
        }],
        "overall_score": 80,
        "summary": "Parsed Summary"
    }
    mock_parse_response.return_value = expected_final_result

    # Mock authentication
    with patch("google.auth.credentials.Credentials") as mock_creds:
        with patch(
            "google.auth._default._get_explicit_environ_credentials",
            return_value=mock_creds,
        ):
            # analyze_code should now return the result from the awaited _parse_response
            result = await gemini_provider.analyze_code(
                code="document.write(userInput)", file_path="/test/src/app.js"
            )

            # Assert that the result matches the mocked parsed result
            assert result == expected_final_result
            # Remove the old TODO comment

            # Assert generate_content was called
            gemini_provider.client.generate_content.assert_called_once()
            # Assert _parse_response was awaited and called correctly
            expected_parsed_input = json.loads(mock_api_response_text)
            mock_parse_response.assert_awaited_once_with(expected_parsed_input, "/test/src/app.js")


@pytest.mark.asyncio
async def test_analyze_code_error(gemini_provider):
    """Test analyze_code error handling"""
    gemini_provider.client.generate_content = AsyncMock(side_effect=Exception("API Error"))
    with patch("google.auth.credentials.Credentials") as mock_creds:
        with patch(
            "google.auth._default._get_explicit_environ_credentials",
            return_value=mock_creds,
        ):
            result = await gemini_provider.analyze_code(
                code="test code", file_path="test.py"
            )
            assert result["summary"] == "Failed to analyze code"
            assert result["overall_score"] == 100
            assert len(result["vulnerabilities"]) == 0


@pytest.mark.asyncio
# Add back mock for the now correctly called _parse_response
@patch.object(GeminiProvider, '_parse_response', new_callable=AsyncMock)
async def test_analyze_code_with_context(mock_parse_response, gemini_provider):
    """Test analyze_code with context, assuming source bug is fixed"""
    code = """
def process_payment(amount, card_number):
    logger.info(f"Processing payment of {amount} with card {card_number}")
    return True
"""
    context = {
        "file_type": "python",
        "imports": ["logging", "sys"],
        "functions": ["process_payment"]
    }

    # Mock the generate_content response object with VALID JSON
    mock_api_response_object = MagicMock()
    valid_json_text = json.dumps({"some_key": "some_value"})
    mock_api_response_object.text = valid_json_text
    mock_api_response_object.parts = []
    gemini_provider.client.generate_content = AsyncMock(return_value=mock_api_response_object)

    # Configure the mock for _parse_response
    expected_final_result = {
        "vulnerabilities": [{
            "type": "sensitive_data_exposure", "severity": 7,
            "description": "Parsed mock response", "line_number": 3, "file": "payment.py"
        }],
        "overall_score": 77,
        "summary": "Parsed mock summary"
    }
    mock_parse_response.return_value = expected_final_result

    # Mock authentication
    with patch("google.auth.credentials.Credentials") as mock_creds:
        with patch(
            "google.auth._default._get_explicit_environ_credentials",
            return_value=mock_creds,
        ):
            # analyze_code should now return the result from the awaited _parse_response
            result = await gemini_provider.analyze_code(
                code=code,
                file_path="payment.py",
                context=context
            )

            # Assert final result comes from mocked _parse_response
            assert result == expected_final_result
            # Remove the old TODO comment

            # Assert generate_content was called
            gemini_provider.client.generate_content.assert_called_once()
            # ... check prompt if needed ...

            # Assert _parse_response was awaited and called correctly
            mock_parse_response.assert_awaited_once_with(json.loads(valid_json_text), "payment.py")


@pytest.mark.asyncio
async def test_merge_results(gemini_provider):
    """Test merging semgrep and AI results"""
    semgrep_results = [
        {"source": "semgrep", "type": "sql_injection", "severity": 8}
    ]
    ai_results = {
        "vulnerabilities": [
            {"source": "ai", "type": "hardcoded_secret", "severity": 7}
        ]
    }

    merged = gemini_provider.merge_results(semgrep_results, ai_results)
    assert len(merged["vulnerabilities"]) == 2
    assert merged["vulnerabilities"][0]["source"] == "semgrep"
    assert merged["vulnerabilities"][1]["source"] == "ai"


@pytest.mark.asyncio
@patch.object(GeminiProvider, 'analyze_code')
async def test_gemini_analyze_batch(mock_analyze_code):
    """Test batch analysis with Gemini by mocking analyze_code"""
    provider = GeminiProvider("test_key")
    files = [
        ("code1", "file1.py"),
        ("code2", "file2.js"),
    ]

    # Setup mock analyze_code to return a simple dict
    mock_analyze_code.return_value = {"vulnerabilities": [], "overall_score": 100}

    results = await provider.analyze_batch(files)
    assert isinstance(results, list)
    assert len(results) == len(files)
    # Assert that analyze_code was called for each file in the batch
    assert mock_analyze_code.call_count == len(files)
    # Assert structure of returned items
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

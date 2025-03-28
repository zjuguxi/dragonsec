"""Test Deepseek provider."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from dragonsec.providers.deepseek import DeepseekProvider
import asyncio


@pytest.fixture
def deepseek_provider():
    """Create a test instance of DeepseekProvider"""
    return DeepseekProvider(api_key="test_key")


@pytest.mark.asyncio
async def test_deepseek_specific_response_format(deepseek_provider):
    """Test Deepseek-specific response format handling."""
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content='''{
                    "vulnerabilities": [
                        {
                            "type": "SQL Injection",
                            "severity": "high",
                            "line": 10,
                            "suggestion": "Use parameterized queries"
                        }
                    ],
                    "overall_score": 85
                }'''
            )
        )
    ]

    async def mock_create(*args, **kwargs):
        return mock_response

    with patch.object(deepseek_provider.client.chat.completions, "create", mock_create):
        result = await deepseek_provider.analyze_code("test code")
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["type"] == "SQL Injection"
        assert result["vulnerabilities"][0]["severity"] == "high"
        assert result["overall_score"] == 85


@pytest.mark.asyncio
async def test_deepseek_specific_error_handling(deepseek_provider):
    """Test Deepseek-specific error handling."""
    with patch.object(deepseek_provider.client.chat.completions, "create", side_effect=Exception("API error")):
        result = await deepseek_provider.analyze_code("test code")
        assert len(result["vulnerabilities"]) == 0
        assert result["overall_score"] == 0
        assert "API error" in result["error"]


@pytest.mark.asyncio
async def test_deepseek_specific_timeout_handling(deepseek_provider):
    """Test Deepseek-specific timeout handling."""
    with patch.object(deepseek_provider.client.chat.completions, "create", side_effect=TimeoutError("Request timed out")):
        result = await deepseek_provider.analyze_code("test code")
        assert len(result["vulnerabilities"]) == 0
        assert result["overall_score"] == 0
        assert "Request timed out" in result["error"]


def test_deepseek_specific_init():
    """Test Deepseek specific initialization"""
    provider = DeepseekProvider("test_key")
    assert provider.model == "deepseek/deepseek-coder-33b-instruct"
    assert str(provider.client.base_url).rstrip("/") == "https://openrouter.ai/api/v1"


def test_calculate_security_score(deepseek_provider):
    """Test security score calculation"""
    vulnerabilities = [{"severity": 8}, {"severity": 6}, {"severity": 4}]
    score = deepseek_provider._calculate_security_score(vulnerabilities)
    assert 0 <= score <= 100
    assert score == round(100 - (6 * 10), 2)  # Average severity is 6


def test_empty_vulnerabilities_score(deepseek_provider):
    """Test security score with no vulnerabilities"""
    score = deepseek_provider._calculate_security_score([])
    assert score == 100.0


@pytest.mark.asyncio
async def test_deepseek_rate_limiting():
    """Test rate limiting behavior"""
    provider = DeepseekProvider("test_key")
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content='{"vulnerabilities": [], "overall_score": 100}'
            )
        )
    ]

    async def mock_create(*args, **kwargs):
        return mock_response

    with patch.object(provider.client.chat.completions, "create", mock_create):
        results = await asyncio.gather(
            *[provider.analyze_code("print('test')", f"test_{i}.py") for i in range(3)]
        )
        assert len(results) == 3
        assert all(isinstance(r, dict) for r in results)


@pytest.mark.asyncio
async def test_deepseek_error_recovery():
    """Test error recovery mechanisms"""
    provider = DeepseekProvider("test_key")
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content='{"vulnerabilities": [], "overall_score": 100}'
            )
        )
    ]

    async def mock_create(*args, **kwargs):
        return mock_response

    with patch.object(provider.client.chat.completions, "create", mock_create):
        result = await provider.analyze_code("def broken_func(:", "test.py")
        assert isinstance(result, dict)
        assert "vulnerabilities" in result

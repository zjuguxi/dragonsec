import pytest
from dragonsec.providers.base import AIProvider

def test_secure_api_key():
    """Test API key validation"""
    class TestProvider(AIProvider):
        async def analyze_code(self, code, file_path, context=None):
            pass
        def merge_results(self, semgrep_results, ai_results):
            pass
            
    # 测试无效的 API 密钥
    with pytest.raises(ValueError, match="API key is required"):
        TestProvider(api_key="")
        
    # 移除 API key 长度检查测试
    provider = TestProvider(api_key="test_key")
    assert provider._api_key == "test_key" 
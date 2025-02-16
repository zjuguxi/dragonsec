from abc import ABC, abstractmethod
from typing import Dict, Any, List

class AIProvider(ABC):
    """Base class for AI providers"""
    
    def __init__(self, api_key: str):
        # 不直接存储 API 密钥
        self._api_key = self._secure_api_key(api_key)
    
    def _secure_api_key(self, key: str) -> str:
        """Securely store API key"""
        # 这里可以添加加密或其他安全措施
        if not key:
            raise ValueError("API key is required")
        if len(key) < 32:
            raise ValueError("API key seems too short")
        return key

    @abstractmethod
    async def analyze_code(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Analyze code for security vulnerabilities"""
        pass

    @abstractmethod
    def merge_results(self, semgrep_results: list, ai_results: Dict) -> Dict:
        """Merge semgrep and AI results"""
        pass 
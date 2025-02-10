from abc import ABC, abstractmethod
from typing import Dict, Any

class AIProvider(ABC):
    """Base class for AI providers"""
    
    @abstractmethod
    async def analyze_code(self, code: str, file_path: str, context: Dict = None) -> Dict[str, Any]:
        """Analyze code for security vulnerabilities"""
        pass

    @abstractmethod
    def merge_results(self, semgrep_results: list, ai_results: Dict) -> Dict:
        """Merge semgrep and AI results"""
        pass 
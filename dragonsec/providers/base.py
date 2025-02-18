from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class AIProvider(ABC):
    """Base class for AI providers with common security analysis logic"""
    
    def __init__(self, api_key: str):
        self.required_fields = [
            "type", "severity", "description", "line_number", 
            "file", "risk_analysis", "recommendation", "confidence"
        ]
        self.api_key = self._secure_api_key(api_key)
        self.test_indicators = [
            "/tests/",
            "/test/",
            "/testing/",
            "_test.py",
            "test_.py",
            "tests.py",
            "/fixtures/",
            "/conftest.py"
        ]
        self.base_system_prompt = """
        You are a security expert. Analyze the code for security vulnerabilities.
        Focus ONLY on critical security issues that could lead to:
        1. Remote Code Execution (RCE)
        2. SQL Injection
        3. Command Injection
        4. Insecure Deserialization
        5. Path Traversal with actual file access
        6. Authentication Bypass
        7. Direct Object References (IDOR)
        8. Hardcoded Production Credentials (like API keys, passwords)
        
        DO NOT report:
        - Dependencies or version issues
        - Logging concerns
        - Test file vulnerabilities
        - Configuration best practices
        - Framework-level security patterns
        - Theoretical vulnerabilities
        - Code style issues
        - Business logic issues (like trading strategies)
        - Performance test scripts
        - Example code
        - Demo applications
        - Benchmark scripts
        
        Context awareness:
        - Performance/benchmark scripts are not production code
        - Test scripts are not security issues
        - Trading strategy logic is not a security concern
        - Example code is not production code
        
        Context awareness for deserialization:
        - Internal data files (like cache, system data) are lower risk
        - User-controlled input is high risk
        - Network-sourced data is high risk
        - Command line arguments are medium risk
        - Environment variables are medium risk
        
        For each vulnerability, you MUST:
        1. Confirm it's in production code (not tests/benchmarks/examples)
        2. Provide a specific exploit scenario
        3. Show the attack path
        4. Demonstrate actual impact
        
        Rate confidence based on data source:
        - high: Direct user input, network data, file uploads
        - medium: Command line args, environment vars
        - low: Internal data files, system generated data
        
        Only report high and medium confidence findings.
        
        Respond with valid JSON only, using this structure:
        {
            "vulnerabilities": [
                {
                    "type": "vulnerability type",
                    "severity": 1-10,
                    "description": "detailed description",
                    "line_number": line number,
                    "file": "file path",
                    "risk_analysis": "specific attack scenarios and impact",
                    "recommendation": "concrete fix suggestions",
                    "confidence": "high|medium|low"
                }
            ]
        }
        
        Severity guidelines:
        10: Critical - Remote code execution, data breach
        8-9: High - Authentication bypass, SQL injection
        6-7: Medium - Information disclosure, DoS
        4-5: Low - Limited impact vulnerabilities
        1-3: Info - Minor security concerns
        """
    
    def _secure_api_key(self, api_key: str) -> str:
        """Validate and secure API key"""
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API key is required")
        return api_key
    
    @abstractmethod
    async def _analyze_with_ai(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Provider-specific AI analysis implementation"""
        pass
    
    def _get_default_response(self) -> Dict:
        """Get default response when analysis fails"""
        return {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "Failed to analyze code"
        }
    
    @property
    def system_prompt(self) -> str:
        """Get the system prompt, can be overridden by providers"""
        return self.base_system_prompt
    
    def _standardize_vulnerability(self, vuln: Dict, file_path: str) -> Dict:
        """Standardize vulnerability format"""
        try:
            return {
                "type": str(vuln["type"]).strip(),
                "severity": int(vuln["severity"]),
                "description": str(vuln["description"]).strip(),
                "line_number": int(vuln["line_number"]),
                "file": file_path,
                "risk_analysis": str(vuln["risk_analysis"]).strip(),
                "recommendation": str(vuln["recommendation"]).strip()
            }
        except (KeyError, ValueError) as e:
            logger.error(f"Error standardizing vulnerability: {e}")
            return None
    
    def _calculate_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall security score"""
        if not vulnerabilities:
            return 100
        max_severity = max(v["severity"] for v in vulnerabilities)
        return max(0, 100 - (max_severity * 10))
    
    def _is_test_file(self, file_path: str) -> bool:
        """检查是否为测试文件"""
        normalized_path = file_path.replace("\\", "/").lower()
        return any(indicator in normalized_path for indicator in self.test_indicators)

    async def analyze_code(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Common code analysis implementation"""
        try:
            # 验证输入
            if not code or not isinstance(code, str):
                return self._get_default_response()
            if not file_path or not isinstance(file_path, str):
                return self._get_default_response()
            
            # 跳过测试文件
            if self._is_test_file(file_path):
                logger.info(f"Skipping test file: {file_path}")
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "Skipped test file"
                }
            
            # 调用具体实现
            result = await self._analyze_with_ai(code, file_path, context)
            
            # 标准化结果
            if "vulnerabilities" in result:
                for vuln in result["vulnerabilities"]:
                    vuln["source"] = "ai"
                    vuln["file"] = file_path
            
            return result
            
        except Exception as e:
            logger.error(f"Error in code analysis: {e}")
            return self._get_default_response()
    
    async def deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Common vulnerability deduplication logic"""
        if not vulnerabilities:
            return []
        
        # 基本去重
        unique_vulns = []
        seen = set()
        
        for vuln in vulnerabilities:
            key = (vuln.get("type", ""), vuln.get("file", ""), vuln.get("line_number", 0))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns 
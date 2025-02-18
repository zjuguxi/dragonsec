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
        NEVER report pickle usage in these scenarios (no exceptions):
        1. Data tooling:
           - Data generation scripts
           - Data loading utilities
           - Data preparation tools
           - Data conversion tools
           - Data bundling tools

        2. Internal data:
           - System generated files
           - Configuration files
           - Cache files
           - State files
           - Temporary data

        3. Development tools:
           - Build scripts
           - Setup tools
           - Test utilities
           - Benchmark tools
           - Analysis tools

        ONLY report when ALL of these are true:
        1. External attack surface exists:
           - Public web endpoint
           - Network service
           - Public API
        2. Direct user input:
           - File uploads
           - Network requests
           - User-provided data
        3. No security controls:
           - No input validation
           - No access controls
           - No environment isolation

        If ANY of the DO NOT REPORT conditions are met, 
        the finding should be skipped completely, 
        regardless of other factors.
        
        Rate severity based on context:
        - Critical (9-10): Web/API endpoints accepting user data
        - High (7-8): Network services with external input
        - Medium (5-6): Internal services with indirect exposure
        - Low (3-4): Internal tools with controlled input
        - Info (1-2): Developer utilities with trusted data
        
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

        Context awareness for credentials:
        DO NOT report when:
        - Credentials are passed as parameters
        - Keys are loaded from environment variables
        - Using standard credential management
        - Configuration objects handle secrets
        - Base classes process credentials

        ONLY report when:
        1. Actual secret values are hardcoded
        2. Credentials are stored in plain text
        3. Production keys are committed
        4. Default passwords are used

        For path traversal:
        DO NOT report when:
        - Tool is CLI-only
        - No network exposure
        - Used by developers only
        - Has path validation
        - Uses Path.resolve()
        - Checks against root directory
        - Has logging and error handling

        ONLY report path traversal when:
        1. Exposed via web/API endpoints
        2. Accepts network input
        3. No path validation
        4. Direct file system access
        5. Public facing service

        Rate severity based on exposure:
        - Critical (9-10): Public web/API endpoints
        - High (7-8): Network services
        - Medium (5-6): Web admin tools
        - Low (3-4): Internal CLI tools
        - Info (1-2): Developer utilities
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
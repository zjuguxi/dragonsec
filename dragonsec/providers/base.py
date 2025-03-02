from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging
import json
import os
import re

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
        return """
        You are a security expert. Follow these principles when analyzing code:

        1. Context Understanding:
           - Distinguish between code patterns and actual vulnerabilities
           - Consider the execution context and deployment environment
           - Understand common security design patterns
        
        2. Code Pattern Recognition:
           SAFE patterns:
           - Constructor parameters
           - Environment variables
           - Configuration loading
           - Dependency injection
           
           UNSAFE patterns:
           - String literals containing secrets
           - Inline credentials
           - Bypassed security controls
           - Direct system calls
        
        3. Risk Assessment Framework:
           - Impact: What's the potential damage?
           - Exploitability: How easy to exploit?
           - Context: Is this production code?
           - Controls: What security measures exist?

        Only report issues that meet ALL criteria:
        1. Confirmed vulnerability (not just a pattern)
        2. Real security impact
        3. Actual exposure risk
        4. Missing security controls
        """
    
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

    def _prepare_prompt(self, code: str, context: Dict = None) -> str:
        return f"""
        Examples of what NOT to flag:
        ```python
        def __init__(self, api_key: str):
            self.api_key = api_key  # SAFE: Parameter injection
        
        def connect(self, password=os.getenv("DB_PASS")):
            self.db.connect(password)  # SAFE: Environment variable
        ```
        
        Examples of what to flag:
        ```python
        PASSWORD = "admin123"  # UNSAFE: Hardcoded credential
        api_key = "sk-1234567890abcdef"  # UNSAFE: Actual API key
        ```
        
        Code to analyze:
        {code}
        
        Context:
        {json.dumps(context) if context else 'No additional context'}
        """ 

    def _get_decision_prompt(self) -> str:
        return """
        For each potential issue, follow this decision tree:

        1. Is it a code pattern?
           Yes -> Is it a security pattern?
                 Yes -> SAFE
                 No  -> Continue
           No  -> Continue
        
        2. Is it actual data?
           Yes -> Is it sensitive?
                 Yes -> Is it production?
                      Yes -> REPORT
                      No  -> SAFE
                 No  -> SAFE
           No  -> SAFE
        """ 

    def _get_context_categories(self) -> str:
        return """
        Security Context Categories:

        1. Infrastructure Code
           - Configuration management
           - Deployment scripts
           - Build tools
        
        2. Application Code
           - Business logic
           - API endpoints
           - Data processing
        
        3. Test Code
           - Unit tests
           - Integration tests
           - Benchmarks
        
        Adjust severity and reporting based on category.
        """ 

    async def filter_false_positives(self, scan_result: Dict, file_contents: Dict = None) -> Dict:
        """Filter false positives from scan results
        
        Args:
            scan_result: The complete scan result with vulnerabilities
            file_contents: Optional dict mapping file paths to their contents
            
        Returns:
            Filtered scan result
        """
        try:
            # 如果没有漏洞，直接返回
            if not scan_result.get("vulnerabilities"):
                return scan_result
            
            # 构建提示
            prompt = self._build_filter_prompt(scan_result, file_contents)
            
            # 调用 API
            response = await self._call_api(prompt)
            
            # 解析响应
            try:
                # 查找 JSON 块
                json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                    # 修复常见的 JSON 格式问题
                    json_str = self._fix_json_format(json_str)
                    try:
                        filtered_result = json.loads(json_str)
                        
                        # 验证结果格式
                        if "vulnerabilities" in filtered_result and isinstance(filtered_result["vulnerabilities"], list):
                            # 更新分数和摘要
                            vulns = filtered_result["vulnerabilities"]
                            if vulns:
                                avg_severity = sum(v.get("severity", 5) for v in vulns) / len(vulns)
                                filtered_result["overall_score"] = self._calculate_security_score(vulns)
                                filtered_result["summary"] = f"Found {len(vulns)} potential issues after filtering false positives"
                            else:
                                filtered_result["overall_score"] = 100
                                filtered_result["summary"] = "No security issues found after filtering false positives"
                            
                            # 保留原始元数据
                            if "metadata" in scan_result:
                                filtered_result["metadata"] = scan_result["metadata"]
                                # 添加过滤信息
                                filtered_result["metadata"]["filtered"] = True
                                filtered_result["metadata"]["original_vulnerabilities"] = len(scan_result.get("vulnerabilities", []))
                                filtered_result["metadata"]["filtered_vulnerabilities"] = len(vulns)
                            
                            return filtered_result
                    except json.JSONDecodeError:
                        logger.error("Failed to parse filtered result JSON")
            except Exception as e:
                logger.error(f"Error parsing filter response: {e}")
            
            # 如果解析失败，返回原始结果
            return scan_result
            
        except Exception as e:
            logger.error(f"Error filtering false positives: {e}")
            return scan_result

    def _build_filter_prompt(self, scan_result: Dict, file_contents: Dict = None) -> str:
        """Build prompt for filtering false positives
        
        Args:
            scan_result: The complete scan result with vulnerabilities
            file_contents: Optional dict mapping file paths to their contents
            
        Returns:
            Prompt for filtering false positives
        """
        # 获取漏洞列表
        vulnerabilities = scan_result.get("vulnerabilities", [])
        
        # 构建提示
        prompt = f"""You are a security expert reviewing scan results for false positives. 
I have a security scan result with {len(vulnerabilities)} potential vulnerabilities.
Please review each vulnerability and determine if it's a real issue or a false positive.

IMPORTANT: Your response MUST be in English only. Do not use any other language.

Here are the vulnerabilities:

"""
        
        # 添加每个漏洞的详细信息
        for i, vuln in enumerate(vulnerabilities):
            prompt += f"Vulnerability #{i+1}:\n"
            prompt += f"Type: {vuln.get('type', 'Unknown')}\n"
            prompt += f"Severity: {vuln.get('severity', 'Unknown')}\n"
            prompt += f"File: {vuln.get('file', 'Unknown')}\n"
            prompt += f"Line: {vuln.get('line_number', 'Unknown')}\n"
            prompt += f"Description: {vuln.get('description', 'Unknown')}\n"
            prompt += f"Risk Analysis: {vuln.get('risk_analysis', 'Unknown')}\n"
            prompt += f"Recommendation: {vuln.get('recommendation', 'Unknown')}\n\n"
        
        # 如果有文件内容，添加相关文件的内容
        if file_contents:
            prompt += "Here are the relevant file contents:\n\n"
            
            # 获取漏洞中提到的所有文件
            vuln_files = set()
            for vuln in vulnerabilities:
                file_path = vuln.get('file')
                if file_path and file_path in file_contents:
                    vuln_files.add(file_path)
            
            # 添加每个文件的内容
            for file_path in vuln_files:
                prompt += f"File: {file_path}\n```\n{file_contents[file_path]}\n```\n\n"
        
        # 添加指导
        prompt += """Please analyze each vulnerability and determine if it's a real issue or a false positive.
Common reasons for false positives include:
1. Security terms mentioned in comments, strings, or variable names
2. Code that looks similar to vulnerable patterns but is actually secure
3. Test code or example code that is not actually used in production
4. Misinterpretation of code functionality

Return a JSON object with only the real vulnerabilities (remove false positives):

```json
{
  "vulnerabilities": [
    // Only include real vulnerabilities here, remove false positives
  ]
}
```

If all vulnerabilities are false positives, return an empty array for "vulnerabilities".
Remember: Your response MUST be in English only.
"""
        
        return prompt

    def _fix_json_format(self, json_str: str) -> str:
        """Fix common JSON format issues"""
        # 修复缺少引号的键
        json_str = re.sub(r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', json_str)
        
        # 修复单引号
        json_str = json_str.replace("'", '"')
        
        # 修复尾部逗号
        json_str = re.sub(r',\s*}', '}', json_str)
        json_str = re.sub(r',\s*]', ']', json_str)
        
        # 修复缺少值的情况
        json_str = re.sub(r':\s*,', ': null,', json_str)
        json_str = re.sub(r':\s*}', ': null}', json_str)
        
        return json_str
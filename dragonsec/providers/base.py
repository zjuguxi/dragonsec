from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable, TypeVar, cast
import logging
import json
import os
import re
import time
import functools
from datetime import datetime

logger = logging.getLogger(__name__)

# 定义类型变量用于装饰器
T = TypeVar('T')


def create_error_response(error_msg: str, score: int = 100, include_metadata: bool = False) -> Dict:
    """创建通用的错误响应

    Args:
        error_msg: 错误消息
        score: 安全分数，默认为 100
        include_metadata: 是否包含元数据

    Returns:
        错误响应字典
    """
    response = {
        "vulnerabilities": [],
        "overall_score": score,
        "summary": error_msg,
        "error": error_msg
    }

    if include_metadata:
        response["metadata"] = {
            "files_scanned": 0,
            "skipped_files": 0,
            "scan_duration": 0,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": error_msg
        }

    return response


def handle_api_errors(func: Callable[..., T]) -> Callable[..., T]:
    """装饰器：处理 API 调用错误

    Args:
        func: 要装饰的函数

    Returns:
        装饰后的函数
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            # 获取类实例（self）
            instance = args[0] if args else None

            # 记录错误
            logger.error(f"API call error in {func.__name__}: {e}")

            # 如果实例有 _get_default_response 方法，使用它
            if instance and hasattr(instance, '_get_default_response'):
                return instance._get_default_response()

            # 否则返回通用错误响应
            return create_error_response(f"API call failed: {str(e)}")

    return cast(Callable[..., T], wrapper)


class AIProvider(ABC):
    """Base class for AI providers with common security analysis logic"""

    # 安全相关术语集合
    SECURITY_TERMS = {
        "crypto",
        "security",
        "auth",
        "jwt",
        "bcrypt",
        "hash",
        "password",
        "ssl",
        "tls",
        "https",
        "oauth",
    }

    def _fix_json_format(self, json_str: str) -> str:
        """Fix common JSON format issues"""
        return fix_json_format(json_str)
    
    def __init__(self, api_key: str):
        """Initialize the AI provider

        Args:
            api_key: API key for the provider
        """
        # 调用 ABC 的 __init__ 方法 - 不传递参数
        super().__init__()

        self.required_fields = [
            "type",
            "severity",
            "description",
            "line_number",
            "file",
            "risk_analysis",
            "recommendation",
            "confidence",
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
            "/conftest.py",
        ]
        
        # 添加基础系统提示词
        self.base_system_prompt = """
        You are a security expert analyzing code for vulnerabilities.
        Focus ONLY on critical security issues that could lead to:
        1. Remote Code Execution (RCE)
        2. SQL Injection
        3. Command Injection
        4. Insecure Deserialization
        5. Path Traversal with actual file access
        6. Authentication Bypass
        7. Direct Object References (IDOR)
        8. Hardcoded Production Credentials
        
        DO NOT report:
        - Dependencies or version issues
        - Logging concerns
        - Test file vulnerabilities
        - Configuration best practices
        - Framework-level security patterns
        - Theoretical vulnerabilities
        - Code style issues
        - Business logic issues
        - Performance test scripts
        """

    def _secure_api_key(self, api_key: str) -> str:
        """Secure API key handling

        Args:
            api_key: The API key to secure

        Returns:
            The secured API key
        """
        if not api_key:
            logger.warning("No API key provided")
            return ""

        # Remove any whitespace
        api_key = api_key.strip()

        # Basic validation
        if len(api_key) < 3:  # Minimal validation for tests
            logger.warning("API key seems too short")

        return api_key

    @abstractmethod
    async def _analyze_with_ai(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
        """Provider-specific AI analysis implementation"""
        pass

    def _get_default_response(self) -> Dict:
        """Get default response when analysis fails"""
        return create_error_response("Failed to analyze code")

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
                "recommendation": str(vuln["recommendation"]).strip(),
            }
        except (KeyError, ValueError) as e:
            logger.error(f"Error standardizing vulnerability: {e}")
            return None

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall security score based on vulnerabilities

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Security score from 0 to 100
        """
        if not vulnerabilities:
            return 100

        score = 100
        severity_weights = {
            range(9, 11): 15,  # Critical: -15 points each
            range(7, 9): 10,   # High: -10 points each
            range(4, 7): 5,    # Medium: -5 points each
            range(1, 4): 2,    # Low: -2 points each
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", 5)
            for severity_range, weight in severity_weights.items():
                if severity in severity_range:
                    score -= weight
                    break

        return max(0, min(100, score))

    def _is_test_file(self, file_path: str) -> bool:
        """检查是否为测试文件"""
        normalized_path = file_path.replace("\\", "/").lower()
        return any(indicator in normalized_path for indicator in self.test_indicators)

    async def analyze_code(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
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
                    "summary": "Skipped test file",
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

    async def deduplicate_vulnerabilities(
        self, vulnerabilities: List[Dict]
    ) -> List[Dict]:
        """Common vulnerability deduplication logic"""
        if not vulnerabilities:
            return []

        # 基本去重
        unique_vulns = []
        seen = set()

        for vuln in vulnerabilities:
            key = (
                vuln.get("type", ""),
                vuln.get("file", ""),
                vuln.get("line_number", 0),
            )
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

    async def filter_false_positives(
        self, scan_result: Dict, file_contents: Dict = None
    ) -> Dict:
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
                json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                    # 修复常见的 JSON 格式问题
                    json_str = self._fix_json_format(json_str)
                    try:
                        filtered_result = json.loads(json_str)

                        # 验证结果格式
                        if "vulnerabilities" in filtered_result and isinstance(
                            filtered_result["vulnerabilities"], list
                        ):
                            # 更新分数和摘要
                            vulns = filtered_result["vulnerabilities"]
                            if vulns:
                                avg_severity = sum(
                                    v.get("severity", 5) for v in vulns
                                ) / len(vulns)
                                filtered_result["overall_score"] = (
                                    self._calculate_security_score(vulns)
                                )
                                filtered_result["summary"] = (
                                    f"Found {len(vulns)} potential issues after filtering false positives"
                                )
                            else:
                                filtered_result["overall_score"] = 100
                                filtered_result["summary"] = (
                                    "No security issues found after filtering false positives"
                                )

                            # 保留原始元数据
                            if "metadata" in scan_result:
                                filtered_result["metadata"] = scan_result["metadata"]
                                # 添加过滤信息
                                filtered_result["metadata"]["filtered"] = True
                                filtered_result["metadata"][
                                    "original_vulnerabilities"
                                ] = len(scan_result.get("vulnerabilities", []))
                                filtered_result["metadata"][
                                    "filtered_vulnerabilities"
                                ] = len(vulns)

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

    def _build_filter_prompt(
        self, scan_result: Dict, file_contents: Dict = None
    ) -> str:
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
                file_path = vuln.get("file")
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

    async def deep_audit_vulnerabilities(
        self, scan_result: Dict, file_contents: Dict = None
    ) -> Dict:
        """Deep audit of vulnerabilities for detailed analysis

        Args:
            scan_result: The scan result with confirmed vulnerabilities
            file_contents: Optional dict mapping file paths to their contents

        Returns:
            Dict with detailed vulnerability analysis
        """
        try:
            # 如果没有漏洞，直接返回
            if not scan_result.get("vulnerabilities"):
                return scan_result

            # 构建提示
            prompt = self._build_deep_audit_prompt(scan_result, file_contents)

            # 调用 API
            response = await self._call_api(prompt)

            # 解析响应
            try:
                # 查找 JSON 块
                json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                    # 修复常见的 JSON 格式问题
                    json_str = self._fix_json_format(json_str)
                    try:
                        audit_result = json.loads(json_str)

                        # 验证结果格式
                        if "vulnerabilities" in audit_result and isinstance(
                            audit_result["vulnerabilities"], list
                        ):
                            # 更新漏洞详细信息
                            scan_result["vulnerabilities"] = audit_result[
                                "vulnerabilities"
                            ]

                            # 添加深度分析元数据
                            if "metadata" not in scan_result:
                                scan_result["metadata"] = {}
                            scan_result["metadata"]["deep_audited"] = True
                            scan_result["metadata"]["audit_timestamp"] = time.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )

                            return scan_result
                    except json.JSONDecodeError:
                        logger.error("Failed to parse deep audit result JSON")
            except Exception as e:
                logger.error(f"Error parsing deep audit response: {e}")

            # 如果解析失败，返回原始结果
            return scan_result

        except Exception as e:
            logger.error(f"Error in deep audit: {e}")
            return scan_result

    def _build_deep_audit_prompt(
        self, scan_result: Dict, file_contents: Dict = None
    ) -> str:
        """Build prompt for deep vulnerability audit

        Args:
            scan_result: The scan result with confirmed vulnerabilities
            file_contents: Optional dict mapping file paths to their contents

        Returns:
            Prompt for deep vulnerability audit
        """
        # 获取漏洞列表
        vulnerabilities = scan_result.get("vulnerabilities", [])

        # 构建提示
        prompt = f"""You are a senior security expert performing a deep analysis of confirmed vulnerabilities.
I have {len(vulnerabilities)} confirmed security vulnerabilities that need detailed analysis.

For each vulnerability, provide a comprehensive analysis including:
1. Exploit Difficulty (1-10, where 10 is most difficult)
2. Business Impact (Critical/High/Medium/Low)
3. Fix Priority (P0/P1/P2/P3)
4. Required Attack Prerequisites
5. Potential Attack Scenarios
6. Detailed Fix Recommendations
7. Security Best Practices
8. Similar Vulnerability Prevention

Here are the vulnerabilities:

"""

        # 添加每个漏洞的详细信息
        for i, vuln in enumerate(vulnerabilities):
            prompt += f"\nVulnerability #{i+1}:\n"
            prompt += f"Type: {vuln.get('type', 'Unknown')}\n"
            prompt += f"Severity: {vuln.get('severity', 'Unknown')}\n"
            prompt += f"File: {vuln.get('file', 'Unknown')}\n"
            prompt += f"Line: {vuln.get('line_number', 'Unknown')}\n"
            prompt += f"Description: {vuln.get('description', 'Unknown')}\n"

            # 如果有文件内容，添加相关代码片段
            file_path = vuln.get("file")
            if file_contents and file_path in file_contents:
                line_number = vuln.get("line_number", 0)
                if line_number > 0:
                    lines = file_contents[file_path].splitlines()
                    start_line = max(0, line_number - 5)
                    end_line = min(len(lines), line_number + 5)
                    code_context = "\n".join(lines[start_line:end_line])
                    prompt += f"\nRelevant Code Context:\n```\n{code_context}\n```\n"

        # 添加响应格式指导
        prompt += """
Please analyze each vulnerability and provide detailed information in the following JSON format:

```json
{
  "vulnerabilities": [
    {
      "type": "original-type",
      "severity": original-severity,
      "file": "original-file",
      "line_number": original-line-number,
      "description": "original-description",
      "exploit_difficulty": 1-10,
      "business_impact": "Critical/High/Medium/Low",
      "fix_priority": "P0/P1/P2/P3",
      "attack_prerequisites": "detailed prerequisites",
      "attack_scenarios": ["scenario1", "scenario2"],
      "detailed_fix": "step by step fix guide",
      "best_practices": ["practice1", "practice2"],
      "prevention_tips": ["tip1", "tip2"]
    }
  ]
}
```

Focus on providing actionable insights and practical recommendations.
"""

        return prompt

def fix_json_format(json_str: str) -> str:
    """修复常见的 JSON 格式问题

    Args:
        json_str: 要修复的 JSON 字符串

    Returns:
        修复后的 JSON 字符串
    """
    try:
        # 首先尝试直接解析
        json.loads(json_str)
        return json_str
    except json.JSONDecodeError:
        # 如果解析失败，尝试修复
        pass

    # 修复缺少引号的键
    json_str = re.sub(
        r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', json_str
    )

    # 修复单引号
    json_str = json_str.replace("'", '"')

    # 修复尾部逗号
    json_str = re.sub(r",\s*}", "}", json_str)
    json_str = re.sub(r",\s*]", "]", json_str)

    # 修复缺少值的情况
    json_str = re.sub(r":\s*,", ": null,", json_str)
    json_str = re.sub(r":\s*}", ": null}", json_str)

    # 修复多余的逗号
    json_str = re.sub(r",\s*,", ",", json_str)

    # 修复缺少逗号的情况
    json_str = re.sub(r"}\s*{", "},{", json_str)
    json_str = re.sub(r"}\s*\[", "},[", json_str)
    json_str = re.sub(r"]\s*\[", "],[", json_str)

    # 修复不匹配的引号
    open_quotes = []
    in_string = False
    escaped = False
    for i, char in enumerate(json_str):
        if char == "\\":
            escaped = not escaped
        elif char == '"' and not escaped:
            in_string = not in_string
            if in_string:
                open_quotes.append(i)
            else:
                if open_quotes:
                    open_quotes.pop()
        else:
            escaped = False

    # 闭合所有未闭合的引号
    for i in reversed(open_quotes):
        next_delimiter = json_str.find(",", i)
        next_brace = json_str.find("}", i)
        next_bracket = json_str.find("]", i)

        delimiters = [
            d for d in [next_delimiter, next_brace, next_bracket] if d != -1
        ]
        if delimiters:
            next_pos = min(delimiters)
            json_str = json_str[:next_pos] + '"' + json_str[next_pos:]
        else:
            json_str += '"'

    # 尝试解析修复后的 JSON
    try:
        json.loads(json_str)
        return json_str
    except json.JSONDecodeError as e:
        # 如果仍然失败，尝试提取 JSON 结构
        try:
            start = json_str.find("{")
            end = json_str.rfind("}")

            if start != -1 and end != -1 and start < end:
                json_obj = json_str[start : end + 1]
                json_obj = re.sub(
                    r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:",
                    r'\1"\2":',
                    json_obj,
                )

                try:
                    json.loads(json_obj)
                    return json_obj
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        # 如果所有尝试都失败，返回原始字符串
        logger.warning("Failed to fix JSON format")
        return json_str


def extract_json_from_text(text: str) -> str:
    """从文本中提取 JSON

    Args:
        text: 包含 JSON 的文本

    Returns:
        提取的 JSON 字符串
    """
    # 尝试从代码块中提取 JSON
    json_match = re.search(r"```json\s*([\s\S]*?)\s*```", text)
    if not json_match:
        json_match = re.search(r"```\s*([\s\S]*?)\s*```", text)

    if json_match:
        return json_match.group(1)

    # 如果没有代码块，尝试直接提取 JSON 对象
    json_start = text.find("{")
    json_end = text.rfind("}")

    if json_start != -1 and json_end != -1 and json_start < json_end:
        return text[json_start:json_end + 1]

    # 如果没有找到 JSON，返回原始文本
    return text


def parse_llm_response(response: str, file_path: str = None) -> Dict:
    """解析 LLM 响应

    Args:
        response: LLM 响应文本
        file_path: 可选的文件路径，用于添加到漏洞信息中

    Returns:
        解析后的响应字典
    """
    try:
        # 提取 JSON
        json_str = extract_json_from_text(response)

        # 修复 JSON 格式
        json_str = fix_json_format(json_str)

        # 解析 JSON
        try:
            result = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response")
            return create_error_response("Failed to parse response")

        # 标准化结果
        if not isinstance(result, dict):
            result = {"vulnerabilities": []}

        if "vulnerabilities" not in result:
            result["vulnerabilities"] = []

        # 标准化漏洞信息
        for vuln in result["vulnerabilities"]:
            if file_path and "file" not in vuln:
                vuln["file"] = file_path

            vuln["type"] = vuln.get("type", "Unknown")
            vuln["severity"] = int(vuln.get("severity", 5))
            vuln["description"] = vuln.get("description", "No description")
            vuln["line_number"] = int(vuln.get("line_number", 0))
            vuln["risk_analysis"] = vuln.get("risk_analysis", "No risk analysis")
            vuln["recommendation"] = vuln.get("recommendation", "No recommendation")
            vuln["confidence"] = vuln.get("confidence", "medium")

        # 添加摘要
        if "summary" not in result:
            if result["vulnerabilities"]:
                result["summary"] = f"Found {len(result['vulnerabilities'])} potential security issues"
            else:
                result["summary"] = "No security issues found"

        # 添加安全评分
        if "overall_score" not in result and "vulnerabilities" in result:
            result["overall_score"] = 100
            if result["vulnerabilities"]:
                avg_severity = sum(v.get("severity", 5) for v in result["vulnerabilities"]) / len(result["vulnerabilities"])
                result["overall_score"] = max(0, 100 - (avg_severity * 10))

        return result

    except Exception as e:
        logger.error(f"Error parsing response: {e}")
        return create_error_response(f"Error parsing response: {str(e)}")

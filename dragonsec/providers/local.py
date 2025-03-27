"""Local model provider for DragonSec using Ollama"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
import asyncio
from pathlib import Path
import os
import random
import re
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from .base import AIProvider  # 改为继承自基类
import hashlib

logger = logging.getLogger(__name__)


class LocalProvider(AIProvider):
    """Local model provider using Ollama"""

    def __init__(
        self,
        api_key: str = None,
        base_url: str = "http://localhost:11434",
        model: str = "deepseek-r1:1.5b",
    ):
        """Initialize local provider

        Args:
            api_key: Not used for local provider
            base_url: URL for Ollama API
            model: Model name to use
        """
        # 调用基类初始化，但不传递 API key
        super().__init__(None)  # 传递 None 作为 API key

        # 设置本地模式特有的属性
        self.base_url = base_url
        self.model = model
        self.provider_name = "local"

        # 设置提示模板
        self._system_prompt = """You are a security expert analyzing code for vulnerabilities.
Your task is to identify security issues, assess their severity, and provide recommendations."""

        # 设置其他参数
        self.max_tokens = 4096
        self.temperature = 0.1

        logger.info(f"Initialized LocalProvider with model {model} at {base_url}")

    def _secure_api_key(self, api_key: str) -> str:
        """Override to make API key optional for local provider"""
        # 本地模式不需要 API key
        return None

    @property
    def system_prompt(self) -> str:
        """Get system prompt"""
        return self._system_prompt

    def is_server_available(self) -> bool:
        """Check if local model server is available"""
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": "hello", "stream": False},
                timeout=5,
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
    )
    async def _call_api(self, prompt: str) -> str:
        """Call Ollama API

        Args:
            prompt: Prompt to send to API

        Returns:
            Response from API
        """
        try:
            logger.info("==== Sending request to local model ====")
            logger.info(f"Prompt length: {len(prompt)} characters")

            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "top_p": 0.9, "top_k": 40},
                },
                timeout=120,  # 增加超时时间到2分钟
            )

            if response.status_code != 200:
                logger.error(
                    f"Error calling local model API: {response.status_code} {response.text}"
                )
                raise Exception(
                    f"Error calling local model API: {response.status_code} {response.text}"
                )

            result = response.json()
            response_text = result.get("response", "")

            logger.info("==== Raw response ====")
            logger.info(f"Response length: {len(response_text)}")
            logger.info(f"First 500 characters:\n{response_text[:500]}")
            logger.info(f"Last 500 characters:\n{response_text[-500:]}")

            return response_text

        except Exception as e:
            logger.error(f"Error calling local model API: {e}")
            raise

    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file"""
        # Always analyze files in 'fixtures' directory, even if they're in a test directory
        if "/fixtures/" in file_path or "\\fixtures\\" in file_path:
            return False

        # Check if file is in a test directory
        test_dir_patterns = ["test", "tests", "testing"]
        path_parts = Path(file_path).parts
        for part in path_parts:
            if any(pattern in part.lower() for pattern in test_dir_patterns):
                # But don't skip if it's in fixtures
                if "fixtures" not in part.lower():
                    return True

        # Check if file name contains test
        file_name = os.path.basename(file_path)
        return "test" in file_name.lower() and "fixtures" not in file_path.lower()

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if a file should be skipped based on its type

        Args:
            file_path: Path to the file

        Returns:
            True if the file should be skipped, False otherwise
        """
        # 获取文件名和扩展名
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()

        # 跳过非代码文件
        non_code_files = [
            "LICENSE",
            "README.md",
            "PKG-INFO",
            "MANIFEST.in",
            "requirements.txt",
        ]
        if file_name in non_code_files:
            logger.info(f"Skipping non-code file: {file_path}")
            return True

        # 跳过某些扩展名的文件
        non_code_exts = [
            ".md",
            ".txt",
            ".rst",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".ini",
        ]
        if ext in non_code_exts:
            logger.info(f"Skipping file with non-code extension: {file_path}")
            return True

        return False

    def _is_english(self, text: str) -> bool:
        """Check if text is primarily in English

        Args:
            text: Text to check

        Returns:
            True if text is primarily in English
        """
        if not text:
            return True

        # 只有当非ASCII字符比例非常高时才认为不是英文
        # 这允许一些非英文字符出现在描述中
        non_ascii_chars = sum(1 for c in text if ord(c) > 127)
        non_ascii_ratio = non_ascii_chars / len(text)

        # 如果非ASCII字符比例小于30%，认为是英文
        return non_ascii_ratio < 0.3

    def _post_process_vulnerabilities(
        self, vulnerabilities: List[Dict], file_path: str
    ) -> List[Dict]:
        """Post-process vulnerabilities to remove false positives

        Args:
            vulnerabilities: List of vulnerabilities
            file_path: Path to file being analyzed

        Returns:
            List of post-processed vulnerabilities
        """
        if not vulnerabilities:
            return []

        # 过滤后的漏洞列表
        filtered_vulns = []

        for vuln in vulnerabilities:
            # 跳过非英文描述
            description = vuln.get("description", "")
            if not self._is_english(description):
                logger.warning(
                    f"Skipping non-English vulnerability: {description[:50]}..."
                )
                continue

            # 添加源信息
            vuln["source"] = "ai"

            # 添加文件信息（如果缺失）
            if "file" not in vuln and file_path:
                vuln["file"] = file_path
            if "file_name" not in vuln and file_path:
                vuln["file_name"] = (
                    os.path.basename(file_path) if file_path else "unknown"
                )

            # 添加到过滤后的列表
            filtered_vulns.append(vuln)

        return filtered_vulns

    def _build_prompt(self, code: str, file_path: str = None) -> str:
        """Build prompt for local model"""
        # 获取文件扩展名
        ext = os.path.splitext(file_path)[1].lower() if file_path else ""

        # 根据文件扩展名确定语言
        language = "unknown"
        if ext in [".py", ".pyw"]:
            language = "Python"
        elif ext in [".js", ".jsx"]:
            language = "JavaScript"
        elif ext in [".ts", ".tsx"]:
            language = "TypeScript"
        elif ext in [".java"]:
            language = "Java"
        elif ext in [".go"]:
            language = "Go"
        elif ext in [".php"]:
            language = "PHP"
        elif ext in [".rb"]:
            language = "Ruby"
        elif ext in [".c", ".cpp", ".cc", ".h", ".hpp"]:
            language = "C/C++"
        elif ext in [".cs"]:
            language = "C#"
        elif ext in [".swift"]:
            language = "Swift"
        elif file_path and os.path.basename(file_path) == "Dockerfile":
            language = "Dockerfile"

        # 添加文件类型特定的指导
        file_type_guidance = ""
        if file_path:
            file_name = os.path.basename(file_path)
            if file_name == "LICENSE":
                file_type_guidance = "This is a LICENSE file, which typically contains only legal text and no executable code. It should not contain any security vulnerabilities."
            elif file_name.endswith(".md") or file_name.endswith(".rst"):
                file_type_guidance = "This is a documentation file, not executable code. It should not contain any security vulnerabilities unless it includes code examples that would be copied directly into production."
            elif "config" in file_name.lower():
                file_type_guidance = "This is a configuration file. Configuration settings themselves are not vulnerabilities unless they explicitly set insecure defaults."
            elif file_name == "PKG-INFO" or file_name.endswith(".egg-info"):
                file_type_guidance = "This is a package metadata file, not executable code. It should not contain any security vulnerabilities."

        # 构建提示
        prompt = f"""
{self.system_prompt}

I need you to analyze the following {language} code for security vulnerabilities:

{file_type_guidance}

```{language}
{code}
```

Please identify any ACTUAL security issues, including but not limited to:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Command Injection
4. Path Traversal
5. Insecure Deserialization
6. Hardcoded Credentials
7. Sensitive Data Exposure
8. Insecure Cryptography
9. Improper Access Control
10. Race Conditions

IMPORTANT:
- Only report REAL vulnerabilities, not just mentions of security terms in comments, strings, or variable names. For example, if the code contains a string like "sql_injection_example", this is NOT a vulnerability.
- Configuration settings themselves are not vulnerabilities unless they explicitly set insecure defaults.
- Your response MUST be in English only. Do not use any other language.
- Do not report theoretical vulnerabilities or issues that require unrealistic scenarios to exploit.
- Do not report vulnerabilities in test files, example code, or documentation.
- Focus on actual security issues that could be exploited in a real-world scenario.

For each vulnerability, provide:
- Type of vulnerability
- Severity (1-10, where 10 is most severe)
- Line number where the issue occurs
- Description of the vulnerability
- Risk analysis
- Recommendation for fixing

Format your response as JSON:
```json
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability-type",
      "severity": 8,
      "line_number": 42,
      "description": "Description of the vulnerability",
      "risk_analysis": "Analysis of the risk",
      "recommendation": "How to fix it"
    }}
  ],
  "overall_score": 70,
  "summary": "Brief summary of findings"
}}
```

If no vulnerabilities are found, return an empty array for "vulnerabilities" and set "overall_score" to 100.
"""

        return prompt

    def _parse_response(self, response: str, file_path: str = None) -> Dict:
        """Parse response from AI model

        Args:
            response: Response from AI model
            file_path: Path to file being analyzed

        Returns:
            Dict with parsed response
        """
        try:
            # 尝试直接解析 JSON
            try:
                result = json.loads(response)
                logger.debug("Response parsed as JSON")
                return result
            except json.JSONDecodeError:
                # 如果直接解析失败，尝试提取 JSON 部分
                pass

            # 尝试从响应中提取 JSON
            json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
            if not json_match:
                json_match = re.search(r"```\s*([\s\S]*?)\s*```", response)

            if json_match:
                json_str = json_match.group(1)
                # 修复常见的 JSON 格式问题
                json_str = self._fix_json_format(json_str)

                try:
                    result = json.loads(json_str)
                    logger.debug("JSON extracted from code block")
                    return result
                except json.JSONDecodeError as e:
                    logger.warning(f"Error parsing JSON from code block: {e}")

            # 如果无法提取 JSON，尝试使用正则表达式提取漏洞
            vulnerabilities = []

            # 提取漏洞类型
            vuln_types = re.findall(
                r"(?:vulnerability|issue)(?:\s+type)?[:\s]+([A-Za-z\s_]+)",
                response,
                re.IGNORECASE,
            )

            # 提取严重性
            severities = re.findall(r"severity[:\s]+(\d+)", response, re.IGNORECASE)

            # 提取描述
            descriptions = re.findall(
                r"description[:\s]+(.*?)(?:\n|$)", response, re.IGNORECASE
            )

            # 创建漏洞对象
            for i in range(max(len(vuln_types), len(severities), len(descriptions))):
                vuln = {}

                if i < len(vuln_types):
                    vuln["type"] = vuln_types[i].strip()
                else:
                    vuln["type"] = "Unknown"

                if i < len(severities):
                    try:
                        vuln["severity"] = int(severities[i])
                    except ValueError:
                        vuln["severity"] = 5  # 默认中等严重性
                else:
                    vuln["severity"] = 5

                if i < len(descriptions):
                    vuln["description"] = descriptions[i].strip()
                else:
                    vuln["description"] = "No description provided"

                # 添加文件信息
                if file_path is not None:  # 添加对 None 的检查
                    vuln["file"] = file_path
                    vuln["file_name"] = os.path.basename(file_path)
                else:
                    vuln["file"] = "unknown"
                    vuln["file_name"] = "unknown"

                vulnerabilities.append(vuln)

            if vulnerabilities:
                logger.debug(
                    f"Extracted {len(vulnerabilities)} vulnerabilities using regex"
                )
                return {
                    "vulnerabilities": vulnerabilities,
                    "overall_score": 50,  # 默认中等分数
                    "summary": "Vulnerabilities extracted from unstructured response",
                }

            # 如果所有方法都失败，返回默认响应
            logger.warning("Could not parse response, returning default")
            return self._get_default_response()

        except Exception as e:
            logger.error(f"Error parsing response: {e}")
            traceback.print_exc()
            return self._get_default_response()

    def _is_likely_false_positive(self, vuln: Dict, file_path: str) -> bool:
        """Check if vulnerability is likely a false positive

        Args:
            vuln: Vulnerability to check
            file_path: Path to file being analyzed

        Returns:
            True if vulnerability is likely a false positive
        """
        # 只保留最基本的检查，减少误报过滤

        # 检查描述是否为空
        description = vuln.get("description", "")
        if not description:
            return True

        # 检查类型是否为空
        vuln_type = vuln.get("type", "")
        if not vuln_type:
            return True

        # 检查是否是测试文件
        if file_path and self._is_test_file(file_path):
            return True

        return False

    def _validate_result(self, result: Dict, file_path: str) -> Dict:
        """Validate and normalize result from AI model

        Args:
            result: Result from AI model
            file_path: Path to file being analyzed

        Returns:
            Validated and normalized result
        """
        # 确保结果是字典
        if not isinstance(result, dict):
            logger.warning(f"Result is not a dictionary: {result}")
            return self._get_default_response()

        # 确保漏洞列表存在
        if "vulnerabilities" not in result:
            result["vulnerabilities"] = []

        # 确保漏洞列表是列表
        if not isinstance(result["vulnerabilities"], list):
            logger.warning(
                f"Vulnerabilities is not a list: {result['vulnerabilities']}"
            )
            result["vulnerabilities"] = []

        # 处理漏洞列表
        result["vulnerabilities"] = self._post_process_vulnerabilities(
            result["vulnerabilities"], file_path
        )

        # 确保总体评分存在
        if "overall_score" not in result or not isinstance(
            result["overall_score"], (int, float)
        ):
            # 如果没有漏洞，评分为100；否则根据漏洞计算评分
            if not result["vulnerabilities"]:
                result["overall_score"] = 100
            else:
                result["overall_score"] = self._calculate_security_score(
                    result["vulnerabilities"]
                )

        # 确保总体评分在0-100之间
        result["overall_score"] = max(0, min(100, result["overall_score"]))

        # 确保摘要存在
        if "summary" not in result or not isinstance(result["summary"], str):
            if not result["vulnerabilities"]:
                result["summary"] = "No vulnerabilities detected."
            else:
                vuln_types = [
                    v.get("type", "Unknown") for v in result["vulnerabilities"]
                ]
                result["summary"] = (
                    f"Found {len(result['vulnerabilities'])} vulnerabilities: {', '.join(vuln_types)}"
                )

        # 添加文件信息
        for vuln in result["vulnerabilities"]:
            if "file" not in vuln and file_path:
                vuln["file"] = file_path
            if "file_name" not in vuln and file_path:
                vuln["file_name"] = os.path.basename(file_path)

        return result

    def _analyze_text_response(self, response: str, file_path: str = None) -> Dict:
        """Analyze text response from AI model

        Args:
            response: Response from AI model
            file_path: Path to file being analyzed

        Returns:
            Dict with analysis result
        """
        vulnerabilities = []

        # 尝试提取漏洞信息
        # 1. 寻找明确的漏洞标记
        vuln_sections = re.findall(
            r"(?:vulnerability|issue|security\s+problem)[:\s]+(.*?)(?:\n\n|\Z)",
            response,
            re.IGNORECASE | re.DOTALL,
        )

        # 2. 寻找常见漏洞类型
        common_vulns = [
            "SQL Injection",
            "XSS",
            "CSRF",
            "Command Injection",
            "Path Traversal",
            "Insecure Deserialization",
            "XXE",
            "SSRF",
            "Open Redirect",
            "Insecure Direct Object Reference",
            "Security Misconfiguration",
            "Sensitive Data Exposure",
            "Broken Authentication",
            "Broken Access Control",
            "Insufficient Logging & Monitoring",
        ]

        for vuln_type in common_vulns:
            if re.search(rf"\b{re.escape(vuln_type)}\b", response, re.IGNORECASE):
                # 尝试提取相关描述
                desc_match = re.search(
                    rf"\b{re.escape(vuln_type)}\b[^.]*\.", response, re.IGNORECASE
                )
                description = (
                    desc_match.group(0)
                    if desc_match
                    else f"Potential {vuln_type} vulnerability detected"
                )

                # 尝试提取严重性
                severity_match = re.search(
                    r"severity[:\s]+(\d+)", response, re.IGNORECASE
                )
                severity = int(severity_match.group(1)) if severity_match else 5

                vulnerabilities.append(
                    {
                        "type": vuln_type,
                        "severity": severity,
                        "description": description,
                        "file": file_path,
                        "file_name": (
                            os.path.basename(file_path) if file_path else "unknown"
                        ),
                    }
                )

        # 3. 寻找明确提到的漏洞函数
        if file_path and file_path.endswith(".py"):
            # 针对Python代码的常见漏洞函数
            vuln_funcs = {
                r"\beval\s*\(": "Code Injection",
                r"\bexec\s*\(": "Code Injection",
                r"\bos\.system\s*\(": "Command Injection",
                r"\bsubprocess\.": "Command Injection",
                r"\bopen\s*\(": "Path Traversal",
                r"%\s*\w+": "Format String Vulnerability",
                r"\.execute\s*\(.*\+": "SQL Injection",
                r"\.execute\s*\(.*%": "SQL Injection",
                r'\.execute\s*\(.*f"': "SQL Injection",
                r"\.execute\s*\(.*f\'": "SQL Injection",
                r"pickle\.loads": "Insecure Deserialization",
                r"yaml\.load\s*\(": "Insecure Deserialization",
                r"\.\.\/": "Path Traversal",
                r"request\.form": "Input Validation",
                r"request\.args": "Input Validation",
            }

            for pattern, vuln_type in vuln_funcs.items():
                if re.search(pattern, response, re.IGNORECASE):
                    vulnerabilities.append(
                        {
                            "type": vuln_type,
                            "severity": 7,  # 默认较高严重性
                            "description": f"Potential {vuln_type} vulnerability detected with pattern {pattern}",
                            "file": file_path,
                            "file_name": (
                                os.path.basename(file_path) if file_path else "unknown"
                            ),
                        }
                    )

        # 如果找到漏洞，计算安全评分
        if vulnerabilities:
            security_score = self._calculate_security_score(vulnerabilities)
            summary = (
                f"Found {len(vulnerabilities)} potential vulnerabilities in the code."
            )
        else:
            # 检查是否有明确的安全评价
            if re.search(r"no\s+vulnerabilities", response, re.IGNORECASE) or re.search(
                r"code\s+is\s+secure", response, re.IGNORECASE
            ):
                security_score = 100
                summary = "No vulnerabilities detected."
            else:
                # 如果没有明确评价，但也没找到漏洞，给一个较高但不是满分的评分
                security_score = 90
                summary = "No obvious vulnerabilities detected, but further review recommended."

        return {
            "vulnerabilities": vulnerabilities,
            "overall_score": security_score,
            "summary": summary,
        }

    def _fix_json_format(self, json_str: str) -> str:
        """Fix common JSON format issues"""
        try:
            # 首先尝试直接解析
            json.loads(json_str)
            return json_str
        except json.JSONDecodeError:
            # 如果解析失败，尝试修复
            pass

        # 修复缺少引号的键
        # 这个正则表达式匹配 { 或 , 后面跟着的非引号包裹的键
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

        # 修复缺少逗号的情况 - 修复警告
        json_str = re.sub(r"}\s*{", "},{", json_str)
        # 使用原始字符串来正确转义方括号
        json_str = re.sub(r"}\s*\[", r"},\[", json_str)
        json_str = re.sub(r"]\s*\[", r"],\[", json_str)

        # 修复不匹配的引号
        # 找到所有未闭合的引号
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
            # 找到下一个逗号、}或]
            next_delimiter = json_str.find(",", i)
            next_brace = json_str.find("}", i)
            next_bracket = json_str.find("]", i)

            # 找到最近的分隔符
            delimiters = [
                d for d in [next_delimiter, next_brace, next_bracket] if d != -1
            ]
            if delimiters:
                next_pos = min(delimiters)
                json_str = json_str[:next_pos] + '"' + json_str[next_pos:]
            else:
                # 如果没有找到分隔符，在末尾添加引号
                json_str += '"'

        # 尝试修复常见的 JSON 语法错误
        try:
            # 尝试解析 JSON
            json.loads(json_str)
            return json_str
        except json.JSONDecodeError as e:
            # 如果解析失败，尝试更激进的修复
            error_msg = str(e)
            error_pos = None

            # 提取错误位置
            if "char " in error_msg:
                match = re.search(r"char (\d+)", error_msg)
                if match:
                    error_pos = int(match.group(1))

            if (
                "Expecting property name enclosed in double quotes" in error_msg
                and error_pos is not None
            ):
                # 在错误位置前查找最近的非空白字符
                i = error_pos - 1
                while i >= 0 and json_str[i].isspace():
                    i -= 1

                if i >= 0:
                    # 如果前一个字符是 { 或 ,，那么下一个应该是一个属性名
                    if json_str[i] in "{,":
                        # 查找下一个非空白字符
                        j = error_pos
                        while j < len(json_str) and json_str[j].isspace():
                            j += 1

                        if j < len(json_str):
                            # 如果下一个字符是字母或下划线，那么它可能是一个未加引号的属性名
                            if json_str[j].isalpha() or json_str[j] == "_":
                                # 查找属性名的结束位置
                                k = j
                                while k < len(json_str) and (
                                    json_str[k].isalnum() or json_str[k] == "_"
                                ):
                                    k += 1

                                # 在属性名周围添加引号
                                property_name = json_str[j:k]
                                json_str = (
                                    json_str[:j]
                                    + '"'
                                    + property_name
                                    + '"'
                                    + json_str[k:]
                                )

            elif "Expecting ',' delimiter" in error_msg and error_pos is not None:
                # 在错误位置插入逗号
                json_str = json_str[:error_pos] + "," + json_str[error_pos:]

            # 最后的尝试：使用正则表达式替换所有未引用的属性名
            json_str = re.sub(
                r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', json_str
            )

            # 再次尝试解析
            try:
                json.loads(json_str)
                return json_str
            except json.JSONDecodeError:
                # 如果仍然失败，尝试更激进的方法：提取 JSON 结构
                try:
                    # 查找 JSON 的开始和结束
                    start = json_str.find("{")
                    end = json_str.rfind("}")

                    if start != -1 and end != -1 and start < end:
                        # 提取 JSON 对象
                        json_obj = json_str[start : end + 1]

                        # 替换所有未引用的属性名
                        json_obj = re.sub(
                            r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:",
                            r'\1"\2":',
                            json_obj,
                        )

                        # 尝试解析
                        try:
                            json.loads(json_obj)
                            return json_obj
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

                # 如果所有尝试都失败，返回原始字符串
                logger.error("Failed to fix JSON format")
                return json_str

    def _get_default_response(self) -> Dict:
        """Get default response when parsing fails"""
        return {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "Failed to parse model response",
        }

    async def _analyze_with_ai(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
        """Analyze code with AI (abstract method implementation)"""
        try:
            # Build prompt
            prompt = self._build_prompt(code, file_path)

            # Call API
            response = await self._call_api(prompt)

            # Parse response
            result = self._parse_response(response, file_path)

            return result
        except Exception as e:
            logger.error(f"Error in _analyze_with_ai: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return self._get_default_response()

    async def analyze_code(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
        """Analyze code for security vulnerabilities"""
        try:
            logger.info(f"Analyzing code from {file_path}")

            # 检查是否应该跳过此文件
            if self._should_skip_file(file_path):
                logger.info(f"Skipping file based on type: {file_path}")
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "Skipped non-code file",
                }

            # 跳过测试文件，除非明确包含
            if self._is_test_file(file_path):
                logger.info(f"Skipping test file: {file_path}")
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "Skipped test file",
                }

            # 使用 _analyze_with_ai 方法进行实际分析
            result = await self._analyze_with_ai(code, file_path, context)

            # 确保结果中的漏洞有正确的文件路径
            if "vulnerabilities" in result and isinstance(
                result["vulnerabilities"], list
            ):
                # 使用完整路径而不仅仅是文件名
                for vuln in result["vulnerabilities"]:
                    if isinstance(vuln, dict):
                        # 保存完整路径
                        vuln["file"] = file_path
                        # 添加一个额外的字段保存文件名，以便向后兼容
                        vuln["file_name"] = os.path.basename(file_path)
                        # 添加来源
                        vuln["source"] = "ai"

                # 后处理漏洞，过滤误报
                result["vulnerabilities"] = self._post_process_vulnerabilities(
                    result["vulnerabilities"], file_path
                )

                # 重新计算安全分数
                if result["vulnerabilities"]:
                    result["overall_score"] = self._calculate_security_score(
                        result["vulnerabilities"]
                    )
                else:
                    result["overall_score"] = 100

                # 更新摘要
                vulns_count = len(result["vulnerabilities"])
                if vulns_count > 0:
                    result["summary"] = f"Found {vulns_count} potential security issues"
                else:
                    result["summary"] = "No security issues found"

            return result
        except Exception as e:
            logger.error(f"Error analyzing code: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return self._get_default_response()

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate security score based on vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Security score (0-100)
        """
        if not vulnerabilities:
            return 100

        # 计算平均严重程度
        total_severity = sum(vuln.get("severity", 5) for vuln in vulnerabilities)
        avg_severity = total_severity / len(vulnerabilities)

        # 根据漏洞数量和严重程度计算分数
        # 基础分数 100，每个漏洞根据严重程度扣分
        base_score = 100
        severity_penalty = avg_severity * 10  # 严重程度越高，扣分越多
        count_penalty = min(
            len(vulnerabilities) * 5, 30
        )  # 漏洞数量越多，扣分越多，但最多扣 30 分

        # 计算最终分数
        score = max(0, base_score - severity_penalty - count_penalty)

        return int(score)

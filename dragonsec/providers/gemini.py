import google.generativeai as genai
from typing import List, Dict, Any, Optional, Tuple
import json
from pathlib import Path
from .base import AIProvider
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
import time
import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
import threading
import re

logger = logging.getLogger(__name__)


class GeminiProvider(AIProvider):
    """Gemini AI provider for code analysis"""

    def __init__(self, api_key: str, max_retries: int = 2):
        super().__init__(api_key)
        
        # 初始化 Google Generative AI
        genai.configure(api_key=api_key)
        
        self.model = "gemini-pro"
        self.client = genai.GenerativeModel(self.model)
        self.context_cache = {}
        self.max_retries = max_retries

    @property
    def system_prompt(self) -> str:
        """Get Gemini-specific system prompt"""
        return (
            self.base_system_prompt
            + """
        Additional Gemini-specific instructions:
        - Be precise and concise
        - Focus on actionable findings
        """
        )

    async def analyze_code(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
        """Analyze code using Google's Gemini API"""
        try:
            # 输入验证
            if not code or not isinstance(code, str):
                raise ValueError("Invalid code input")

            # 使用异步锁而不是线程锁
            async with asyncio.Lock():
                # 构建提示
                prompt = self._build_prompt(code, file_path, context)

                # 直接使用异步 API
                response = await self.client.generate_content(prompt)

                # 处理响应
                if not response:
                    raise ValueError("Empty response from Gemini API")

                # 获取响应文本
                if hasattr(response, "text"):
                    text = response.text
                else:
                    parts = response.parts[0].text if response.parts else ""
                    text = parts

                # 清理响应文本
                text = text.strip()
                if text.startswith("```"):
                    text = text[text.find("\n") + 1 : text.rfind("```")].strip()

                try:
                    result = json.loads(text)
                    return self._parse_response(result)
                except json.JSONDecodeError:
                    print(f"Invalid JSON response: {text[:100]}...")
                    raise

        except Exception as e:
            logger.error(f"Gemini analysis failed: {str(e)}")
            return self._get_default_response()

    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Merge and enhance semgrep results with AI analysis"""
        ai_vulns = ai_results.get("vulnerabilities", [])

        # process semgrep results
        semgrep_vulns = []
        for finding in semgrep_results:
            # 确保所有必要的字段都存在
            file_path = finding.get("path", "")
            relative_path = self._get_relative_project_path(file_path)

            # 提取更详细的信息
            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})

            vuln = {
                "source": "semgrep",
                "type": finding.get("check_id", "unknown"),
                "severity": self._convert_semgrep_severity(
                    extra.get("severity", "medium")
                ),
                "description": extra.get(
                    "message", finding.get("message", "")
                ),  # 尝试两个位置获取描述
                "line_number": finding.get("start", {}).get("line", 0),
                "file": relative_path,
                "risk_analysis": metadata.get(
                    "impact", "Potential security vulnerability detected"
                ),
                "recommendation": metadata.get(
                    "fix", extra.get("fix", "Review and fix the identified issue")
                ),
            }

            # 添加代码片段如果存在
            if "lines" in finding:
                vuln["code_snippet"] = finding["lines"]

            semgrep_vulns.append(vuln)

        all_vulns = semgrep_vulns + [{"source": "ai", **v} for v in ai_vulns]
        score = self._calculate_security_score(all_vulns)

        # 添加更详细的统计信息
        stats = {
            "total": len(all_vulns),
            "semgrep": len(semgrep_vulns),
            "ai": len(ai_vulns),
            "by_severity": {
                "critical": len([v for v in all_vulns if v["severity"] >= 9]),
                "high": len([v for v in all_vulns if 7 <= v["severity"] < 9]),
                "medium": len([v for v in all_vulns if 4 <= v["severity"] < 7]),
                "low": len([v for v in all_vulns if v["severity"] < 4]),
            },
        }

        return {
            "vulnerabilities": all_vulns,
            "overall_score": score,
            "summary": (
                f"Found {stats['total']} vulnerabilities "
                f"({stats['semgrep']} from semgrep, {stats['ai']} from AI analysis). "
                f"Security Score: {score}%. "
                f"Severity breakdown: {stats['by_severity']['critical']} critical, "
                f"{stats['by_severity']['high']} high, "
                f"{stats['by_severity']['medium']} medium, "
                f"{stats['by_severity']['low']} low."
            ),
        }

    # reuse the same helper methods as OpenAIProvider
    def _optimize_context(self, file_path: str, context: Dict) -> str:
        """optimize context information, reduce token usage"""
        project_root = str(Path(file_path).parent)

        if project_root not in self.context_cache:
            self.context_cache[project_root] = {
                "dependencies": self._filter_relevant_deps(
                    context.get("dependencies", {})
                ),
                "structure": self._simplify_structure(
                    context.get("project_structure", {})
                ),
            }

        cached_context = self.context_cache[project_root]
        relevant_files = self._filter_related_files(
            file_path, context.get("related_files", [])
        )
        relevant_imports = self._filter_relevant_imports(context.get("imports", []))

        return f"""
        Key Context:
        - File: {file_path}
        - Related Files: {', '.join(relevant_files)}
        - Key Imports: {', '.join(relevant_imports)}
        - Critical Dependencies: {json.dumps(cached_context['dependencies'], indent=2)}
        """

    def _filter_relevant_deps(self, deps: Dict[str, str]) -> Dict[str, str]:
        """filter out security related dependencies"""
        return {
            k: v
            for k, v in deps.items()
            if any(term in k.lower() for term in self.SECURITY_TERMS)
        }

    def _simplify_structure(self, structure: Dict) -> Dict:
        """simplify project structure, only keep key directories"""
        key_dirs = {"src", "security", "auth", "api", "controllers", "routes"}
        return {
            k: v
            for k, v in structure.items()
            if any(dir in k.lower() for dir in key_dirs)
        }

    def _filter_related_files(
        self, current_file: str, related: List[str], max_files: int = 3
    ) -> List[str]:
        """select the most relevant files"""
        current_dir = str(Path(current_file).parent)
        security_patterns = {"security", "auth", "login", "password", "crypto"}

        scored_files = []
        for file in related:
            score = 0
            if str(Path(file).parent) == current_dir:
                score += 2
            if any(pattern in file.lower() for pattern in security_patterns):
                score += 1
            scored_files.append((score, file))

        return [f for _, f in sorted(scored_files, reverse=True)[:max_files]]

    def _filter_relevant_imports(
        self, imports: List[str], max_imports: int = 5
    ) -> List[str]:
        """filter out the most relevant imports"""
        relevant = [
            imp
            for imp in imports
            if any(term in imp.lower() for term in self.SECURITY_TERMS)
        ]
        return relevant[:max_imports]

    # 使用基类的 _get_default_response 方法

    def _find_project_root(self, file_path: str) -> Optional[str]:
        """find the project root directory"""
        from ..utils.file_utils import FileContext
        context = FileContext()
        return context.find_project_root(file_path)

    def _get_relative_project_path(self, file_path: str) -> str:
        """get the relative path from the project root"""
        try:
            file_path = Path(file_path)
            root_dir = self._find_project_root(str(file_path))

            if root_dir:
                try:
                    relative_path = file_path.relative_to(Path(root_dir))
                    return str(relative_path)
                except ValueError:
                    return file_path.name
            return file_path.name
        except Exception:
            return Path(file_path).name

    def _convert_semgrep_severity(self, severity: str) -> int:
        """convert semgrep severity to numeric scale"""
        severity_map = {
            "ERROR": 9,
            "WARNING": 6,
            "INFO": 3,
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2,
        }
        return severity_map.get(severity, 5)

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """calculate security score based on vulnerabilities"""
        if not vulnerabilities:
            return 100

        score = 100
        severity_weights = {
            range(9, 11): 15,  # Critical: -15 points each
            range(7, 9): 10,  # High: -10 points each
            range(4, 7): 5,  # Medium: -5 points each
            range(1, 4): 2,  # Low: -2 points each
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", 5)
            for severity_range, weight in severity_weights.items():
                if severity in severity_range:
                    score -= weight
                    break

        return max(0, min(100, score))

    def _build_prompt(self, code: str, file_path: str, context: Dict = None) -> str:
        """Build prompt for Gemini API"""
        relative_path = self._get_relative_project_path(file_path)
        context_info = self._optimize_context(file_path, context) if context else ""

        return f"""You are a security code analyzer. Analyze the following code for security vulnerabilities.

        Context:
        {context_info}

        Code to analyze:
        {code}

        Respond ONLY with a JSON object in the following format (no markdown, no other text):
        {{
            "vulnerabilities": [
                {{
                    "type": "vulnerability type",
                    "severity": 1-10,
                    "description": "detailed description",
                    "line_number": line number,
                    "file": "{relative_path}",
                    "risk_analysis": "potential impact",
                    "recommendation": "how to fix"
                }}
            ],
            "overall_score": 0-100,
            "summary": "brief security assessment"
        }}

        If no vulnerabilities found, return empty array for vulnerabilities. Do not include any markdown formatting or additional text."""

    async def _parse_response(self, response: str, file_path: str) -> Dict:
        """Parse response from Gemini API"""
        try:
            # 尝试解析 JSON 响应
            try:
                # 查找 JSON 块
                json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                    result = json.loads(json_str)

                    # 确保结果包含必要的字段
                    if not isinstance(result, dict):
                        result = {"vulnerabilities": []}

                    if "vulnerabilities" not in result:
                        result["vulnerabilities"] = []

                    # 标准化每个漏洞对象
                    for vuln in result["vulnerabilities"]:
                        # 设置必需字段
                        vuln["file"] = file_path
                        vuln["type"] = vuln.get("type", "Unknown")
                        vuln["severity"] = int(vuln.get("severity", 5))
                        vuln["description"] = vuln.get("description", "No description")
                        vuln["line_number"] = int(vuln.get("line_number", 0))
                        vuln["risk_analysis"] = vuln.get("risk_analysis", "No risk analysis")
                        vuln["recommendation"] = vuln.get("recommendation", "No recommendation")
                        vuln["confidence"] = vuln.get("confidence", "medium")
                        vuln["source"] = "gemini"

                    # 计算整体评分
                    if "overall_score" not in result:
                        vulns = result["vulnerabilities"]
                        if vulns:
                            result["overall_score"] = self._calculate_security_score(vulns)
                        else:
                            result["overall_score"] = 100

                    # 添加摘要
                    if "summary" not in result:
                        if result["vulnerabilities"]:
                            result["summary"] = f"Found {len(result['vulnerabilities'])} potential security issues"
                        else:
                            result["summary"] = "No security issues found"

                    return result
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON response")

            # 如果 JSON 解析失败，返回默认响应
            return self._get_default_response()

        except Exception as e:
            logger.error(f"Error parsing Gemini response: {e}")
            return self._get_default_response()

    async def _analyze_with_ai(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
        """Gemini-specific implementation"""
        try:
            response = await self.client.generate_content(
                self.system_prompt + f"\n\nAnalyze this code:\n\n{code}"
            )

            content = response.text
            logger.debug(f"Raw response content: {content}")

            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse response as JSON: {e}")
                return self._get_default_response()

        except Exception as e:
            logger.error(f"Error calling Gemini API: {e}")
            return self._get_default_response()

    async def analyze_batch(self, files: List[Tuple[str, str]]) -> List[Dict]:
        """批量分析代码文件"""
        results = []
        for code, file_path in files:
            result = await self.analyze_code(code, file_path)
            results.append(result)
        return results

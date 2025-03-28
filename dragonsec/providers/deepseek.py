import json
import logging
from typing import Dict, Any, List, Tuple
from pathlib import Path
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
import httpx
import asyncio
import os
import random
from openai import AsyncOpenAI
from dragonsec.providers.base import AIProvider
from dragonsec.utils.secure import secure

logger = logging.getLogger(__name__)


class DeepseekProvider(AIProvider):
    """Deepseek provider implementation."""

    def __init__(self, api_key: str):
        """Initialize Deepseek provider.

        Args:
            api_key: OpenRouter API key
        """
        super().__init__(api_key)
        self.client = AsyncOpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=self.api_key,
        )
        self.model = "deepseek/deepseek-coder-33b-instruct"
        self.timeout = httpx.Timeout(60.0)
        self.max_retries = 3
        self.concurrent_limit = 2
        self.batch_delay = 1.0

    def _get_default_response(self) -> Dict:
        """Get default response when analysis fails"""
        return {"vulnerabilities": [], "overall_score": 0, "summary": "Analysis failed"}

    async def analyze_code(
        self, code: str, language: str = "python"
    ) -> Dict[str, any]:
        """Analyze code using Deepseek API.

        Args:
            code: Code to analyze
            language: Programming language

        Returns:
            Analysis results
        """
        try:
            messages = [
                {
                    "role": "system",
                    "content": """You are a security expert. Analyze the code for security vulnerabilities.
                    Return a JSON response with:
                    {
                        "vulnerabilities": [
                            {
                                "type": "vulnerability type",
                                "severity": "high/medium/low",
                                "line": line number,
                                "suggestion": "fix suggestion"
                            }
                        ],
                        "overall_score": score between 0-100
                    }""",
                },
                {"role": "user", "content": f"Analyze this {language} code:\n{code}"},
            ]

            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.1,
                max_tokens=2000,
                extra_headers={
                    "HTTP-Referer": "https://github.com/dragonsec/dragonsec",
                    "X-Title": "DragonSec",
                },
            )

            try:
                # Extract the content from the response
                content = completion.choices[0].message.content
                # Parse the JSON response
                analysis = json.loads(content)
                return analysis
            except (KeyError, json.JSONDecodeError) as e:
                logger.error(f"Error parsing Deepseek response: {e}")
                return {
                    "vulnerabilities": [],
                    "overall_score": 0,
                    "error": f"Response parsing error: {str(e)}",
                }

        except Exception as e:
            logger.error(f"Error in Deepseek analysis: {e}")
            return {
                "vulnerabilities": [],
                "overall_score": 0,
                "error": str(e),
            }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=20),  # 增加重试等待时间
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPError)),
    )
    async def _call_api(self, prompt: str) -> str:
        """Call Deepseek API with improved retry logic"""
        try:
            logger.info("Calling Deepseek API")

            # 添加随机延迟避免并发请求
            await asyncio.sleep(random.uniform(0.5, 2.0))

            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security code analyzer. Analyze the code for security vulnerabilities and provide detailed findings in JSON format.",
                    },
                    {"role": "user", "content": prompt},
                ],
                timeout=self.timeout,
            )
            return completion.choices[0].message.content

        except Exception as e:
            logger.error(f"Deepseek API call failed: {e}")
            raise

    def _build_prompt(self, code: str, file_path: str, context: Dict = None) -> str:
        """Build custom prompt for Deepseek"""
        file_type = Path(file_path).suffix.lstrip(".") or "txt"

        prompt = f"""Analyze the following {file_type} code for security vulnerabilities.
        Focus on identifying concrete, exploitable security issues:

        - SQL Injection (e.g., unparameterized queries)
        - Command Injection (e.g., unsanitized shell commands)
        - Path Traversal (e.g., unvalidated file paths)
        - Hardcoded Secrets (e.g., API keys, passwords in code)
        - Insecure Cryptography (e.g., weak algorithms, improper key handling)
        - XSS Vulnerabilities (e.g., unescaped output)
        - Unsafe Deserialization (e.g., pickle.loads of untrusted data)

        Important guidelines:
        1. Only report issues that are clearly exploitable
        2. Ignore commented code
        3. Consider the context and common practices
        4. Focus on implementation flaws, not architectural choices
        5. Provide concrete evidence for each vulnerability

        For each vulnerability found, provide:
        1. Type: Specific vulnerability category
        2. Severity: 1-10 based on exploitability and impact
        3. Description: Clear explanation with code evidence
        4. Line number: Exact location in code
        5. Risk analysis: Concrete attack scenarios
        6. Recommendation: Specific, actionable fixes

        Format your response as JSON with this structure:
        {{
            "vulnerabilities": [
                {{
                    "type": "vulnerability type",
                    "severity": severity_number,
                    "description": "detailed description with code evidence",
                    "line_number": line_number,
                    "risk_analysis": "specific attack scenarios",
                    "recommendation": "concrete fix suggestions"
                }}
            ]
        }}

        Code to analyze:
        ```{file_type}
        {code}
        ```
        """

        if context:
            prompt += f"\nAdditional context: {json.dumps(context)}"

        return prompt

    def _parse_response(self, response: str) -> Dict:
        """Parse Deepseek response with improved error handling"""
        try:
            # 添加调试日志
            logger.debug(f"Raw response: {response}")

            # 尝试从响应中提取 JSON 部分
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                logger.debug(f"Extracted JSON: {json_str}")

                result = json.loads(json_str)

                # 处理不同的响应格式
                if isinstance(result, dict):
                    vulnerabilities = []

                    # 直接使用 vulnerabilities 数组
                    if "vulnerabilities" in result:
                        vulnerabilities = result["vulnerabilities"]

                    # 处理嵌套的漏洞信息
                    elif "findings" in result:
                        for finding in result["findings"]:
                            if isinstance(finding, dict):
                                vulnerabilities.append(finding)

                    # 处理键值对格式
                    else:
                        for key, value in result.items():
                            if isinstance(value, dict):
                                vuln = {
                                    "type": key,
                                    "severity": value.get("severity", 5),
                                    "description": value.get("description", ""),
                                    "line_number": value.get("line_number", 0),
                                    "risk_analysis": value.get("risk_analysis", ""),
                                    "recommendation": value.get("recommendation", ""),
                                }
                                vulnerabilities.append(vuln)

                    # 标准化每个漏洞对象
                    for vuln in vulnerabilities:
                        vuln.update(
                            {
                                "type": vuln.get("type", "Unknown"),
                                "severity": int(vuln.get("severity", 5)),
                                "description": vuln.get(
                                    "description", "No description"
                                ),
                                "line_number": int(vuln.get("line_number", 0)),
                                "risk_analysis": vuln.get(
                                    "risk_analysis", "No risk analysis"
                                ),
                                "recommendation": vuln.get(
                                    "recommendation", "No recommendation"
                                ),
                            }
                        )

                    return {
                        "vulnerabilities": vulnerabilities,
                        "overall_score": self._calculate_security_score(
                            vulnerabilities
                        ),
                        "summary": f"Found {len(vulnerabilities)} potential security issues",
                    }

            logger.error("Failed to extract valid JSON from response")
            logger.debug(f"Invalid response: {response}")
            return self._get_default_response()

        except Exception as e:
            logger.error(f"Error parsing response: {str(e)}")
            logger.debug(f"Failed response: {response}")
            return self._get_default_response()

    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Merge semgrep and AI results"""
        all_vulns = []
        all_vulns.extend(semgrep_results)
        if "vulnerabilities" in ai_results:
            all_vulns.extend(ai_results["vulnerabilities"])

        score = self._calculate_security_score(all_vulns)

        return {
            "vulnerabilities": all_vulns,
            "overall_score": score,
            "summary": f"Found {len(all_vulns)} vulnerabilities ({len(semgrep_results)} from semgrep, {len(ai_results.get('vulnerabilities', []))} from AI analysis). Security Score: {score}%",
        }

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall security score"""
        if not vulnerabilities:
            return 100.0

        # 基于漏洞严重程度计算分数
        total_severity = sum(vuln.get("severity", 5) for vuln in vulnerabilities)
        avg_severity = total_severity / len(vulnerabilities)

        # 将平均严重程度转换为 0-100 的分数
        score = max(0, 100 - (avg_severity * 10))
        return round(score, 2)

    async def analyze_batch(self, files: List[Tuple[str, str]]) -> List[Dict]:
        """Analyze a batch of files with improved concurrency control"""
        semaphore = asyncio.Semaphore(self.concurrent_limit)
        results = []

        async def analyze_with_semaphore(code: str, file_path: str) -> Dict:
            async with semaphore:
                try:
                    result = await self.analyze_code(code, file_path)
                    # 成功后添加延迟
                    await asyncio.sleep(self.batch_delay)
                    return result
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
                    return self._get_default_response()

        # 分批处理文件
        for i in range(0, len(files), self.concurrent_limit):
            batch = files[i : i + self.concurrent_limit]
            batch_results = await asyncio.gather(
                *[analyze_with_semaphore(code, file_path) for code, file_path in batch]
            )
            results.extend(batch_results)
            # 批次间添加更长的延迟
            await asyncio.sleep(self.batch_delay * 2)

        return results

    async def _analyze_with_ai(
        self, code: str, file_path: str, context: Dict = None
    ) -> Dict:
        """Analyze code using Deepseek API.

        Args:
            code: Code to analyze
            file_path: Path to the file being analyzed
            context: Additional context for analysis

        Returns:
            Analysis results
        """
        try:
            messages = [
                {
                    "role": "system",
                    "content": self._get_system_prompt(),
                },
                {"role": "user", "content": f"Analyze this code:\n{code}"},
            ]

            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.1,
                max_tokens=2000,
                extra_headers={
                    "HTTP-Referer": "https://github.com/dragonsec/dragonsec",
                    "X-Title": "DragonSec",
                },
            )

            try:
                # Extract the content from the response
                content = completion["choices"][0]["message"]["content"]
                # Parse the JSON response
                analysis = json.loads(content)
                
                # 确保所有漏洞都有完整的字段
                if "vulnerabilities" in analysis:
                    for vuln in analysis["vulnerabilities"]:
                        # 设置必需字段
                        vuln["file"] = file_path
                        vuln["type"] = vuln.get("type", "Unknown")
                        vuln["severity"] = int(vuln.get("severity", 5))
                        vuln["description"] = vuln.get("description", "No description")
                        vuln["line_number"] = int(vuln.get("line_number", 0))
                        vuln["risk_analysis"] = vuln.get("risk_analysis", "No risk analysis")
                        vuln["recommendation"] = vuln.get("recommendation", "No recommendation")
                        vuln["confidence"] = vuln.get("confidence", "medium")
                        vuln["source"] = "deepseek"
                
                return analysis
            except (KeyError, json.JSONDecodeError) as e:
                logger.error(f"Error parsing Deepseek response: {e}")
                return {
                    "vulnerabilities": [],
                    "overall_score": 0,
                    "error": f"Response parsing error: {str(e)}",
                }

        except Exception as e:
            logger.error(f"Error in Deepseek analysis: {e}")
            return {
                "vulnerabilities": [],
                "overall_score": 0,
                "error": str(e),
            }

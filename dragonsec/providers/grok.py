"""Grok AI provider for code analysis"""

import logging
from .openai import OpenAIProvider
from pathlib import Path
from typing import Dict, List
import json

logger = logging.getLogger(__name__)

class GrokProvider(OpenAIProvider):
    """Grok AI provider for code analysis"""
    
    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://api.x.ai/v1",
            model="grok-2-latest"
        )

    async def _call_api(self, prompt: str) -> str:
        """Call Grok API using OpenAI client"""
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security code analyzer..."},
                    {"role": "user", "content": prompt}
                ]
            )
            return completion.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Grok API call failed: {e}")
            raise

    def _get_default_response(self) -> Dict:
        """Get default response when analysis fails"""
        return {
            "vulnerabilities": [],
            "overall_score": 100,  # 没有发现漏洞时返回满分
            "summary": "Failed to analyze code"
        }

    async def _parse_response(self, result: str) -> Dict:
        """Parse and clean up Grok response"""
        try:
            parsed = json.loads(result)
            if "vulnerabilities" not in parsed:
                return {
                    "vulnerabilities": [],
                    "overall_score": 0,
                    "summary": "No vulnerabilities found"
                }
            
            # 确保所有漏洞都标记为 AI 来源
            for vuln in parsed.get("vulnerabilities", []):
                vuln["source"] = "ai"
            
            # 确保返回格式一致
            if "overall_score" not in parsed:
                parsed["overall_score"] = 0
            if "summary" not in parsed:
                parsed["summary"] = "Analysis completed"
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing Grok response: {e}")
            return {
                "vulnerabilities": [],
                "overall_score": 0,
                "summary": "Failed to parse response"
            }

    async def deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Deduplicate and merge similar vulnerabilities using AI"""
        if not vulnerabilities:
            return []
        
        try:
            # 首先进行基本的去重
            unique_vulns = []
            seen = set()
            
            for vuln in vulnerabilities:
                key = (vuln.get("title", ""), vuln.get("file", ""), vuln.get("line_number", 0))
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)
            
            if len(unique_vulns) <= 1:
                return unique_vulns
            
            # 然后使用 AI 进行更智能的去重
            dedup_prompt = """
            Please analyze these vulnerability findings and remove duplicates or merge similar issues.
            Return the result as a JSON array of unique vulnerabilities.
            Each vulnerability should keep its original format with all fields.
            
            Original vulnerabilities:
            {vulns}
            """
            
            dedup_response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert helping to deduplicate vulnerability findings."},
                    {"role": "user", "content": dedup_prompt.format(vulns=json.dumps(unique_vulns, indent=2))}
                ]
            )
            
            content = dedup_response.choices[0].message.content
            logger.debug(f"Deduplication response: {content}")
            
            try:
                dedup_result = json.loads(content)
                if isinstance(dedup_result, list):
                    return dedup_result
                elif isinstance(dedup_result, dict) and "vulnerabilities" in dedup_result:
                    return dedup_result["vulnerabilities"]
                return unique_vulns
                
            except json.JSONDecodeError:
                logger.error("Failed to parse AI deduplication response")
                return unique_vulns
                
        except Exception as e:
            logger.error(f"Error during AI deduplication: {e}")
            return vulnerabilities

    async def analyze_code(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Analyze code using Grok API"""
        try:
            # 验证输入
            if not code or not isinstance(code, str):
                return self._get_default_response()
            if not file_path or not isinstance(file_path, str):
                return self._get_default_response()
            
            # 跳过测试文件
            if "/tests/" in file_path or "\\tests\\" in file_path:
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "Skipped test file"
                }
            
            system_prompt = """You are a security code analyzer. Analyze the given code for security vulnerabilities.
            Focus on real, exploitable security issues only. Avoid reporting:
            - Code style issues
            - Best practice violations that don't have direct security impact
            - Theoretical vulnerabilities without clear exploit paths
            - Issues in test code or example code

            Before reporting a vulnerability, verify:
            1. The vulnerability is in production code
            2. There is a clear and realistic attack scenario
            3. The vulnerability can be exploited by an attacker
            4. The impact is significant enough to warrant fixing

            Return your findings in the following JSON format ONLY:
            {
                "vulnerabilities": [
                    {
                        "type": "Type of the vulnerability (e.g. SQL Injection, XSS, etc.)",
                        "severity": <integer 1-10, based on CVSS scoring>,
                        "description": "Brief description of the vulnerability",
                        "line_number": <integer>,
                        "file": "<file path>",
                        "risk_analysis": "Detailed analysis of potential risks and impacts, including exploit scenarios",
                        "recommendation": "Specific recommendations to fix the issue"
                    }
                ],
                "overall_score": <integer 0-100>,
                "summary": "Brief summary of findings"
            }

            Important:
            - Only report vulnerabilities that have clear security impact
            - Severity should follow CVSS scoring guidelines
            - Each vulnerability must have a concrete exploit scenario
            - Line number must point to the exact vulnerable code
            - If no real security vulnerabilities found, return empty array"""
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Please analyze this code for security vulnerabilities. File: {file_path}\n\nCode:\n{code}"}
                ]
            )
            
            logger.debug(f"Raw Grok response: {response}")
            
            try:
                content = response.choices[0].message.content.strip()
                logger.debug(f"Raw response content: {content}")
                
                try:
                    findings = json.loads(content)
                    if isinstance(findings, dict):
                        # 标准化返回格式
                        result = {
                            "vulnerabilities": [],
                            "overall_score": 100,
                            "summary": "No vulnerabilities found"
                        }
                        
                        if "vulnerabilities" in findings:
                            vulns = []
                            required_fields = ["type", "severity", "description", "line_number", 
                                            "file", "risk_analysis", "recommendation"]
                            
                            for vuln in findings["vulnerabilities"]:
                                if all(k in vuln for k in required_fields):
                                    clean_vuln = {
                                        "type": str(vuln["type"]).strip(),
                                        "severity": int(vuln["severity"]),
                                        "description": str(vuln["description"]).strip(),
                                        "line_number": int(vuln["line_number"]),
                                        "file": file_path,
                                        "risk_analysis": str(vuln["risk_analysis"]).strip(),
                                        "recommendation": str(vuln["recommendation"]).strip()
                                    }
                                    vulns.append(clean_vuln)
                            
                            if vulns:
                                result["vulnerabilities"] = vulns
                                # 使用最高严重性作为整体分数
                                max_severity = max(v["severity"] for v in vulns)
                                result["overall_score"] = max(0, 100 - (max_severity * 10))
                                result["summary"] = f"Found {len(vulns)} security issues"
                                
                        return result
                        
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.error(f"Failed to parse response as JSON: {e}")
                    logger.debug(f"Failed content: {content}")
                    return self._get_default_response()
                
            except Exception as e:
                logger.error(f"Error parsing Grok response: {e}")
                return self._get_default_response()
                
        except Exception as e:
            logger.error(f"Error calling Grok API: {e}")
            return self._get_default_response() 
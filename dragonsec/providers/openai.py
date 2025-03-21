from openai import AsyncOpenAI
from typing import List, Dict, Any, Optional
import json
from pathlib import Path
from .base import AIProvider
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

logger = logging.getLogger(__name__)

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, base_url: str = None, model: str = "gpt-4"):
        """Initialize OpenAI provider
        
        Args:
            api_key (str): API key from environment or secure storage
            base_url (str, optional): Custom API endpoint
            model (str, optional): Model to use. Defaults to "gpt-4"
        """
        # API key should be provided at runtime, not hardcoded
        super().__init__(api_key=api_key)
        
        # Initialize client with runtime credentials
        self.client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=base_url
        ) if base_url else AsyncOpenAI(api_key=self.api_key)
        self.model = model
        self.context_cache = {}
        self.SYSTEM_PROMPT = """
        You are a security expert. You MUST respond with valid JSON only, no markdown formatting or other text.
        """

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def analyze_code(self, code: str, file_path: str, stream: bool = False, **kwargs) -> Dict:
        """Analyze code for security issues"""
        try:
            # 验证输入
            if not code or not isinstance(code, str):
                raise ValueError("Invalid code input")
            if not file_path or not isinstance(file_path, str):
                raise ValueError("Invalid file path")
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": self._prepare_prompt(code, kwargs)}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            try:
                result = response.choices[0].message.content
                return await self._parse_response(result)
            except (KeyError, IndexError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse OpenAI response: {e}")
                return self._get_default_response()
            
        except Exception as e:
            logger.error(f"Error in OpenAI analysis: {str(e)}")
            return self._get_default_response()

    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Merge and enhance semgrep results with AI analysis"""
        ai_vulns = ai_results.get("vulnerabilities", [])
        
        # process semgrep results
        semgrep_vulns = []
        for finding in semgrep_results:
            # convert semgrep path to relative path
            file_path = finding.get("path", "")
            relative_path = self._get_relative_project_path(file_path)
            
            semgrep_vulns.append({
                "source": "semgrep",
                "type": finding.get("check_id", "unknown"),
                "severity": self._convert_semgrep_severity(finding.get("extra", {}).get("severity", "medium")),
                "description": finding.get("extra", {}).get("message", ""),
                "line_number": finding.get("start", {}).get("line", 0),
                "file": relative_path,
                "risk_analysis": finding.get("extra", {}).get("metadata", {}).get("impact", "Unknown impact"),
                "recommendation": finding.get("extra", {}).get("metadata", {}).get("fix", "No fix provided")
            })

        all_vulns = semgrep_vulns + [{"source": "ai", **v} for v in ai_vulns]
        score = self._calculate_security_score(all_vulns)
        
        return {
            "vulnerabilities": all_vulns,
            "overall_score": score,
            "summary": f"Found {len(all_vulns)} vulnerabilities ({len(semgrep_vulns)} from semgrep, {len(ai_vulns)} from AI analysis). Security Score: {score}%"
        }

    def _optimize_context(self, file_path: str, context: Dict) -> str:
        """Optimize context information to reduce token usage"""
        project_root = str(Path(file_path).parent)
        
        if project_root not in self.context_cache:
            self.context_cache[project_root] = {
                'dependencies': self._filter_relevant_deps(context.get('dependencies', {})),
                'structure': self._simplify_structure(context.get('project_structure', {}))
            }
        
        cached_context = self.context_cache[project_root]
        relevant_files = self._filter_related_files(file_path, context.get('related_files', []))
        relevant_imports = self._filter_relevant_imports(context.get('imports', []))
        
        return f"""
        Key Context:
        - File: {file_path}
        - Related Files: {', '.join(relevant_files)}
        - Key Imports: {', '.join(relevant_imports)}
        - Critical Dependencies: {json.dumps(cached_context['dependencies'], indent=2)}
        """

    def _get_relative_project_path(self, file_path: str) -> str:
        """Get path relative to project root"""
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

    def _filter_relevant_deps(self, deps: Dict[str, str]) -> Dict[str, str]:
        """Filter security-related dependencies"""
        security_related = {
            'crypto', 'security', 'auth', 'jwt', 'bcrypt', 'hash',
            'password', 'ssl', 'tls', 'https', 'oauth'
        }
        return {
            k: v for k, v in deps.items() 
            if any(term in k.lower() for term in security_related)
        }

    def _simplify_structure(self, structure: Dict) -> Dict:
        """Simplify project structure, keep only key directories"""
        key_dirs = {'src', 'security', 'auth', 'api', 'controllers', 'routes'}
        return {
            k: v for k, v in structure.items() 
            if any(dir in k.lower() for dir in key_dirs)
        }

    def _filter_related_files(self, current_file: str, related: List[str], max_files: int = 3) -> List[str]:
        """Select most relevant files"""
        current_dir = str(Path(current_file).parent)
        security_patterns = {'security', 'auth', 'login', 'password', 'crypto'}
        
        scored_files = []
        for file in related:
            score = 0
            if str(Path(file).parent) == current_dir:
                score += 2
            if any(pattern in file.lower() for pattern in security_patterns):
                score += 1
            scored_files.append((score, file))
        
        return [f for _, f in sorted(scored_files, reverse=True)[:max_files]]

    def _filter_relevant_imports(self, imports: List[str], max_imports: int = 5) -> List[str]:
        """Filter most relevant imports"""
        security_related = {
            'crypto', 'security', 'auth', 'jwt', 'bcrypt',
            'hash', 'password', 'ssl', 'tls', 'https'
        }
        
        relevant = [imp for imp in imports if any(term in imp.lower() for term in security_related)]
        return relevant[:max_imports]

    def _get_default_response(self) -> Dict:
        """Get default response when analysis fails"""
        return {
            "vulnerabilities": [],
            "overall_score": 0,
            "summary": "Failed to analyze code"
        }

    def _find_project_root(self, file_path: str) -> Optional[str]:
        """Find project root directory"""
        current = Path(file_path).parent
        root_indicators = {'.git', 'package.json', 'setup.py', 'pom.xml', 'build.gradle'}
        
        while current != current.parent:
            if any((current / indicator).exists() for indicator in root_indicators):
                return str(current)
            current = current.parent
        return None

    def _convert_semgrep_severity(self, severity: str) -> int:
        """Convert semgrep severity to numeric scale"""
        severity_map = {
            "ERROR": 9,
            "WARNING": 6,
            "INFO": 3,
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2
        }
        return severity_map.get(severity, 5)

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate security score based on vulnerabilities"""
        if not vulnerabilities:
            return 100
        
        score = 100
        severity_weights = {
            range(9, 11): 15,  # Critical: -15 points each
            range(7, 9): 10,   # High: -10 points each
            range(4, 7): 5,    # Medium: -5 points each
            range(1, 4): 2     # Low: -2 points each
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", 5)
            for severity_range, weight in severity_weights.items():
                if severity in severity_range:
                    score -= weight
                    break
        
        return max(0, min(100, score))

    def _prepare_prompt(self, code: str, context: Dict) -> str:
        """Prepare the prompt for OpenAI analysis"""
        context_info = self._optimize_context(code, context) if context else ""
        
        prompt = f"""Analyze this code for security vulnerabilities, considering the following context:
        
        {context_info}
        
        Code to analyze:
        {code}
        
        Required JSON format:
        {{
            "vulnerabilities": [
                {{
                    "type": "vulnerability type",
                    "severity": 1-10,
                    "description": "detailed description",
                    "line_number": line number,
                    "file": "relative path from project root (e.g. src/store.js)",
                    "risk_analysis": "potential impact",
                    "recommendation": "how to fix"
                }}
            ],
            "overall_score": 0-100,
            "summary": "brief security assessment"
        }}
        
        Important: 
        1. Use project-relative paths in the 'file' field.
        2. The file path relative to project root is: {self._get_relative_project_path(code)}
        3. Response MUST be valid JSON only, no other text.
        """
        
        return prompt

    async def _parse_response(self, result: str) -> Dict:
        """Parse response from OpenAI"""
        try:
            parsed = json.loads(result)
            if "vulnerabilities" not in parsed:
                return self._get_default_response()
            
            # 确保所有漏洞都标记为 AI 来源
            for vuln in parsed.get("vulnerabilities", []):
                vuln["source"] = "ai"
            
            return parsed
        
        except Exception as e:
            logger.error(f"Error parsing OpenAI response: {e}")
            return self._get_default_response()

    async def _call_api(self, prompt: str) -> str:
        """Call OpenAI API"""
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
            logger.error(f"API call failed: {e}")
            raise

    def _build_prompt(self, code: str, file_path: str, context: Dict = None) -> str:
        """Build prompt for code analysis"""
        return f"""
Analyze the following code for security vulnerabilities:

File: {file_path}

{code}

Context:
{json.dumps(context or {}, indent=2)}

Provide your analysis in the following JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability type",
            "severity": severity_score (1-10),
            "description": "detailed description",
            "line_number": line_number,
            "risk_analysis": "impact and risk description",
            "recommendation": "how to fix"
        }}
    ]
}}
"""

    async def _analyze_with_ai(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """OpenAI-specific implementation"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": f"Analyze this code:\n\n{code}"}
                ]
            )
            
            content = response.choices[0].message.content
            logger.debug(f"Raw response content: {content}")
            
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse response as JSON: {e}")
                return self._get_default_response()
                
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {e}")
            return self._get_default_response()

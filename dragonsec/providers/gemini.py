import google.generativeai as genai
from typing import List, Dict, Any, Optional
import json
from pathlib import Path
from .base import AIProvider

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        self.context_cache = {}

    async def analyze_code(self, code: str, file_path: str, context: Dict = None) -> Dict[str, Any]:
        """Analyze code using Gemini AI for security vulnerabilities"""
        relative_path = self._get_relative_project_path(file_path)
        context_info = self._optimize_context(file_path, context) if context else ""
        
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
        2. The file path relative to project root is: {relative_path}
        3. Response MUST be valid JSON only, no other text.
        """
        
        try:
            response = await self.model.generate_content_async(prompt)
            result = json.loads(response.text)
            
            for vuln in result.get("vulnerabilities", []):
                if "file" not in vuln or not vuln["file"]:
                    vuln["file"] = relative_path
            
            return result
        except Exception as e:
            print(f"Error during Gemini analysis: {e}")
            return self._get_default_response()

    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Merge and enhance semgrep results with AI analysis"""
        ai_vulns = ai_results.get("vulnerabilities", [])
        
        # process semgrep results
        semgrep_vulns = []
        for finding in semgrep_results:
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

    # reuse the same helper methods as OpenAIProvider
    def _optimize_context(self, file_path: str, context: Dict) -> str:
        """optimize context information, reduce token usage"""
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

    def _filter_relevant_deps(self, deps: Dict[str, str]) -> Dict[str, str]:
        """filter out security related dependencies"""
        security_related = {
            'crypto', 'security', 'auth', 'jwt', 'bcrypt', 'hash',
            'password', 'ssl', 'tls', 'https', 'oauth'
        }
        return {
            k: v for k, v in deps.items() 
            if any(term in k.lower() for term in security_related)
        }

    def _simplify_structure(self, structure: Dict) -> Dict:
        """simplify project structure, only keep key directories"""
        key_dirs = {'src', 'security', 'auth', 'api', 'controllers', 'routes'}
        return {
            k: v for k, v in structure.items() 
            if any(dir in k.lower() for dir in key_dirs)
        }

    def _filter_related_files(self, current_file: str, related: List[str], max_files: int = 3) -> List[str]:
        """select the most relevant files"""
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
        """filter out the most relevant imports"""
        security_related = {
            'crypto', 'security', 'auth', 'jwt', 'bcrypt',
            'hash', 'password', 'ssl', 'tls', 'https'
        }
        
        relevant = [imp for imp in imports if any(term in imp.lower() for term in security_related)]
        return relevant[:max_imports]

    def _get_default_response(self) -> Dict:
        """return default response"""
        return {
            "vulnerabilities": [],
            "overall_score": 0,
            "summary": "Failed to analyze code"
        }

    def _find_project_root(self, file_path: str) -> Optional[str]:
        """find the project root directory"""
        current = Path(file_path).parent
        root_indicators = {'.git', 'package.json', 'setup.py', 'pom.xml', 'build.gradle'}
        
        while current != current.parent:
            if any((current / indicator).exists() for indicator in root_indicators):
                return str(current)
            current = current.parent
        return None

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
            "low": 2
        }
        return severity_map.get(severity, 5)

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """calculate security score based on vulnerabilities"""
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
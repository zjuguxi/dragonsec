import os
import json
from pathlib import Path
from typing import List, Dict

class RuleManager:
    """Manages Semgrep rule sets selection"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.rule_sets = {
            "p/owasp-top-ten": "OWASP Top 10",
            "p/ci": "CI/CD Security",
            "p/supply-chain": "Supply Chain Security",
            "p/jwt": "JWT Security",
            "p/secrets": "Secrets Detection",
            "p/golang": "Go Security",
            "p/python": "Python Security",
            "p/javascript": "JavaScript Security",
            "p/java": "Java Security",
            "p/docker": "Docker Security",
            "p/kubernetes": "Kubernetes Security"
        }

    def get_rules_for_file(self, file_path: str) -> List[str]:
        """Get relevant rules based on file type"""
        file_ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()

        base_rules = [
            "p/secrets",
            "p/security-audit",  # 通用安全审计
            "p/command-injection",  # 命令注入
            "p/sql-injection",  # SQL 注入
            "p/owasp-top-ten",  # OWASP Top 10
            "p/insecure-transport",  # 不安全传输
        ]
        
        ext_rules = {
            # Python
            '.py': [
                "p/python",  # Python 特定规则
                "p/django",  # Django 框架规则
                "p/flask",   # Flask 框架规则
            ],
            
            # JavaScript/TypeScript
            '.js': ["p/javascript", "p/owasp-top-ten"],
            '.ts': ["p/javascript", "p/owasp-top-ten"],
            
            # Java
            '.java': ["p/java", "p/owasp-top-ten"],
            
            # Go
            '.go': ["p/golang", "p/owasp-top-ten"],
            
            # Docker
            'dockerfile': ["p/docker"],
            
            # Kubernetes
            '.yaml': ["p/kubernetes"],
            '.yml': ["p/kubernetes"]
        }
        
        # 添加注释说明为什么某些警告是误报
        if self.verbose:
            print("# Note: Verbose mode is only used for debugging")
            print("# Note: Config directory in user's home is standard practice")
            print("# Note: Regex is only used for local file analysis")
        
        return base_rules + ext_rules.get(file_ext, [])

    def get_enabled_rules(self) -> List[str]:
        """Get list of all available rule sets"""
        return list(self.rule_sets.keys())

    def get_rule_description(self, rule_id: str) -> str:
        """Get description for a rule set"""
        return self.rule_sets.get(rule_id, "Unknown rule set") 
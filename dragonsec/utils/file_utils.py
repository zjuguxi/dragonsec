# 新文件，包含所有文件处理相关功能
from pathlib import Path
from typing import Dict, List, Optional
import json
import re
import os

class FileContext:
    def __init__(self):
        self.root_indicators = {'.git', 'package.json', 'setup.py', 'pom.xml', 'build.gradle'}

    def get_context(self, file_path: str) -> Dict:
        context = {
            "content": "",
            "imports": [],
            "related_files": [],
            "project_structure": {},
            "dependencies": {}
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                context["content"] = f.read()
                
            root_dir = self.find_project_root(file_path)
            if root_dir:
                context["imports"] = self.analyze_imports(context["content"])
                context["related_files"] = self.find_related_files(file_path, root_dir)
                context["project_structure"] = self.get_project_structure(root_dir)
                context["dependencies"] = self.analyze_dependencies(root_dir)
                
        except Exception as e:
            print(f"Warning: Error collecting context for {file_path}: {e}")
            
        return context

    def find_project_root(self, file_path: str) -> Optional[str]:
        current = Path(file_path).parent
        while current != current.parent:
            if any((current / indicator).exists() for indicator in self.root_indicators):
                return str(current)
            current = current.parent
        return None

    def analyze_imports(self, content: str) -> List[str]:
        imports = []
        import_patterns = [
            r'^import\s+(.+)$',
            r'^from\s+(.+)\s+import',
            r'require\([\'"](.+)[\'"]\)',
            r'import.*from\s+[\'"](.+)[\'"]'
        ]
        
        for line in content.split('\n'):
            for pattern in import_patterns:
                if match := re.search(pattern, line.strip()):
                    imports.append(match.group(1))
        return imports

    def find_related_files(self, file_path: str, root_dir: str) -> List[str]:
        related = []
        file_name = Path(file_path).stem
        
        for ext in ['.py', '.js', '.ts', '.java', '.go', '.php']:
            related_path = Path(root_dir).rglob(f"*{file_name}*{ext}")
            related.extend(str(p) for p in related_path if str(p) != file_path)
        
        return related[:5]

    def get_project_structure(self, root_dir: str) -> Dict[str, List[str]]:
        structure = {}
        for root, _, files in os.walk(root_dir):
            rel_path = os.path.relpath(root, root_dir)
            if rel_path == '.':
                structure['/'] = files
            else:
                structure[rel_path] = files
        return structure

    def analyze_dependencies(self, root_dir: str) -> Dict[str, str]:
        dependencies = {}
        
        requirements_file = Path(root_dir) / 'requirements.txt'
        if requirements_file.exists():
            with open(requirements_file, 'r') as f:
                for line in f:
                    if '==' in line:
                        name, version = line.strip().split('==')
                        dependencies[name] = version
                        
        package_json = Path(root_dir) / 'package.json'
        if package_json.exists():
            with open(package_json, 'r') as f:
                data = json.load(f)
                dependencies.update(data.get('dependencies', {}))
                dependencies.update(data.get('devDependencies', {}))
                
        return dependencies

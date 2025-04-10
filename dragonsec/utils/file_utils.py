# New file, containing all file processing related functionality
from pathlib import Path
from typing import Dict, List, Optional
import json
import re
import os
import logging

logger = logging.getLogger(__name__)


class FileContext:
    """File context manager for security scanning"""

    def __init__(self, file_path: Optional[str] = None):
        from ..config import ROOT_INDICATORS
        self.root_indicators = ROOT_INDICATORS
        self._scan_root = None
        self._allowed_paths = set()
        self._imports = []  # Add import list
        self.content = ""  # Add content attribute

        if file_path:
            try:
                # Parse file path, get real path if it's a symbolic link
                path = Path(file_path)
                if path.is_symlink():
                    self.file_path = str(path.resolve())  # Save real file path
                else:
                    self.file_path = str(path)

                # Set scan root directory
                self.set_scan_root(str(Path(self.file_path).parent))
                # Add file directory to allowed list
                self.add_allowed_path(str(Path(self.file_path).parent))

                # Read file content
                try:
                    with open(self.file_path, "r", encoding="utf-8") as f:
                        self.content = f.read()
                except Exception as e:
                    logger.warning(f"Error reading file content: {e}")
                    self.content = ""

            except Exception as e:
                logger.warning(
                    f"Error initializing FileContext with path {file_path}: {e}"
                )
                # If error occurs, use current directory as root
                self.set_scan_root(str(Path.cwd()))
                self.file_path = file_path
                self.content = ""

    def set_scan_root(self, path: str) -> None:
        """Set scan root directory"""
        self._scan_root = Path(os.path.abspath(os.path.expanduser(path))).resolve()
        self._allowed_paths = {self._scan_root}  # Reset allowed paths

    def add_allowed_path(self, path: str) -> None:
        """Add additional allowed paths"""
        abs_path = Path(os.path.abspath(os.path.expanduser(path))).resolve()
        self._allowed_paths.add(abs_path)

    def _is_path_allowed(self, path: Path) -> bool:
        """Check if path is within allowed range"""
        try:
            # First check if it's a symbolic link
            if path.is_symlink():
                logger.warning(f"Symlink detected: {path}")
                return False

            path = path.resolve()

            # Check file permissions
            if os.access(path, os.W_OK):
                logger.debug(f"File is writable: {path}")

            # Use os.path.commonpath for stricter path checking
            for allowed_path in self._allowed_paths:
                allowed_path = allowed_path.resolve()
                try:
                    common = os.path.commonpath([str(path), str(allowed_path)])
                    if common == str(allowed_path):
                        return True
                except ValueError:
                    continue

            logger.warning(f"Path not in allowed directories: {path}")
            return False

        except Exception as e:
            logger.error(f"Error checking path: {e}")
            return False

    def get_context(self, file_path: str) -> Dict:
        """Get context information for a file"""
        try:
            path = Path(file_path).resolve()

            # If scan root is not set, use file directory
            if not self._scan_root:
                self.set_scan_root(str(path.parent))

            # Check if path is within allowed range
            if not self._is_path_allowed(path):
                # Automatically add file directory to allowed list
                self.add_allowed_path(str(path.parent))

            # Check if it's a binary file
            try:
                if self.is_binary_file(str(path)):
                    return {
                        "content": "",
                        "imports": [],
                        "related_files": [],
                        "error": "Binary file detected",
                    }
            except Exception as e:
                return self._get_error_response(f"Error reading file: {e}")

            # Read text content
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                return {
                    "content": "",
                    "imports": [],
                    "related_files": [],
                    "error": "Binary or non-UTF8 file detected",
                }

            # Analyze imports
            imports = self.analyze_imports(content)

            return {
                "content": content,
                "imports": imports,
                "related_files": self.find_related_files(str(path)),
                "error": None,
            }

        except Exception as e:
            logger.error(f"Error getting context for {file_path}: {e}")
            return {"content": "", "imports": [], "related_files": [], "error": str(e)}

    def _get_scan_root(self) -> Path:
        """Get scan root directory"""
        if self._scan_root is None:
            return Path(os.getenv("DRAGONSEC_SCAN_ROOT", Path.cwd())).resolve()
        return Path(self._scan_root).resolve()

    def find_project_root(self, file_path: str) -> Optional[str]:
        current = Path(file_path).parent
        while current != current.parent:
            if any(
                (current / indicator).exists() for indicator in self.root_indicators
            ):
                return str(current)
            current = current.parent
        return None

    def analyze_imports(self, content: str) -> List[str]:
        """Analyze imports in code content"""
        # Limit input size to prevent ReDoS
        MAX_SIZE = 1024 * 1024  # 1MB
        if len(content) > MAX_SIZE:
            logger.warning(f"File too large for import analysis: {len(content)} bytes")
            return []

        imports = []
        try:
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # JavaScript require
                if "require(" in line:
                    match = re.search(r"require\(['\"](.+?)['\"]\)", line)
                    if match:
                        imports.append(match.group(1))

                # ES6 import
                elif " from " in line:
                    # Extract module name
                    match = re.search(r"from ['\"](.+?)['\"]", line)
                    if match:
                        module = match.group(1)
                        imports.append(module)

                    # Extract imported content
                    if line.startswith("import "):
                        # Handle import { x } from 'y' case
                        content_match = re.search(
                            r"import\s*{?\s*([^}]+?)\s*}?\s*from", line
                        )
                        if content_match:
                            imported = content_match.group(1).strip()
                            if imported != "*":
                                imports.append(imported)

                # Simple import
                elif line.startswith("import "):
                    # Handle import x as y case
                    for part in line[7:].split(","):
                        part = part.strip()
                        if " as " in part:
                            module = part.split(" as ")[0].strip()
                        else:
                            module = part
                        imports.append(module)

                # from ... import ...
                elif line.startswith("from "):
                    if " import " in line:
                        module = line[5 : line.index(" import ")].strip()
                        imports.append(module)

            return list(
                set(imp for imp in imports if imp)
            )  # Remove duplicates and empty values

        except Exception as e:
            logger.error(f"Error analyzing imports: {e}")
            return []

    def find_related_files(self, file_path: str, max_files: int = 5) -> List[str]:
        """Find files related to the given file based on imports

        Args:
            file_path: Path to the file
            max_files: Maximum number of related files to return

        Returns:
            List of related file paths
        """
        try:
            path = Path(file_path).resolve()
            scan_root = self._get_scan_root()

            # Skip binary files
            if self.is_binary_file(str(path)):
                return []

            # Get file content
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                logger.warning(f"Cannot decode file as UTF-8: {file_path}")
                return []

            # Analyze import statements
            imports = self.analyze_imports(content)
            related = []

            # Find imported module files
            for imp in imports:
                # Remove possible relative import prefix
                imp = imp.replace(".", "").replace("/", "")
                for ext in [".py", ".js", ".ts", ".java", ".go", ".php"]:
                    pattern = f"{imp}{ext}"
                    for p in scan_root.rglob(pattern):
                        if p.is_file() and p != path:
                            related.append(str(p))

            return related[:max_files]  # Limit return count
        except Exception as e:
            logger.error(f"Error finding related files: {e}")
            return []

    def get_project_structure(self) -> Dict[str, List[str]]:
        """Get project structure

        Returns:
            Dictionary mapping directories to lists of files
        """
        # Use scan root directory
        scan_root = self._get_scan_root()
        structure = {}

        for root, _, files in os.walk(scan_root):
            rel_path = os.path.relpath(root, scan_root)
            if rel_path == ".":
                structure["/"] = files
            else:
                structure[rel_path] = files
        return structure

    def analyze_dependencies(self) -> Dict[str, str]:
        """Analyze project dependencies

        Returns:
            Dictionary mapping package names to versions
        """
        # Use scan root directory
        scan_root = self._get_scan_root()
        dependencies = {}

        # Check dependency files
        requirements_file = scan_root / "requirements.txt"
        if requirements_file.exists():
            with open(requirements_file, "r") as f:
                for line in f:
                    if "==" in line:
                        name, version = line.strip().split("==")
                        dependencies[name] = version

        package_json = scan_root / "package.json"
        if package_json.exists():
            with open(package_json, "r") as f:
                data = json.load(f)
                dependencies.update(data.get("dependencies", {}))
                dependencies.update(data.get("devDependencies", {}))

        return dependencies

    def is_binary_file(self, file_path: str) -> bool:
        """Check if a file is a binary file

        Args:
            file_path: Path to the file

        Returns:
            True if the file is binary, False otherwise
        """
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                return b"\0" in chunk or b"\x00" in chunk
        except Exception as e:
            logger.error(f"Error checking if file is binary: {e}")
            return False

    def is_text_file(self, file_path: str) -> bool:
        """Check if a file is a text file

        Args:
            file_path: Path to the file

        Returns:
            True if the file is text, False otherwise
        """
        return not self.is_binary_file(file_path)

    def is_file_in_scan_root(self, file_path: str, scan_root: str) -> bool:
        """Check if file is within scan root"""
        try:
            # Normalize path
            file_path = os.path.abspath(file_path)
            scan_root = os.path.abspath(scan_root)

            # Check if file path starts with scan root
            return file_path.startswith(scan_root)
        except Exception as e:
            logger.error(f"Error checking file path: {e}")
            return False

    def _get_error_response(self, error_msg: str) -> Dict:
        """Uniform error response format"""
        from ..providers.base import create_error_response

        # 创建文件上下文特定的错误响应
        response = {"content": "", "imports": [], "related_files": []}
        response["error"] = error_msg
        return create_error_response(error_msg, include_metadata=True)

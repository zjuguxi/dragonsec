import pytest
from pathlib import Path
from dragonsec.utils.file_utils import FileContext
import tempfile
import os
import json
from typing import List

@pytest.fixture
def file_context():
    return FileContext()

@pytest.fixture
def sample_file_path():
    return Path(__file__).parent.parent / "fixtures" / "sample_file.py"

@pytest.fixture(scope="session")
def fixtures_dir():
    path = Path(__file__).parent / "fixtures"
    path.mkdir(parents=True, exist_ok=True)
    return path

def test_file_context_initialization():
    """Test FileContext initialization"""
    context = FileContext()
    assert context._scan_root is None
    assert context._allowed_paths == set()
    assert context._imports == []

def test_set_scan_root():
    """Test setting scan root directory"""
    context = FileContext()
    test_dir = "/test/dir"
    context.set_scan_root(test_dir)
    assert str(context._scan_root) == os.path.abspath(test_dir)
    assert context._allowed_paths == {context._scan_root}

def test_add_allowed_path(tmp_path):
    """Test adding allowed path"""
    context = FileContext()
    # Use temporary directory instead of hardcoded paths
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    context.add_allowed_path(str(test_dir))
    assert test_dir.resolve() in context._allowed_paths

def test_get_context_with_valid_file(tmp_path):
    """Test getting context with valid file"""
    test_file = tmp_path / "test.py"
    test_file.write_text("""
import os
from pathlib import Path
import sys
""")

    context = FileContext()
    result = context.get_context(str(test_file))

    assert result["content"] == test_file.read_text()
    assert "os" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "sys" in result["imports"]
    assert result["error"] is None

def test_get_context_with_binary_file(tmp_path):
    """Test handling binary file"""
    binary_file = tmp_path / "test.bin"
    with open(binary_file, 'wb') as f:
        f.write(b'\x00\x01\x02\x03')

    context = FileContext()
    result = context.get_context(str(binary_file))

    assert result["content"] == ""
    assert result["imports"] == []
    assert result["error"] is not None
    assert "Binary file" in result["error"]

def test_get_context_with_nonexistent_file(tmp_path):
    """Test handling nonexistent file"""
    context = FileContext()
    # Use non-existent file in temporary directory
    nonexistent_file = tmp_path / "nonexistent.py"
    result = context.get_context(str(nonexistent_file))
    assert result["content"] == ""
    assert result["imports"] == []
    assert result["error"] is not None
    # Use more generic error message check
    assert any(msg in result["error"] for msg in ["No such file", "File not found"])

def test_find_project_root(tmp_path):
    """Test finding project root directory"""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    (project_dir / ".git").mkdir()

    test_file = project_dir / "src" / "test.py"
    test_file.parent.mkdir()
    test_file.touch()

    context = FileContext()
    root = context.find_project_root(str(test_file))
    assert root == str(project_dir)

def test_find_related_files(tmp_path):
    """Test finding related files"""
    # Create test files
    main_file = tmp_path / "main.py"
    main_file.write_text("from module import func")
    module_file = tmp_path / "module.py"
    module_file.write_text("def func(): pass")

    context = FileContext()
    # Set scan root
    context.set_scan_root(str(tmp_path))

    # Debug information
    print(f"Scan root: {context._get_scan_root()}")
    print(f"Main file: {main_file}")
    print(f"Module file: {module_file}")

    result = context.get_context(str(main_file))

    # Debug information
    print(f"Related files: {result['related_files']}")

    # Use Path object for comparison
    assert any(Path(f) == module_file for f in result["related_files"])

def test_analyze_imports():
    """Test import analysis"""
    context = FileContext()
    code = """
    import os
    from pathlib import Path
    from .local_module import func
    import sys as system
    from random import randint, choice
    """
    imports = context.analyze_imports(code)

    assert "os" in imports
    assert "pathlib" in imports
    assert ".local_module" in imports
    assert "sys" in imports
    assert "random" in imports

def test_file_context_symlink_handling(tmp_path):
    """Test symbolic link handling"""
    # Skip this test on Windows
    if os.name == 'nt':
        pytest.skip("Symbolic link test skipped on Windows")

    real_file = tmp_path / "real.py"
    real_file.write_text("print('test')")
    symlink = tmp_path / "link.py"
    symlink.symlink_to(real_file)

    context = FileContext(str(symlink))
    assert context.file_path == str(real_file)

    result = context.get_context(str(symlink))
    assert result["content"] == "print('test')"
    assert result["error"] is None

def test_get_project_structure(tmp_path):
    """Test getting project structure"""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()

    # Create project structure
    (project_dir / "src").mkdir()
    (project_dir / "src" / "main.py").write_text("print('main')")
    (project_dir / "tests").mkdir()
    (project_dir / "tests" / "test_main.py").write_text("def test(): pass")

    context = FileContext()
    context.set_scan_root(str(project_dir))
    structure = context.get_project_structure(str(project_dir))

    assert "src" in structure
    assert "tests" in structure
    assert "main.py" in structure["src"]
    assert "test_main.py" in structure["tests"]

def test_analyze_dependencies(tmp_path):
    """Test dependency analysis"""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()

    # Create dependency files
    (project_dir / "requirements.txt").write_text("""
requests==2.28.0
pytest==7.0.0
""")

    (project_dir / "package.json").write_text(json.dumps({
        "dependencies": {
            "lodash": "^4.17.21"
        },
        "devDependencies": {
            "jest": "^29.0.0"
        }
    }))

    context = FileContext()
    context.set_scan_root(str(project_dir))
    deps = context.analyze_dependencies(str(project_dir))

    assert "requests" in deps
    assert "pytest" in deps
    assert "lodash" in deps
    assert "jest" in deps

def test_get_context(sample_file_path):
    try:
        context = FileContext()
        result = context.get_context(str(sample_file_path))
        assert "content" in result
        assert "imports" in result
        assert isinstance(result["content"], str)
        assert isinstance(result["imports"], list)
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

def test_get_context_with_imports(fixtures_dir):
    """Test getting file context with imports"""
    code = """
import os
from pathlib import Path
import sys
"""
    test_file = fixtures_dir / "test_imports.py"
    test_file.write_text(code.strip())  # Remove leading whitespace

    context = FileContext()
    result = context.get_context(str(test_file))

    assert result["imports"]  # Ensure imports exist
    assert "os" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "sys" in result["imports"]

def test_find_project_root_with_git():
    """Test finding project root with .git directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create .git directory
        (tmpdir / ".git").mkdir()

        # Create nested file
        test_dir = tmpdir / "src" / "module"
        test_dir.mkdir(parents=True)
        test_file = test_dir / "test.py"
        test_file.touch()

        context = FileContext()
        root = context.find_project_root(str(test_file))
        assert root == str(tmpdir)

def test_file_context_with_large_file(tmp_path):
    """Test handling of large files"""
    large_file = tmp_path / "large.py"
    # Create a large file exceeding the limit
    large_content = "x" * (2 * 1024 * 1024)  # 2MB
    large_file.write_text(large_content)

    context = FileContext()
    result = context.get_context(str(large_file))
    assert result["imports"] == []  # Large files should skip import analysis

def test_file_context_with_complex_imports(tmp_path):
    """Test handling of complex import patterns"""
    test_file = tmp_path / "complex_imports.py"
    content = """
    import os, sys, json
    from pathlib import Path
    from .local_module import something
    from ..parent_module import another_thing
    import security.crypto as crypto
    from auth.utils import *
    """
    test_file.write_text(content)

    context = FileContext()
    result = context.get_context(str(test_file))
    assert "os" in result["imports"]
    assert "sys" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "security.crypto" in result["imports"]
    assert "auth.utils" in result["imports"]

def test_file_context_with_js_imports(tmp_path):
    """Test handling of JavaScript imports"""
    test_file = tmp_path / "module.js"
    content = """
    const crypto = require('crypto');
    import { auth } from '@company/auth';
    import security from './security';
    """
    test_file.write_text(content)

    context = FileContext()
    result = context.get_context(str(test_file))
    assert "crypto" in result["imports"]
    assert "@company/auth" in result["imports"]
    assert "./security" in result["imports"]

def test_file_context_binary_file_handling(tmp_path):
    """Test handling of binary files"""
    # Create a binary file
    binary_file = tmp_path / "test.bin"
    with open(binary_file, 'wb') as f:
        f.write(b'\x00\x01\x02\x03')

    context = FileContext()
    result = context.get_context(str(binary_file))
    assert result["error"] is not None

def find_related_files(self, file_path: str) -> List[str]:
    try:
        path = Path(file_path).resolve()
        scan_root = self._get_scan_root()

        # Get filename without extension
        file_name = path.stem
        related = []

        # Find related files under scan root
        for ext in ['.py', '.js', '.ts', '.java', '.go', '.php']:
            # Modify matching pattern to be more precise
            pattern = f"{file_name}{ext}"  # Exact filename match
            for p in scan_root.rglob(pattern):
                if p.is_file() and p != path:
                    related.append(str(p))

        return related[:5]  # Limit return count

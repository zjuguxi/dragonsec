import pytest
from pathlib import Path
from dragonsec.utils.file_utils import FileContext
import tempfile

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

def test_analyze_imports(file_context):
    code = """
    import os
    from crypto.cipher import AES
    import security.auth
    from random import randint
    """
    imports = file_context.analyze_imports(code)
    assert "crypto.cipher" in imports
    assert "security.auth" in imports
    assert "random" in imports

def test_find_project_root(file_context, tmp_path):
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    (project_dir / ".git").mkdir()
    
    test_file = project_dir / "src" / "test.py"
    test_file.parent.mkdir()
    test_file.touch()
    
    root = file_context.find_project_root(str(test_file))
    assert root == str(project_dir)

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
    test_file.write_text(code)
    
    context = FileContext()
    result = context.get_context(str(test_file))
    assert "os" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "sys" in result["imports"]
    
    test_file.unlink()

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
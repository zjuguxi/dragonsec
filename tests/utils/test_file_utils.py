import pytest
from pathlib import Path
from dragonsec.utils.file_utils import FileContext

@pytest.fixture
def file_context():
    return FileContext()

@pytest.fixture
def sample_file_path():
    return Path(__file__).parent.parent / "fixtures" / "sample_file.py"

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
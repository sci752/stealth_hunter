
import pytest
import os
import tempfile
import sys
from pathlib import Path
from core.auto_discovery import DiscoveryEngine, get_attack_modules
from core.models import ScanResult, Severity


class TestDiscoveryEngine:
    """Unit tests for the DiscoveryEngine class."""
    
    @pytest.fixture
    def temp_attacks_dir(self):
        """Create a temporary directory for test attack modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_initialization_with_existing_directory(self, temp_attacks_dir):
        """Test DiscoveryEngine initializes correctly with existing directory."""
        engine = DiscoveryEngine(temp_attacks_dir)
        
        assert engine.directory == temp_attacks_dir
        assert os.path.exists(engine.absolute_path)
        assert engine.absolute_path == os.path.abspath(temp_attacks_dir)
    
    def test_initialization_creates_missing_directory(self):
        """Test that DiscoveryEngine creates missing directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_dir = os.path.join(tmpdir, "nonexistent", "attacks")
            
            engine = DiscoveryEngine(missing_dir)
            
            assert os.path.exists(engine.absolute_path)
    
    def test_validate_contract_accepts_valid_module(self, temp_attacks_dir):
        """Test that _validate_contract accepts valid modules."""
        # Create a valid attack module file
        valid_module_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Valid_Test_Module",
        description="Test module"
    )
"""
        module_path = os.path.join(temp_attacks_dir, "valid_module.py")
        with open(module_path, "w") as f:
            f.write(valid_module_code)
        
        # Load and validate
        import importlib.util
        spec = importlib.util.spec_from_file_location("valid_module", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        assert engine._validate_contract(module) is True
    
    def test_validate_contract_rejects_missing_execute(self, temp_attacks_dir):
        """Test that _validate_contract rejects modules without execute function."""
        # Create a module without execute function
        invalid_module_code = """
def some_other_function(target: str):
    pass
"""
        module_path = os.path.join(temp_attacks_dir, "invalid_module.py")
        with open(module_path, "w") as f:
            f.write(invalid_module_code)
        
        # Load and validate
        import importlib.util
        spec = importlib.util.spec_from_file_location("invalid_module", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        assert engine._validate_contract(module) is False
    
    def test_validate_contract_rejects_wrong_parameter_count(self, temp_attacks_dir):
        """Test that _validate_contract rejects execute() without target parameter."""
        # Create a module with execute() but wrong signature
        invalid_module_code = """
def execute():
    pass
"""
        module_path = os.path.join(temp_attacks_dir, "invalid_module.py")
        with open(module_path, "w") as f:
            f.write(invalid_module_code)
        
        # Load and validate
        import importlib.util
        spec = importlib.util.spec_from_file_location("invalid_module", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        assert engine._validate_contract(module) is False
    
    def test_validate_contract_rejects_non_function(self, temp_attacks_dir):
        """Test that _validate_contract rejects if execute is not a function."""
        # Create a module with execute as a variable
        invalid_module_code = """
execute = "not a function"
"""
        module_path = os.path.join(temp_attacks_dir, "invalid_module.py")
        with open(module_path, "w") as f:
            f.write(invalid_module_code)
        
        # Load and validate
        import importlib.util
        spec = importlib.util.spec_from_file_location("invalid_module", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        assert engine._validate_contract(module) is False
    
    def test_load_all_finds_valid_modules(self, temp_attacks_dir):
        """Test that load_all discovers and loads valid modules."""
        # Create two valid modules
        for i in range(2):
            module_code = f"""
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Test_Module_{i}",
        description="Test module {i}"
    )
"""
            module_path = os.path.join(temp_attacks_dir, f"test_module_{i}.py")
            with open(module_path, "w") as f:
                f.write(module_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        assert len(modules) == 2
        assert all(callable(m) for m in modules)
    
    def test_load_all_skips_invalid_modules(self, temp_attacks_dir):
        """Test that load_all skips invalid modules but continues loading."""
        # Create one valid and one invalid module
        valid_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Valid_Module",
        description="Valid"
    )
"""
        invalid_code = """
def not_execute():
    pass
"""
        
        with open(os.path.join(temp_attacks_dir, "valid.py"), "w") as f:
            f.write(valid_code)
        
        with open(os.path.join(temp_attacks_dir, "invalid.py"), "w") as f:
            f.write(invalid_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        # Should load only the valid module
        assert len(modules) == 1
    
    def test_load_all_skips_init_file(self, temp_attacks_dir):
        """Test that load_all skips __init__.py files."""
        init_code = """
# This should be skipped
"""
        valid_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Real_Module",
        description="Real"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "__init__.py"), "w") as f:
            f.write(init_code)
        
        with open(os.path.join(temp_attacks_dir, "real_module.py"), "w") as f:
            f.write(valid_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        # Should load only real_module, not __init__.py
        assert len(modules) == 1
    
    def test_load_all_handles_syntax_errors(self, temp_attacks_dir):
        """Test that load_all handles syntax errors gracefully."""
        # Create a module with syntax error
        syntax_error_code = """
def execute(target: str) -> ScanResult:
    this is not valid python!!
"""
        
        valid_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Valid",
        description="Valid"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "broken.py"), "w") as f:
            f.write(syntax_error_code)
        
        with open(os.path.join(temp_attacks_dir, "working.py"), "w") as f:
            f.write(valid_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        # Should load only the valid module (syntax error should be caught)
        assert len(modules) == 1
    
    def test_load_all_handles_import_errors(self, temp_attacks_dir):
        """Test that load_all handles import errors gracefully."""
        # Create a module with import error
        import_error_code = """
import nonexistent_library

def execute(target: str):
    pass
"""
        
        valid_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Valid",
        description="Valid"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "broken.py"), "w") as f:
            f.write(import_error_code)
        
        with open(os.path.join(temp_attacks_dir, "working.py"), "w") as f:
            f.write(valid_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        # Should load only the valid module (import error should be caught)
        assert len(modules) == 1
    
    def test_load_all_returns_empty_list_for_empty_directory(self, temp_attacks_dir):
        """Test that load_all returns empty list when directory is empty."""
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        assert modules == []
        assert isinstance(modules, list)
    
    def test_load_all_discovers_nested_modules(self, temp_attacks_dir):
        """Test that load_all finds modules in subdirectories."""
        # Create subdirectory with module
        subdir = os.path.join(temp_attacks_dir, "subdirectory")
        os.makedirs(subdir)
        
        module_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Nested_Module",
        description="Nested"
    )
"""
        
        with open(os.path.join(subdir, "nested_module.py"), "w") as f:
            f.write(module_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        assert len(modules) == 1
    
    def test_get_attack_modules_convenience_function(self, temp_attacks_dir):
        """Test the get_attack_modules convenience function."""
        # Create a valid module
        module_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Test",
        description="Test"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "test.py"), "w") as f:
            f.write(module_code)
        
        modules = get_attack_modules(temp_attacks_dir)
        
        assert len(modules) == 1
        assert callable(modules[0])
    
    def test_module_isolation(self, temp_attacks_dir):
        """Test that modules are loaded in isolated namespaces."""
        # Create two modules with same function names but different behavior
        module1_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Module1",
        description="Module 1"
    )
"""
        
        module2_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Module2",
        description="Module 2"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "module1.py"), "w") as f:
            f.write(module1_code)
        
        with open(os.path.join(temp_attacks_dir, "module2.py"), "w") as f:
            f.write(module2_code)
        
        engine = DiscoveryEngine(temp_attacks_dir)
        modules = engine.load_all()
        
        # Both should be loaded
        assert len(modules) == 2
        
        # Call both and verify they return different module names
        result1 = modules[0]("http://example.com")
        result2 = modules[1]("http://example.com")
        
        assert result1.module_name in ["Module1", "Module2"]
        assert result2.module_name in ["Module1", "Module2"]
        assert result1.module_name != result2.module_name


class TestModuleExecution:
    """Test that loaded modules can be executed correctly."""
    
    @pytest.fixture
    def temp_attacks_dir(self):
        """Create a temporary directory for test attack modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_module_execution_returns_scan_result(self, temp_attacks_dir):
        """Test that executing a module returns a valid ScanResult."""
        module_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=True,
        module_name="Test_Module",
        severity=Severity.HIGH,
        description="Test vulnerability",
        evidence="Test evidence"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "test.py"), "w") as f:
            f.write(module_code)
        
        modules = get_attack_modules(temp_attacks_dir)
        result = modules[0]("http://example.com")
        
        assert isinstance(result, ScanResult)
        assert result.is_vulnerable is True
        assert result.module_name == "Test_Module"
        assert result.severity == Severity.HIGH
    
    def test_module_receives_target_parameter(self, temp_attacks_dir):
        """Test that modules receive the target parameter correctly."""
        module_code = """
from core.models import ScanResult, Severity

def execute(target: str) -> ScanResult:
    return ScanResult(
        is_vulnerable=False,
        module_name="Echo_Module",
        description=f"Received target: {target}"
    )
"""
        
        with open(os.path.join(temp_attacks_dir, "echo.py"), "w") as f:
            f.write(module_code)
        
        modules = get_attack_modules(temp_attacks_dir)
        test_target = "https://test.example.com"
        result = modules[0](test_target)
        
        assert test_target in result.description


if __name__ == "__main__":
    # Run tests with: pytest tests/test_auto_discovery.py -v
    pytest.main([__file__, "-v", "--tb=short"])


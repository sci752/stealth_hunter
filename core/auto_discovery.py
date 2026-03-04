import os
import sys
import importlib.util
import inspect
import logging
from typing import List, Callable, Optional
from types import ModuleType
import config

# Setup enterprise-grade logging
logging.basicConfig(level=logging.getLevelName(config.LOG_LEVEL), format=config.LOG_FORMAT)
logger = logging.getLogger("DiscoveryEngine")


class DiscoveryEngine:
    """
    Highly advanced module discovery system.
    Scans, validates, and hot-loads attack libraries dynamically.
    
    This system allows you to drop new Python files into the attacks/ directory
    and they are automatically discovered and loaded on the next run without
    modifying the core framework.
    
    Requirements for attack modules:
    - Must contain an `execute(target: str) -> ScanResult` function
    - Must return a ScanResult object from core.models
    """
    
    def __init__(self, directory: str = None):
        """
        Initialize the DiscoveryEngine.
        
        Args:
            directory (str): Path to the attacks directory. Defaults to config.ATTACKS_DIRECTORY.
                If directory doesn't exist, it will be created automatically.
        """
        self.directory = directory or config.ATTACKS_DIRECTORY
        self.absolute_path = os.path.abspath(self.directory)
        
        logger.debug(f"DiscoveryEngine initialized with directory: {self.absolute_path}")
        
        # Auto-create directory if missing
        if not os.path.exists(self.absolute_path):
            if config.AUTO_CREATE_ATTACKS_DIR:
                try:
                    os.makedirs(self.absolute_path)
                    logger.info(f"Created missing attack directory: {self.absolute_path}")
                except OSError as e:
                    logger.error(f"Failed to create attacks directory: {e}")
                    raise
            else:
                logger.error(f"Attacks directory not found: {self.absolute_path}")
                raise FileNotFoundError(f"Directory not found: {self.absolute_path}")

    def _validate_contract(self, module: ModuleType) -> bool:
        """
        Ensures the module contains the mandatory 'execute' function 
        with the correct signature.
        
        Args:
            module (ModuleType): The loaded Python module to validate.
        
        Returns:
            bool: True if module has valid execute(target) function, False otherwise.
        """
        # Check if module has 'execute' attribute
        if not hasattr(module, 'execute'):
            logger.debug(f"Module validation failed: no 'execute' function found")
            return False
        
        # Check if it's actually a function
        func = getattr(module, 'execute')
        if not inspect.isfunction(func):
            logger.debug(f"Module validation failed: 'execute' is not a function (type: {type(func)})")
            return False
        
        # Check if it accepts at least one argument (the target URL)
        try:
            params = inspect.signature(func).parameters
            param_count = len(params)
            
            if param_count < 1:
                logger.debug(f"Module validation failed: execute() requires at least 1 parameter, has {param_count}")
                return False
            
            logger.debug(f"Module validation passed: execute() has {param_count} parameter(s)")
            return True
            
        except Exception as e:
            logger.debug(f"Module validation failed during signature check: {e}")
            return False

    def load_all(self) -> List[Callable]:
        """
        Performs a deep sweep of the attacks directory.
        Recursively scans subdirectories and loads all Python modules.
        Returns only validated execution functions.
        
        Returns:
            List[Callable]: List of validated execute() functions ready to be called.
                Empty list if no valid modules found.
        """
        attack_functions = []
        logger.info(f"Initiating deep sweep of {self.directory}/...")

        try:
            for root, dirs, files in os.walk(self.absolute_path):
                for file in files:
                    # Skip non-Python files and __init__.py
                    if not file.endswith(".py") or file == "__init__.py":
                        continue
                    
                    module_name = file[:-3]  # Remove .py extension
                    file_path = os.path.join(root, file)
                    
                    try:
                        # 1. Create an isolated module specification
                        spec = importlib.util.spec_from_file_location(module_name, file_path)
                        
                        if spec is None or spec.loader is None:
                            logger.warning(f"Skipped '{file}': Could not create module spec")
                            continue
                        
                        # 2. Create module object from spec
                        new_module = importlib.util.module_from_spec(spec)
                        
                        # 3. Execute the module in its own isolated namespace
                        spec.loader.exec_module(new_module)
                        
                        # 4. Strict Contract Validation
                        if self._validate_contract(new_module):
                            attack_functions.append(new_module.execute)
                            logger.info(f"Loaded attack module: '{file}' ✓")
                        else:
                            logger.warning(
                                f"Rejected: '{file}' - Fails Contract Validation. "
                                f"Must have execute(target: str) -> ScanResult function."
                            )
                    
                    except SyntaxError as syntax_err:
                        logger.error(f"Syntax error in '{file}': {syntax_err}")
                        continue
                        
                    except ImportError as import_err:
                        logger.error(f"Import error in '{file}': {import_err}")
                        continue
                        
                    except Exception as e:
                        logger.error(f"Critical failure loading '{file}': {type(e).__name__}: {e}")
                        if config.LOG_FULL_TRACEBACK:
                            logger.debug(f"Traceback:", exc_info=True)
                        continue
            
            # Summary logging
            if attack_functions:
                logger.info(f"Discovery complete. {len(attack_functions)} attack module(s) armed and ready.")
            else:
                logger.warning(f"Discovery complete. No valid attack modules found in {self.directory}/")
            
            return attack_functions
            
        except Exception as e:
            logger.error(f"Fatal error during module discovery: {e}")
            if config.LOG_FULL_TRACEBACK:
                logger.debug(f"Traceback:", exc_info=True)
            return []


def get_attack_modules(directory: str = None) -> List[Callable]:
    """
    Convenience function to discover and load attack modules.
    This is the main entry point called by the orchestrator.
    
    Args:
        directory (str): Path to attacks directory. If None, uses config.ATTACKS_DIRECTORY.
    
    Returns:
        List[Callable]: List of validated execute() functions ready to be called.
    
    Example:
        modules = get_attack_modules("attacks")
        for attack_func in modules:
            result = attack_func(target_url)
    """
    try:
        engine = DiscoveryEngine(directory or config.ATTACKS_DIRECTORY)
        return engine.load_all()
    except Exception as e:
        logger.error(f"Failed to initialize DiscoveryEngine: {e}")
        if config.LOG_FULL_TRACEBACK:
            logger.debug(f"Traceback:", exc_info=True)
        return []

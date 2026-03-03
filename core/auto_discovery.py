import os
import sys
import importlib.util
import inspect
import logging
from typing import List, Callable, Optional
from types import ModuleType

# Setup enterprise-grade logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("DiscoveryEngine")

class DiscoveryEngine:
    """
    Highly advanced module discovery system.
    Scans, validates, and hot-loads attack libraries dynamically.
    """
    def __init__(self, directory: str = "attacks"):
        self.directory = directory
        self.absolute_path = os.path.abspath(directory)
        
        if not os.path.exists(self.absolute_path):
            os.makedirs(self.absolute_path)
            logger.info(f"Created missing attack directory: {self.absolute_path}")

    def _validate_contract(self, module: ModuleType) -> bool:
        """
        Ensures the module contains the mandatory 'execute' function 
        with the correct signature.
        """
        if not hasattr(module, 'execute'):
            return False
        
        func = getattr(module, 'execute')
        if not inspect.isfunction(func):
            return False
            
        # Check if it accepts at least one argument (the target URL)
        params = inspect.signature(func).parameters
        return len(params) >= 1

    def load_all(self) -> List[Callable]:
        """
        Performs a deep sweep of the attacks directory.
        Returns only validated execution functions.
        """
        attack_functions = []
        logger.info(f"Initiating deep sweep of {self.directory}/...")

        for root, _, files in os.walk(self.absolute_path):
            for file in files:
                if file.endswith(".py") and file != "__init__.py":
                    module_name = file[:-3]
                    file_path = os.path.join(root, file)
                    
                    try:
                        # 1. Create a isolated module specification
                        spec = importlib.util.spec_from_file_location(module_name, file_path)
                        if spec and spec.loader:
                            new_module = importlib.util.module_from_spec(spec)
                            
                            # 2. Execute the module in its own namespace
                            spec.loader.exec_module(new_module)
                            
                            # 3. Strict Contract Validation
                            if self._validate_contract(new_module):
                                attack_functions.append(new_module.execute)
                            else:
                                logger.warning(f"Rejected: '{file}' - Fails Contract Validation.")
                                
                    except Exception as e:
                        logger.error(f"Critical Failure loading '{file}': {e}")
                        continue

        logger.info(f"Discovery complete. {len(attack_functions)} libraries armed and ready.")
        return attack_functions

# Singleton helper for the orchestrator
def get_attack_modules() -> List[Callable]:
    engine = DiscoveryEngine()
    return engine.load_all()
                  

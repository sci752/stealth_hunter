
import os
import importlib.util
import inspect
import logging
from typing import List, Callable
from types import ModuleType
import config

# FIX: Removed logging.basicConfig() call here. Logging configuration belongs
# exclusively in the entry point (orchestrator.py). Calling basicConfig() in
# submodules causes duplicate handlers and fights with the orchestrator's setup.
logger = logging.getLogger("DiscoveryEngine")


class DiscoveryEngine:
    """
    Dynamic module discovery system.
    Scans, validates, and hot-loads attack libraries from the attacks/ directory.

    Requirements for attack modules:
    - Must contain an `execute(target: str) -> ScanResult` function
    - Must return a ScanResult object from core.models
    """

    def __init__(self, directory: str = None):
        """
        Initialize the DiscoveryEngine.

        Args:
            directory (str): Path to the attacks directory. Defaults to config.ATTACKS_DIRECTORY.
        """
        self.directory = directory or config.ATTACKS_DIRECTORY
        self.absolute_path = os.path.abspath(self.directory)

        logger.debug(f"DiscoveryEngine initialized with directory: {self.absolute_path}")

        if not os.path.exists(self.absolute_path):
            if config.AUTO_CREATE_ATTACKS_DIR:
                try:
                    os.makedirs(self.absolute_path, exist_ok=True)
                    logger.info(f"Created missing attack directory: {self.absolute_path}")
                except OSError as e:
                    logger.error(f"Failed to create attacks directory: {e}")
                    raise
            else:
                raise FileNotFoundError(f"Attacks directory not found: {self.absolute_path}")

    def _validate_contract(self, module: ModuleType) -> bool:
        """
        Ensures the module has a valid `execute(target: str)` function.

        Args:
            module (ModuleType): The loaded Python module to validate.

        Returns:
            bool: True if module passes contract, False otherwise.
        """
        if not hasattr(module, "execute"):
            logger.debug("Module validation failed: no 'execute' function found")
            return False

        func = getattr(module, "execute")
        if not inspect.isfunction(func):
            logger.debug(
                f"Module validation failed: 'execute' is not a function (type: {type(func)})"
            )
            return False

        try:
            params = inspect.signature(func).parameters
            if len(params) < 1:
                logger.debug(
                    f"Module validation failed: execute() needs at least 1 parameter, has {len(params)}"
                )
                return False

            logger.debug(f"Module validation passed: execute() has {len(params)} parameter(s)")
            return True

        except Exception as e:
            logger.debug(f"Module validation failed during signature check: {e}")
            return False

    def load_all(self) -> List[Callable]:
        """
        Deep sweep of the attacks directory.
        Recursively scans subdirectories and loads all valid Python modules.

        Returns:
            List[Callable]: Validated execute() functions ready to be called.
        """
        attack_functions = []
        logger.info(f"Initiating deep sweep of {self.directory}/...")

        try:
            for root, dirs, files in os.walk(self.absolute_path):
                # Sort for deterministic load order across platforms
                for file in sorted(files):
                    if not file.endswith(".py") or file == "__init__.py":
                        continue

                    module_name = file[:-3]
                    file_path = os.path.join(root, file)

                    try:
                        spec = importlib.util.spec_from_file_location(module_name, file_path)

                        if spec is None or spec.loader is None:
                            logger.warning(f"Skipped '{file}': Could not create module spec")
                            continue

                        new_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(new_module)

                        if self._validate_contract(new_module):
                            attack_functions.append(new_module.execute)
                            logger.info(f"Loaded attack module: '{file}' ✓")
                        else:
                            logger.warning(
                                f"Rejected: '{file}' — must have execute(target: str) -> ScanResult"
                            )

                    except SyntaxError as syntax_err:
                        logger.error(f"Syntax error in '{file}': {syntax_err}")
                        continue

                    except ImportError as import_err:
                        logger.error(f"Import error in '{file}': {import_err}")
                        continue

                    except Exception as e:
                        logger.error(
                            f"Critical failure loading '{file}': {type(e).__name__}: {e}"
                        )
                        if config.LOG_FULL_TRACEBACK:
                            logger.debug("Traceback:", exc_info=True)
                        continue

            if attack_functions:
                logger.info(
                    f"Discovery complete. {len(attack_functions)} attack module(s) armed and ready."
                )
            else:
                logger.warning(
                    f"Discovery complete. No valid attack modules found in {self.directory}/"
                )

            return attack_functions

        except Exception as e:
            logger.error(f"Fatal error during module discovery: {e}")
            if config.LOG_FULL_TRACEBACK:
                logger.debug("Traceback:", exc_info=True)
            return []


def get_attack_modules(directory: str = None) -> List[Callable]:
    """
    Convenience function to discover and load attack modules.
    Main entry point called by the orchestrator.

    Args:
        directory (str): Path to attacks directory. Defaults to config.ATTACKS_DIRECTORY.

    Returns:
        List[Callable]: Validated execute() functions ready to be called.
    """
    try:
        engine = DiscoveryEngine(directory or config.ATTACKS_DIRECTORY)
        return engine.load_all()
    except Exception as e:
        logger.error(f"Failed to initialize DiscoveryEngine: {e}")
        if config.LOG_FULL_TRACEBACK:
            logger.debug("Traceback:", exc_info=True)
        return []
import os
import importlib.util
import inspect
import logging
from typing import List, Callable
from types import ModuleType
import config

# FIX: Removed logging.basicConfig() call here. Logging configuration belongs
# exclusively in the entry point (orchestrator.py). Calling basicConfig() in
# submodules causes duplicate handlers and fights with the orchestrator's setup.
logger = logging.getLogger("DiscoveryEngine")


class DiscoveryEngine:
    """
    Dynamic module discovery system.
    Scans, validates, and hot-loads attack libraries from the attacks/ directory.

    Requirements for attack modules:
    - Must contain an `execute(target: str) -> ScanResult` function
    - Must return a ScanResult object from core.models
    """

    def __init__(self, directory: str = None):
        """
        Initialize the DiscoveryEngine.

        Args:
            directory (str): Path to the attacks directory. Defaults to config.ATTACKS_DIRECTORY.
        """
        self.directory = directory or config.ATTACKS_DIRECTORY
        self.absolute_path = os.path.abspath(self.directory)

        logger.debug(f"DiscoveryEngine initialized with directory: {self.absolute_path}")

        if not os.path.exists(self.absolute_path):
            if config.AUTO_CREATE_ATTACKS_DIR:
                try:
                    os.makedirs(self.absolute_path, exist_ok=True)
                    logger.info(f"Created missing attack directory: {self.absolute_path}")
                except OSError as e:
                    logger.error(f"Failed to create attacks directory: {e}")
                    raise
            else:
                raise FileNotFoundError(f"Attacks directory not found: {self.absolute_path}")

    def _validate_contract(self, module: ModuleType) -> bool:
        """
        Ensures the module has a valid `execute(target: str)` function.

        Args:
            module (ModuleType): The loaded Python module to validate.

        Returns:
            bool: True if module passes contract, False otherwise.
        """
        if not hasattr(module, "execute"):
            logger.debug("Module validation failed: no 'execute' function found")
            return False

        func = getattr(module, "execute")
        if not inspect.isfunction(func):
            logger.debug(
                f"Module validation failed: 'execute' is not a function (type: {type(func)})"
            )
            return False

        try:
            params = inspect.signature(func).parameters
            if len(params) < 1:
                logger.debug(
                    f"Module validation failed: execute() needs at least 1 parameter, has {len(params)}"
                )
                return False

            logger.debug(f"Module validation passed: execute() has {len(params)} parameter(s)")
            return True

        except Exception as e:
            logger.debug(f"Module validation failed during signature check: {e}")
            return False

    def load_all(self) -> List[Callable]:
        """
        Deep sweep of the attacks directory.
        Recursively scans subdirectories and loads all valid Python modules.

        Returns:
            List[Callable]: Validated execute() functions ready to be called.
        """
        attack_functions = []
        logger.info(f"Initiating deep sweep of {self.directory}/...")

        try:
            for root, dirs, files in os.walk(self.absolute_path):
                # Sort for deterministic load order across platforms
                for file in sorted(files):
                    if not file.endswith(".py") or file == "__init__.py":
                        continue

                    module_name = file[:-3]
                    file_path = os.path.join(root, file)

                    try:
                        spec = importlib.util.spec_from_file_location(module_name, file_path)

                        if spec is None or spec.loader is None:
                            logger.warning(f"Skipped '{file}': Could not create module spec")
                            continue

                        new_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(new_module)

                        if self._validate_contract(new_module):
                            attack_functions.append(new_module.execute)
                            logger.info(f"Loaded attack module: '{file}' ✓")
                        else:
                            logger.warning(
                                f"Rejected: '{file}' — must have execute(target: str) -> ScanResult"
                            )

                    except SyntaxError as syntax_err:
                        logger.error(f"Syntax error in '{file}': {syntax_err}")
                        continue

                    except ImportError as import_err:
                        logger.error(f"Import error in '{file}': {import_err}")
                        continue

                    except Exception as e:
                        logger.error(
                            f"Critical failure loading '{file}': {type(e).__name__}: {e}"
                        )
                        if config.LOG_FULL_TRACEBACK:
                            logger.debug("Traceback:", exc_info=True)
                        continue

            if attack_functions:
                logger.info(
                    f"Discovery complete. {len(attack_functions)} attack module(s) armed and ready."
                )
            else:
                logger.warning(
                    f"Discovery complete. No valid attack modules found in {self.directory}/"
                )

            return attack_functions

        except Exception as e:
            logger.error(f"Fatal error during module discovery: {e}")
            if config.LOG_FULL_TRACEBACK:
                logger.debug("Traceback:", exc_info=True)
            return []


def get_attack_modules(directory: str = None) -> List[Callable]:
    """
    Convenience function to discover and load attack modules.
    Main entry point called by the orchestrator.

    Args:
        directory (str): Path to attacks directory. Defaults to config.ATTACKS_DIRECTORY.

    Returns:
        List[Callable]: Validated execute() functions ready to be called.
    """
    try:
        engine = DiscoveryEngine(directory or config.ATTACKS_DIRECTORY)
        return engine.load_all()
    except Exception as e:
        logger.error(f"Failed to initialize DiscoveryEngine: {e}")
        if config.LOG_FULL_TRACEBACK:
            logger.debug("Traceback:", exc_info=True)
        return []

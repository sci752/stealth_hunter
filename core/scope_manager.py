

import os
import logging
from typing import List
from urllib.parse import urlparse
import config

logger = logging.getLogger("ScopeManager")


def is_valid_url(url) -> bool:
    """
    Validate that a URL is well-formed and uses HTTP/HTTPS.

    Args:
        url: Value to validate. Non-string inputs return False gracefully.

    Returns:
        bool: True if URL is valid, False otherwise.

    FIX: Original accepted `url: str` type hint but crashed on non-string
    inputs (None, int, list) with AttributeError before the try/except.
    The test suite explicitly checks these cases.
    """
    # FIX: Guard against non-string inputs before calling .strip()
    if not isinstance(url, str):
        return False

    try:
        url = url.strip()

        if not url:
            return False

        if url.startswith("#"):
            return False

        result = urlparse(url)

        has_scheme = bool(result.scheme and result.scheme in ["http", "https"])
        has_netloc = bool(result.netloc)

        is_valid = has_scheme and has_netloc

        if not is_valid:
            logger.debug(f"Invalid URL: {url} (scheme={result.scheme}, netloc={result.netloc})")

        return is_valid

    except Exception as e:
        logger.debug(f"URL validation error for '{url}': {e}")
        return False


def load_mass_scope(filepath: str) -> List[str]:
    """
    Load mass scope from a file containing one target URL per line.

    File Format:
        https://target1.com
        https://target2.com:8443
        # This is a comment
        https://target3.com

    Features:
    - Skips empty lines and comment lines
    - Validates each URL (HTTP/HTTPS only)
    - Deduplicates while preserving order

    Args:
        filepath (str): Path to the scope file.

    Returns:
        List[str]: List of valid, unique target URLs. Empty list if file not found.
    """
    targets = []

    if not os.path.exists(filepath):
        logger.info(f"Scope file not found: {filepath}")
        return []

    logger.info(f"Loading scope from {filepath}")

    try:
        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, start=1):
                url = line.strip()

                if not url:
                    continue

                if url.startswith("#"):
                    logger.debug(f"Line {line_num}: Comment skipped")
                    continue

                if is_valid_url(url):
                    if url not in targets:
                        targets.append(url)
                        logger.debug(f"Line {line_num}: URL loaded: {url}")
                    else:
                        logger.debug(f"Line {line_num}: Duplicate URL skipped: {url}")
                else:
                    logger.warning(f"Line {line_num}: Invalid URL skipped: {url}")

        logger.info(f"Scope loading complete. {len(targets)} unique valid target(s) loaded")
        return targets

    except IOError as io_err:
        logger.error(f"Failed to read scope file '{filepath}': {io_err}")
        return []

    except Exception as unexpected_err:
        logger.error(
            f"Unexpected error reading scope file: "
            f"{type(unexpected_err).__name__}: {unexpected_err}"
        )
        if config.LOG_FULL_TRACEBACK:
            logger.debug("Traceback:", exc_info=True)
        return []


def save_scope(filepath: str, targets: List[str]) -> bool:
    """
    Save a list of targets to a scope file.

    Args:
        filepath (str): Path where scope file will be saved.
        targets (List[str]): List of target URLs to save.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        with open(filepath, "w") as f:
            for target in targets:
                f.write(f"{target}\n")

        logger.info(f"Saved {len(targets)} target(s) to {filepath}")
        return True

    except IOError as io_err:
        logger.error(f"Failed to write scope file '{filepath}': {io_err}")
        return False

    except Exception as unexpected_err:
        logger.error(f"Unexpected error writing scope file: {unexpected_err}")
        return False


def merge_scopes(file1: str, file2: str, output_file: str = None) -> List[str]:
    """
    Merge two scope files and remove duplicates.

    Args:
        file1 (str): First scope file path.
        file2 (str): Second scope file path.
        output_file (str, optional): Save merged results here. If None, only returns list.

    Returns:
        List[str]: Merged and deduplicated, sorted list of targets.
    """
    targets = set()
    targets.update(load_mass_scope(file1))
    targets.update(load_mass_scope(file2))

    merged_list = sorted(list(targets))

    if output_file:
        save_scope(output_file, merged_list)

    logger.info(f"Merged scope: {len(merged_list)} unique targets")
    return merged_list


def filter_scope_by_pattern(targets: List[str], pattern: str) -> List[str]:
    """
    Filter targets by a pattern (e.g., only /api paths, or specific domains).

    Args:
        targets (List[str]): List of target URLs.
        pattern (str): String pattern to match within URLs (case-insensitive).

    Returns:
        List[str]: Filtered list of targets containing the pattern.
    """
    filtered = [t for t in targets if pattern.lower() in t.lower()]
    logger.info(f"Filtered scope by '{pattern}': {len(filtered)} target(s) match")
    return filtered


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO)

    print("=" * 60)
    print("Stealth Hunter Scope Manager")
    print("=" * 60)

    scope_file = config.SCOPE_FILE
    targets = load_mass_scope(scope_file)

    if targets:
        print(f"\n✅ Loaded {len(targets)} target(s):")
        for i, target in enumerate(targets, 1):
            print(f"  {i}. {target}")
    else:
        print(f"\n⚠️  No targets loaded from {scope_file}")
        print("   Create a scope.txt file with one URL per line")

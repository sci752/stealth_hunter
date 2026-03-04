import os
import logging
from typing import List
from urllib.parse import urlparse
import config

# Setup logging
logger = logging.getLogger("ScopeManager")


def is_valid_url(url: str) -> bool:
    """
    Validate that a URL is well-formed and has required components.
    
    Args:
        url (str): URL string to validate (e.g., "https://example.com/api")
    
    Returns:
        bool: True if URL is valid, False otherwise.
    
    Example:
        >>> is_valid_url("https://example.com")
        True
        >>> is_valid_url("not a url")
        False
    """
    try:
        url = url.strip()
        
        # Empty check
        if not url:
            return False
        
        # Skip comments
        if url.startswith("#"):
            return False
        
        # Parse the URL
        result = urlparse(url)
        
        # Check for required components: scheme (http/https) and netloc (domain)
        has_scheme = bool(result.scheme and result.scheme in ['http', 'https'])
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
    Robust parsing with error handling and validation.
    
    File Format:
        Each line should contain one target URL:
        ```
        https://target1.com
        https://target2.com:8443
        https://api.target3.com/v1
        # This is a comment
        https://target4.com
        ```
    
    Features:
    - Skips empty lines
    - Skips lines starting with '#' (comments)
    - Validates each URL
    - Removes duplicates
    - Logs warnings for invalid entries
    
    Args:
        filepath (str): Path to the scope file (default: "scope.txt" from config)
    
    Returns:
        List[str]: List of valid target URLs. Empty list if file not found or no valid URLs.
    
    Example:
        targets = load_mass_scope("scope.txt")
        print(f"Loaded {len(targets)} targets")
    """
    targets = []
    
    # Check if file exists
    if not os.path.exists(filepath):
        logger.info(f"Scope file not found: {filepath}")
        return []
    
    logger.info(f"Loading scope from {filepath}")
    
    try:
        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, start=1):
                url = line.strip()
                
                # Skip empty lines
                if not url:
                    continue
                
                # Skip comments
                if url.startswith("#"):
                    logger.debug(f"Line {line_num}: Comment skipped")
                    continue
                
                # Validate URL
                if is_valid_url(url):
                    # Check for duplicates
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
        logger.error(f"Unexpected error reading scope file: {type(unexpected_err).__name__}: {unexpected_err}")
        if config.LOG_FULL_TRACEBACK:
            logger.debug(f"Traceback:", exc_info=True)
        return []


def save_scope(filepath: str, targets: List[str]) -> bool:
    """
    Save a list of targets to a scope file.
    Useful for exporting discovered targets or organizing scans.
    
    Args:
        filepath (str): Path where scope file will be saved
        targets (List[str]): List of target URLs to save
    
    Returns:
        bool: True if successful, False otherwise.
    
    Example:
        targets = ["https://example1.com", "https://example2.com"]
        save_scope("my_scope.txt", targets)
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
    Useful for combining multiple recon results.
    
    Args:
        file1 (str): First scope file path
        file2 (str): Second scope file path
        output_file (str, optional): Save merged results to this file. If None, only returns list.
    
    Returns:
        List[str]: Merged and deduplicated list of targets.
    
    Example:
        merged = merge_scopes("scope1.txt", "scope2.txt", "merged_scope.txt")
        print(f"Total unique targets: {len(merged)}")
    """
    targets = set()
    
    # Load from first file
    targets.update(load_mass_scope(file1))
    
    # Load from second file
    targets.update(load_mass_scope(file2))
    
    # Convert back to list
    merged_list = sorted(list(targets))
    
    # Save if output file specified
    if output_file:
        save_scope(output_file, merged_list)
    
    logger.info(f"Merged scope: {len(merged_list)} unique targets")
    return merged_list


def filter_scope_by_pattern(targets: List[str], pattern: str) -> List[str]:
    """
    Filter targets by a pattern (e.g., only .com domains, or specific paths).
    
    Args:
        targets (List[str]): List of target URLs
        pattern (str): String pattern to match in URLs
    
    Returns:
        List[str]: Filtered list of targets containing the pattern.
    
    Example:
        # Get only API targets
        api_targets = filter_scope_by_pattern(targets, "/api")
        
        # Get only .com domains
        com_targets = filter_scope_by_pattern(targets, ".com")
    """
    filtered = [t for t in targets if pattern.lower() in t.lower()]
    logger.info(f"Filtered scope by '{pattern}': {len(filtered)} target(s) match")
    return filtered


if __name__ == "__main__":
    # Test/demo mode - load and display scope
    logger.basicConfig(level=logging.INFO)
    
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
        print(f"\n⚠️ No targets loaded from {scope_file}")
        print("   Create a scope.txt file with one URL per line")


import pytest
import os
import tempfile
from core.scope_manager import (
    is_valid_url,
    load_mass_scope,
    save_scope,
    merge_scopes,
    filter_scope_by_pattern
)


class TestIsValidUrl:
    """Unit tests for the is_valid_url function."""
    
    def test_valid_https_url(self):
        """Test that valid HTTPS URLs are accepted."""
        assert is_valid_url("https://example.com") is True
        assert is_valid_url("https://example.com:443") is True
        assert is_valid_url("https://api.example.com/v1") is True
    
    def test_valid_http_url(self):
        """Test that valid HTTP URLs are accepted."""
        assert is_valid_url("http://example.com") is True
        assert is_valid_url("http://example.com:8080") is True
        assert is_valid_url("http://localhost:3000") is True
    
    def test_url_with_path(self):
        """Test URLs with paths are valid."""
        assert is_valid_url("https://example.com/api/v1") is True
        assert is_valid_url("http://example.com/deep/path/to/endpoint") is True
    
    def test_url_with_query_string(self):
        """Test URLs with query strings are valid."""
        assert is_valid_url("https://example.com?param=value") is True
        assert is_valid_url("https://example.com/api?token=abc123") is True
    
    def test_missing_scheme(self):
        """Test that URLs without scheme are rejected."""
        assert is_valid_url("example.com") is False
        assert is_valid_url("www.example.com") is False
    
    def test_invalid_scheme(self):
        """Test that only HTTP/HTTPS schemes are accepted."""
        assert is_valid_url("ftp://example.com") is False
        assert is_valid_url("file:///etc/passwd") is False
        assert is_valid_url("gopher://example.com") is False
    
    def test_missing_domain(self):
        """Test that URLs without domain are rejected."""
        assert is_valid_url("https://") is False
        assert is_valid_url("http://") is False
    
    def test_empty_string(self):
        """Test that empty strings are rejected."""
        assert is_valid_url("") is False
        assert is_valid_url("   ") is False
    
    def test_comment_line(self):
        """Test that comment lines are rejected."""
        assert is_valid_url("# https://example.com") is False
    
    def test_whitespace_handling(self):
        """Test that leading/trailing whitespace is handled."""
        assert is_valid_url("  https://example.com  ") is True
        assert is_valid_url("\thttps://example.com\n") is True
    
    def test_ipv4_address(self):
        """Test that IPv4 addresses are valid."""
        assert is_valid_url("http://192.168.1.1") is True
        assert is_valid_url("https://10.0.0.1:8443") is True
    
    def test_localhost(self):
        """Test that localhost URLs are valid."""
        assert is_valid_url("http://localhost") is True
        assert is_valid_url("http://127.0.0.1") is True
        assert is_valid_url("http://localhost:3000") is True
    
    def test_non_string_input(self):
        """Test that non-string inputs are handled gracefully."""
        # These should return False without crashing
        assert is_valid_url(None) is False
        assert is_valid_url(123) is False
        assert is_valid_url([]) is False


class TestLoadMassScope:
    """Unit tests for the load_mass_scope function."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_load_single_valid_url(self, temp_dir):
        """Test loading a single valid URL."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("https://example.com\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 1
        assert targets[0] == "https://example.com"
    
    def test_load_multiple_valid_urls(self, temp_dir):
        """Test loading multiple valid URLs."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        urls = [
            "https://target1.com",
            "https://target2.com",
            "http://target3.com:8080"
        ]
        
        with open(scope_file, "w") as f:
            for url in urls:
                f.write(f"{url}\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 3
        assert all(url in targets for url in urls)
    
    def test_skip_empty_lines(self, temp_dir):
        """Test that empty lines are skipped."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("https://target1.com\n")
            f.write("\n")
            f.write("\n")
            f.write("https://target2.com\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 2
        assert "https://target1.com" in targets
        assert "https://target2.com" in targets
    
    def test_skip_comment_lines(self, temp_dir):
        """Test that comment lines are skipped."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("# This is a comment\n")
            f.write("https://target1.com\n")
            f.write("# Another comment\n")
            f.write("https://target2.com\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 2
        assert "https://target1.com" in targets
        assert "https://target2.com" in targets
    
    def test_skip_invalid_urls(self, temp_dir):
        """Test that invalid URLs are skipped."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("https://valid1.com\n")
            f.write("not a url\n")
            f.write("https://valid2.com\n")
            f.write("ftp://invalid.com\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 2
        assert "https://valid1.com" in targets
        assert "https://valid2.com" in targets
    
    def test_remove_duplicates(self, temp_dir):
        """Test that duplicate URLs are removed."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("https://example.com\n")
            f.write("https://example.com\n")
            f.write("https://example.com\n")
            f.write("https://other.com\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 2
        assert targets.count("https://example.com") == 1
    
    def test_file_not_found(self, temp_dir):
        """Test that missing file returns empty list."""
        scope_file = os.path.join(temp_dir, "nonexistent.txt")
        
        targets = load_mass_scope(scope_file)
        
        assert targets == []
        assert isinstance(targets, list)
    
    def test_mixed_valid_invalid_and_comments(self, temp_dir):
        """Test handling of mixed content."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("# Scope for target\n")
            f.write("https://api.example.com\n")
            f.write("\n")
            f.write("invalid url\n")
            f.write("# Another section\n")
            f.write("https://admin.example.com:8443\n")
            f.write("http://localhost:3000\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 3
        assert "https://api.example.com" in targets
        assert "https://admin.example.com:8443" in targets
        assert "http://localhost:3000" in targets
    
    def test_whitespace_trimming(self, temp_dir):
        """Test that whitespace is trimmed from URLs."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("  https://example1.com  \n")
            f.write("\thttps://example2.com\t\n")
            f.write("https://example3.com\n")
        
        targets = load_mass_scope(scope_file)
        
        assert len(targets) == 3
        assert all(not url.startswith(" ") and not url.endswith(" ") for url in targets)


class TestSaveScope:
    """Unit tests for the save_scope function."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_save_single_target(self, temp_dir):
        """Test saving a single target."""
        scope_file = os.path.join(temp_dir, "output.txt")
        targets = ["https://example.com"]
        
        result = save_scope(scope_file, targets)
        
        assert result is True
        assert os.path.exists(scope_file)
        
        # Verify content
        with open(scope_file, "r") as f:
            content = f.read().strip()
        
        assert content == "https://example.com"
    
    def test_save_multiple_targets(self, temp_dir):
        """Test saving multiple targets."""
        scope_file = os.path.join(temp_dir, "output.txt")
        targets = ["https://target1.com", "https://target2.com", "https://target3.com"]
        
        result = save_scope(scope_file, targets)
        
        assert result is True
        
        # Verify content
        with open(scope_file, "r") as f:
            lines = f.read().strip().split("\n")
        
        assert len(lines) == 3
        assert all(target in lines for target in targets)
    
    def test_save_empty_list(self, temp_dir):
        """Test saving an empty list."""
        scope_file = os.path.join(temp_dir, "output.txt")
        targets = []
        
        result = save_scope(scope_file, targets)
        
        assert result is True
        assert os.path.exists(scope_file)
        
        with open(scope_file, "r") as f:
            content = f.read()
        
        assert content == ""
    
    def test_overwrite_existing_file(self, temp_dir):
        """Test that save_scope overwrites existing files."""
        scope_file = os.path.join(temp_dir, "output.txt")
        
        # Write initial content
        with open(scope_file, "w") as f:
            f.write("old content\n")
        
        # Save new content
        targets = ["https://example.com"]
        result = save_scope(scope_file, targets)
        
        assert result is True
        
        with open(scope_file, "r") as f:
            content = f.read().strip()
        
        assert content == "https://example.com"
        assert "old content" not in content


class TestMergeScopes:
    """Unit tests for the merge_scopes function."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_merge_two_scopes(self, temp_dir):
        """Test merging two scope files."""
        file1 = os.path.join(temp_dir, "scope1.txt")
        file2 = os.path.join(temp_dir, "scope2.txt")
        
        with open(file1, "w") as f:
            f.write("https://target1.com\n")
            f.write("https://target2.com\n")
        
        with open(file2, "w") as f:
            f.write("https://target2.com\n")  # Duplicate
            f.write("https://target3.com\n")
        
        merged = merge_scopes(file1, file2)
        
        assert len(merged) == 3
        assert "https://target1.com" in merged
        assert "https://target2.com" in merged
        assert "https://target3.com" in merged
    
    def test_merge_removes_duplicates(self, temp_dir):
        """Test that merge removes duplicates."""
        file1 = os.path.join(temp_dir, "scope1.txt")
        file2 = os.path.join(temp_dir, "scope2.txt")
        
        with open(file1, "w") as f:
            f.write("https://example.com\n")
        
        with open(file2, "w") as f:
            f.write("https://example.com\n")
        
        merged = merge_scopes(file1, file2)
        
        assert len(merged) == 1
        assert "https://example.com" in merged
    
    def test_merge_saves_to_output_file(self, temp_dir):
        """Test that merge saves to output file when specified."""
        file1 = os.path.join(temp_dir, "scope1.txt")
        file2 = os.path.join(temp_dir, "scope2.txt")
        output = os.path.join(temp_dir, "merged.txt")
        
        with open(file1, "w") as f:
            f.write("https://target1.com\n")
        
        with open(file2, "w") as f:
            f.write("https://target2.com\n")
        
        merged = merge_scopes(file1, file2, output)
        
        assert os.path.exists(output)
        assert len(merged) == 2
        
        with open(output, "r") as f:
            saved_content = f.read().strip().split("\n")
        
        assert len(saved_content) == 2


class TestFilterScopeByPattern:
    """Unit tests for the filter_scope_by_pattern function."""
    
    def test_filter_by_path(self):
        """Test filtering targets by path pattern."""
        targets = [
            "https://example.com",
            "https://api.example.com",
            "https://example.com/api/v1",
            "https://example.com/admin"
        ]
        
        filtered = filter_scope_by_pattern(targets, "/api")
        
        assert len(filtered) == 2
        assert "https://api.example.com" in filtered
        assert "https://example.com/api/v1" in filtered
    
    def test_filter_by_domain(self):
        """Test filtering targets by domain pattern."""
        targets = [
            "https://api.example.com",
            "https://admin.example.com",
            "https://example.com",
            "https://other.com"
        ]
        
        filtered = filter_scope_by_pattern(targets, ".example.com")
        
        assert len(filtered) == 3
        assert all(".example.com" in target for target in filtered)
    
    def test_filter_by_tld(self):
        """Test filtering targets by top-level domain."""
        targets = [
            "https://example.com",
            "https://target.org",
            "https://another.com",
            "https://example.edu"
        ]
        
        filtered = filter_scope_by_pattern(targets, ".com")
        
        assert len(filtered) == 2
        assert "https://example.com" in filtered
        assert "https://another.com" in filtered
    
    def test_filter_case_insensitive(self):
        """Test that filtering is case-insensitive."""
        targets = [
            "https://API.example.com",
            "https://api.example.com",
            "https://example.com"
        ]
        
        filtered = filter_scope_by_pattern(targets, "api")
        
        assert len(filtered) == 2
    
    def test_filter_no_matches(self):
        """Test filtering when no targets match."""
        targets = [
            "https://example.com",
            "https://target.com"
        ]
        
        filtered = filter_scope_by_pattern(targets, "nonexistent")
        
        assert filtered == []
    
    def test_filter_all_match(self):
        """Test filtering when all targets match."""
        targets = [
            "https://example.com",
            "https://target.com",
            "https://another.com"
        ]
        
        filtered = filter_scope_by_pattern(targets, ".com")
        
        assert len(filtered) == 3


if __name__ == "__main__":
    # Run tests with: pytest tests/test_scope_manager.py -v
    pytest.main([__file__, "-v", "--tb=short"])

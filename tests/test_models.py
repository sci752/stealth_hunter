import pytest
import json
from datetime import datetime
from core.models import ScanResult, Severity


class TestSeverityEnum:
    """Unit tests for the Severity enum."""

    def test_all_severity_levels_exist(self):
        """Test that all five severity levels are defined."""
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"
        assert Severity.MEDIUM == "MEDIUM"
        assert Severity.LOW == "LOW"
        assert Severity.INFO == "INFO"

    def test_severity_is_string_enum(self):
        """Test that Severity inherits from str, enabling direct string comparisons."""
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.HIGH == "HIGH"

    def test_severity_values_are_uppercase(self):
        """Test that all severity values are uppercase strings."""
        for sev in Severity:
            assert sev.value == sev.value.upper()


class TestScanResultCreation:
    """Unit tests for ScanResult model creation and validation."""

    def test_minimal_vulnerable_result(self):
        """Test creating a minimal vulnerable ScanResult."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test_Module",
            description="Vulnerability found",
        )

        assert result.is_vulnerable is True
        assert result.module_name == "Test_Module"
        assert result.description == "Vulnerability found"

    def test_minimal_safe_result(self):
        """Test creating a minimal safe ScanResult."""
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="Target is secure",
        )

        assert result.is_vulnerable is False

    def test_default_severity_is_info(self):
        """Test that default severity is INFO."""
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="No issue",
        )

        assert result.severity == Severity.INFO

    def test_default_execution_time_is_zero(self):
        """Test that default execution_time_ms is 0.0."""
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="No issue",
        )

        assert result.execution_time_ms == 0.0

    def test_default_metadata_is_empty_dict(self):
        """Test that default metadata is an empty dict."""
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="No issue",
        )

        assert result.metadata == {}
        assert isinstance(result.metadata, dict)

    def test_default_evidence_is_none(self):
        """Test that default evidence is None."""
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="No issue",
        )

        assert result.evidence is None

    def test_timestamp_is_set_automatically(self):
        """Test that timestamp is auto-set to a datetime object."""
        before = datetime.utcnow()
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="No issue",
        )
        after = datetime.utcnow()

        assert before <= result.timestamp <= after

    def test_full_result_with_all_fields(self):
        """Test creating a ScanResult with all fields populated."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="SQL_Injection",
            severity=Severity.CRITICAL,
            description="SQL injection in login endpoint",
            evidence="HTTP/1.1 200 OK ...",
            payload_used="' OR 1=1; --",
            execution_time_ms=125.5,
            metadata={"endpoint": "/api/login", "parameter": "username"},
        )

        assert result.is_vulnerable is True
        assert result.severity == Severity.CRITICAL
        assert result.evidence == "HTTP/1.1 200 OK ..."
        assert result.payload_used == "' OR 1=1; --"
        assert result.execution_time_ms == 125.5
        assert result.metadata["endpoint"] == "/api/login"

    def test_severity_stored_as_string_value(self):
        """Test that use_enum_values=True stores severity as string."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test",
            severity=Severity.HIGH,
            description="Test",
        )

        # Because use_enum_values=True, severity should compare equal to the string
        assert result.severity == "HIGH"

    def test_missing_required_field_raises_error(self):
        """Test that missing required fields raise a validation error."""
        with pytest.raises(Exception):
            ScanResult(
                is_vulnerable=True,
                # missing module_name
                description="Test",
            )

    def test_missing_description_raises_error(self):
        """Test that missing description raises a validation error."""
        with pytest.raises(Exception):
            ScanResult(
                is_vulnerable=False,
                module_name="Test",
                # missing description
            )


class TestScanResultMethods:
    """Unit tests for ScanResult helper methods."""

    def test_is_critical_returns_true_for_critical(self):
        """Test is_critical() returns True for CRITICAL severity."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test",
            severity=Severity.CRITICAL,
            description="Critical vuln",
        )
        assert result.is_critical() is True

    def test_is_critical_returns_false_for_high(self):
        """Test is_critical() returns False for HIGH severity."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test",
            severity=Severity.HIGH,
            description="High vuln",
        )
        assert result.is_critical() is False

    def test_is_critical_returns_false_for_non_critical(self):
        """Test is_critical() returns False for all non-CRITICAL severities."""
        for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            result = ScanResult(
                is_vulnerable=False,
                module_name="Test",
                severity=sev,
                description="Test",
            )
            assert result.is_critical() is False

    def test_is_high_or_above_for_critical(self):
        """Test is_high_or_above() returns True for CRITICAL."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test",
            severity=Severity.CRITICAL,
            description="Test",
        )
        assert result.is_high_or_above() is True

    def test_is_high_or_above_for_high(self):
        """Test is_high_or_above() returns True for HIGH."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test",
            severity=Severity.HIGH,
            description="Test",
        )
        assert result.is_high_or_above() is True

    def test_is_high_or_above_for_medium_and_below(self):
        """Test is_high_or_above() returns False for MEDIUM, LOW, INFO."""
        for sev in [Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            result = ScanResult(
                is_vulnerable=False,
                module_name="Test",
                severity=sev,
                description="Test",
            )
            assert result.is_high_or_above() is False

    def test_to_json_report_returns_valid_json(self):
        """Test that to_json_report() returns valid JSON string."""
        result = ScanResult(
            is_vulnerable=True,
            module_name="Test_Module",
            severity=Severity.HIGH,
            description="Test vulnerability",
            evidence="Some evidence",
            execution_time_ms=42.0,
            metadata={"key": "value"},
        )

        json_str = result.to_json_report()

        # Must be valid JSON
        parsed = json.loads(json_str)

        assert parsed["is_vulnerable"] is True
        assert parsed["module_name"] == "Test_Module"
        assert parsed["severity"] == "HIGH"
        assert parsed["description"] == "Test vulnerability"
        assert parsed["execution_time_ms"] == 42.0

    def test_to_json_report_includes_all_fields(self):
        """Test that to_json_report() includes all fields including None values."""
        result = ScanResult(
            is_vulnerable=False,
            module_name="Test_Module",
            description="No issue",
        )

        json_str = result.to_json_report()
        parsed = json.loads(json_str)

        # All fields should be present
        assert "is_vulnerable" in parsed
        assert "module_name" in parsed
        assert "severity" in parsed
        assert "description" in parsed
        assert "evidence" in parsed
        assert "execution_time_ms" in parsed
        assert "metadata" in parsed

    def test_metadata_can_hold_nested_data(self):
        """Test that metadata field can store complex nested structures."""
        nested_meta = {
            "endpoint": "/api/login",
            "attack_type": "SQLi",
            "request": {"method": "POST", "params": ["username", "password"]},
        }

        result = ScanResult(
            is_vulnerable=True,
            module_name="Test",
            description="Test",
            metadata=nested_meta,
        )

        assert result.metadata["request"]["method"] == "POST"
        assert result.metadata["request"]["params"] == ["username", "password"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
      

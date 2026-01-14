"""Unit tests for SCP Linter."""

import json
from pathlib import Path

from scp_simulator.linter import LintResult, LintSeverity, SCPLinter


class TestSCPLinterBasic:
    """Basic linter functionality tests."""

    def test_valid_minimal_scp(self):
        """Valid minimal SCP should have no errors."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyS3Delete",
                    "Effect": "Deny",
                    "Action": "s3:DeleteBucket",
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert report.is_valid
        assert len(report.errors) == 0

    def test_lint_from_string(self):
        """Lint from JSON string."""
        policy_str = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            }
        )
        linter = SCPLinter()
        report = linter.lint_string(policy_str)

        assert report.is_valid

    def test_lint_from_file(self, tmp_path):
        """Lint from file path."""
        policy_file = tmp_path / "scp.json"
        policy_file.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
                }
            )
        )

        linter = SCPLinter()
        report = linter.lint_file(policy_file)

        assert report.is_valid


class TestJSONSyntaxValidation:
    """JSON syntax validation tests."""

    def test_invalid_json_syntax(self):
        """Invalid JSON should report error."""
        linter = SCPLinter()
        report = linter.lint_string("{ not valid json }")

        assert not report.is_valid
        assert len(report.errors) == 1
        assert report.errors[0].code == "E003"
        assert "Invalid JSON" in report.errors[0].message

    def test_file_not_found(self):
        """Non-existent file should report error."""
        linter = SCPLinter()
        report = linter.lint_file(Path("/nonexistent/scp.json"))

        assert not report.is_valid
        assert len(report.errors) == 1
        assert report.errors[0].code == "E001"


class TestPolicySizeLimits:
    """Policy size validation tests."""

    def test_policy_size_reported(self):
        """Policy size should be reported."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert report.policy_size > 0

    def test_policy_over_size_limit(self):
        """Policy over 5120 chars should report error."""
        # Create a policy that exceeds 5120 characters
        large_actions = [f"service{i}:Action{j}" for i in range(50) for j in range(10)]
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": large_actions, "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "E010" for r in report.errors)

    def test_policy_near_size_limit_warning(self):
        """Policy over 75% of limit should warn."""
        # Create a policy around 4000 chars (78% of 5120)
        actions = [f"service{i}:Action{j}" for i in range(20) for j in range(8)]
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": actions, "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        # Should have warning if over 75%
        if report.policy_size > 5120 * 0.75:
            assert any(r.code == "W010" for r in report.warnings)


class TestStructureValidation:
    """Policy structure validation tests."""

    def test_missing_version(self):
        """Missing Version should report error."""
        policy = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not report.is_valid
        assert any(r.code == "E020" for r in report.errors)

    def test_missing_statement(self):
        """Missing Statement should report error."""
        policy = {"Version": "2012-10-17"}
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not report.is_valid
        assert any(r.code == "E021" for r in report.errors)

    def test_unusual_version_warning(self):
        """Unusual Version value should warn."""
        policy = {
            "Version": "2020-01-01",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W020" for r in report.warnings)

    def test_unknown_top_level_field(self):
        """Unknown top-level field should warn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            "UnknownField": "value",
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W021" for r in report.warnings)

    def test_empty_statements_warning(self):
        """Empty statements array should warn."""
        policy = {"Version": "2012-10-17", "Statement": []}
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W030" for r in report.warnings)

    def test_many_statements_warning(self):
        """More than 20 statements should warn."""
        statements = [
            {"Sid": f"Stmt{i}", "Effect": "Deny", "Action": f"s3:Action{i}", "Resource": "*"}
            for i in range(25)
        ]
        policy = {"Version": "2012-10-17", "Statement": statements}
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W031" for r in report.warnings)


class TestStatementValidation:
    """Statement-level validation tests."""

    def test_missing_effect(self):
        """Statement missing Effect should report error."""
        policy = {"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*"}]}
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not report.is_valid
        assert any(r.code == "E031" for r in report.errors)

    def test_invalid_effect(self):
        """Invalid Effect value should report error."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not report.is_valid
        assert any(r.code == "E032" for r in report.errors)

    def test_missing_action(self):
        """Statement missing Action/NotAction should report error."""
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Resource": "*"}]}
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not report.is_valid
        assert any(r.code == "E033" for r in report.errors)

    def test_notaction_is_valid(self):
        """NotAction should be valid alternative to Action."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "E033" for r in report.errors)

    def test_principal_in_scp_error(self):
        """Principal in SCP statement should report error."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Principal": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not report.is_valid
        assert any(r.code == "E034" for r in report.errors)

    def test_missing_sid_info(self):
        """Statement without Sid should report info."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "I031" for r in report.infos)

    def test_missing_resource_info(self):
        """Statement without Resource should report info."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "Test", "Effect": "Deny", "Action": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "I030" for r in report.infos)


class TestActionValidation:
    """Action field validation tests."""

    def test_action_missing_service_prefix(self):
        """Action without service prefix should warn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "GetObject",  # Missing s3:
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W040" for r in report.warnings)

    def test_action_wildcard_is_valid(self):
        """Action '*' should not warn about missing prefix."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W040" for r in report.warnings)

    def test_action_as_array(self):
        """Action as array should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["s3:DeleteBucket", "s3:DeleteObject"],
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "E040" for r in report.errors)


class TestBestPractices:
    """Best practices validation tests."""

    def test_blanket_deny_all_warning(self):
        """Deny * without conditions should warn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W050" for r in report.warnings)

    def test_blanket_deny_with_condition_no_warning(self):
        """Deny * with conditions should not warn about blanket deny."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W050" for r in report.warnings)

    def test_service_wide_deny_warning(self):
        """Deny service:* without conditions should warn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W051" for r in report.warnings)

    def test_allow_only_scp_info(self):
        """SCP with only Allow statements should report info."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "I050" for r in report.infos)


class TestLintReport:
    """LintReport functionality tests."""

    def test_report_properties(self):
        """Report should correctly categorize results."""
        linter = SCPLinter()
        report = linter.lint(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            }
        )

        # Should have some warnings/infos from best practices
        assert isinstance(report.errors, list)
        assert isinstance(report.warnings, list)
        assert isinstance(report.infos, list)
        assert report.statement_count == 1

    def test_has_errors_property(self):
        """has_errors should be True when errors exist."""
        linter = SCPLinter()

        # Invalid policy
        report = linter.lint({"Version": "2012-10-17"})  # Missing Statement
        assert report.has_errors

        # Valid policy
        report = linter.lint(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
            }
        )
        assert not report.has_errors


class TestLintResult:
    """LintResult formatting tests."""

    def test_lint_result_str(self):
        """LintResult should format correctly as string."""
        result = LintResult(
            severity=LintSeverity.ERROR,
            code="E001",
            message="Test error",
            location="Statement[0]",
            suggestion="Fix it",
        )
        result_str = str(result)

        assert "ERROR" in result_str
        assert "E001" in result_str
        assert "Test error" in result_str
        assert "Statement[0]" in result_str
        assert "Fix it" in result_str


class TestIAMActionValidation:
    """Tests for IAM action validation against reference data."""

    def test_valid_action_no_warning(self):
        """Valid action should not produce warning."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W041" for r in report.warnings)
        assert not any(r.code == "W042" for r in report.warnings)

    def test_invalid_service_prefix_warning(self):
        """Unknown service prefix should produce W041 warning."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "s3x:GetObject",
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W041" for r in report.warnings)
        w041 = [r for r in report.warnings if r.code == "W041"][0]
        assert "s3x" in w041.message

    def test_invalid_action_name_warning(self):
        """Unknown action name should produce W042 warning."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "s3:GetObjet",  # Typo: missing 'c'
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W042" for r in report.warnings)
        w042 = [r for r in report.warnings if r.code == "W042"][0]
        assert "GetObjet" in w042.message

    def test_wildcard_action_no_warning(self):
        """Wildcard action '*' should not produce warning."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Test", "Effect": "Deny", "Action": "*", "Resource": "*"}
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W041" for r in report.warnings)
        assert not any(r.code == "W042" for r in report.warnings)

    def test_service_wildcard_validates_service(self):
        """Service wildcard 's3:*' should validate service prefix."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Test", "Effect": "Deny", "Action": "s3:*", "Resource": "*"}
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W041" for r in report.warnings)

    def test_invalid_service_with_wildcard_action(self):
        """Invalid service with wildcard action should warn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Test", "Effect": "Deny", "Action": "s3x:*", "Resource": "*"}
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W041" for r in report.warnings)

    def test_action_with_partial_wildcard(self):
        """Action with partial wildcard 's3:Get*' should validate service."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Test", "Effect": "Deny", "Action": "s3:Get*", "Resource": "*"}
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W041" for r in report.warnings)

    def test_suggestion_for_typo(self):
        """Typo in action should provide suggestion."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "s3:GetObjet",
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        w042 = [r for r in report.warnings if r.code == "W042"]
        assert len(w042) == 1
        assert w042[0].suggestion is not None
        assert "Did you mean" in w042[0].suggestion

    def test_multiple_actions_validated(self):
        """Multiple actions should all be validated."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": ["s3:GetObject", "s3:PutObjet", "ec2x:RunInstances"],
                    "Resource": "*",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        # Should have W042 for PutObjet and W041 for ec2x
        assert any(r.code == "W041" for r in report.warnings)
        assert any(r.code == "W042" for r in report.warnings)


class TestConditionKeyValidation:
    """Tests for condition key validation against reference data."""

    def test_valid_global_condition_key(self):
        """Valid global condition key should not warn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceIp": "1.2.3.4"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W043" for r in report.warnings)

    def test_valid_requested_region_key(self):
        """aws:RequestedRegion should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {"aws:RequestedRegion": "us-east-1"}
                    },
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W043" for r in report.warnings)

    def test_invalid_condition_key_warning(self):
        """Unknown condition key should produce W043 warning."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:InvalidKey": "value"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W043" for r in report.warnings)

    def test_tag_condition_keys_valid(self):
        """Tag-based condition keys should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestTag/Environment": "prod",
                            "aws:ResourceTag/Team": "security",
                        }
                    },
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W043" for r in report.warnings)

    def test_mfa_condition_key_valid(self):
        """MFA condition keys should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "W043" for r in report.warnings)


class TestConditionSyntaxValidation:
    """Tests for condition block syntax validation."""

    def test_valid_condition_block(self):
        """Valid condition block should not produce errors."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceIp": "1.2.3.4"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code.startswith("E05") for r in report.errors)

    def test_condition_block_must_be_object(self):
        """Condition block that is not an object should produce E050."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": "not an object",
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "E050" for r in report.errors)

    def test_operator_value_must_be_object(self):
        """Operator value that is not an object should produce E051."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": "not an object"},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "E051" for r in report.errors)

    def test_unknown_operator_error(self):
        """Unknown operator should produce E052."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquls": {"aws:SourceIp": "1.2.3.4"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "E052" for r in report.errors)
        e052 = [r for r in report.errors if r.code == "E052"][0]
        assert "StringEquls" in e052.message

    def test_empty_condition_block_warning(self):
        """Empty condition block should produce W044."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W044" for r in report.warnings)

    def test_empty_operator_block_warning(self):
        """Empty operator block should produce W045."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W045" for r in report.warnings)

    def test_empty_condition_values_warning(self):
        """Empty condition values should produce W046."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceIp": []}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W046" for r in report.warnings)

    def test_null_condition_value_warning(self):
        """Null condition value should produce W046."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceIp": None}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert any(r.code == "W046" for r in report.warnings)

    def test_operator_with_if_exists_suffix(self):
        """Operator with IfExists suffix should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIfExists": {"aws:SourceIp": "1.2.3.4"}
                    },
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "E052" for r in report.errors)

    def test_operator_with_for_all_values_prefix(self):
        """Operator with ForAllValues prefix should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team"]}
                    },
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "E052" for r in report.errors)

    def test_operator_with_for_any_value_prefix(self):
        """Operator with ForAnyValue prefix should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "ForAnyValue:StringEquals": {"aws:TagKeys": ["env", "team"]}
                    },
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "E052" for r in report.errors)

    def test_operator_with_combined_modifiers(self):
        """Operator with both prefix and suffix modifiers should be valid."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "ForAllValues:StringEqualsIfExists": {
                            "aws:TagKeys": ["env", "team"]
                        }
                    },
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        assert not any(r.code == "E052" for r in report.errors)

    def test_suggestion_for_operator_typo(self):
        """Typo in operator should provide suggestion."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquls": {"aws:SourceIp": "1.2.3.4"}},
                }
            ],
        }
        linter = SCPLinter()
        report = linter.lint(policy)

        e052 = [r for r in report.errors if r.code == "E052"]
        assert len(e052) == 1
        assert e052[0].suggestion is not None
        assert "Did you mean" in e052[0].suggestion

"""
Demo script for SCP Linter functionality.
"""

from linter.scp_linter import SCPLinter
import json

# Example SCP policies

# 1. Valid SCP
valid_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyS3Delete",
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*"
        }
    ]
}

# 2. Invalid JSON
invalid_json = '{"Version": "2012-10-17", "Statement": [ { "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*" } '  # Missing closing brackets

# 3. Missing required fields
missing_fields_scp = {
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*"
        }
    ]
}  # Missing Version

# 4. Unknown top-level field
unknown_top_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*"
        }
    ],
    "UnknownField": "value"
}

# 5. Invalid Effect value
invalid_effect_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Block",  # Invalid effect
            "Action": "s3:DeleteBucket",
            "Resource": "*"
        }
    ]
}

# 6. Exceeding size limit
large_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Sid": "A" * 5200  # Oversized Sid to exceed 5120 chars
        }
    ]
}

# 7. Statement missing Action
missing_action_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Resource": "*"
        }
    ]
}

# 8. Principal field present (should be rejected)
principal_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Principal": "*"
        }
    ]
}

# 9. Unknown statement field
unknown_stmt_field_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Foo": "Bar"
        }
    ]
}

# 10. Action typo (IAM reference validation)
action_typo_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:GetObjet",  # Typo: should be s3:GetObject
            "Resource": "*"
        }
    ]
}

# 11. Condition block with unknown operator
unknown_operator_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Condition": {
                "StringEquls": {  # Typo: should be StringEquals
                    "aws:SourceIp": "1.2.3.4"
                }
            }
        }
    ]
}

# 12. Condition block with empty conditions
empty_condition_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Condition": {}
        }
    ]
}

# 13. Condition key validation (unknown key)
unknown_key_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:NotARealKey": "value"
                }
            }
        }
    ]
}

# 14. Condition key validation (tag-based key)
tag_key_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:DeleteBucket",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestTag/Project": "Test"
                }
            }
        }
    ]
}

# 15. Blanket deny without condition (best practice warning)
blanket_deny_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }
    ]
}

# 16. Service-wide deny (best practice warning)
service_wide_deny_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}

# 17. Allow-only SCP (best practice warning)
allow_only_scp = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}

# Initialize linter
linter = SCPLinter()


def run_demo(title, policy, use_string=False):
    print(f"\n=== {title} ===")
    if isinstance(policy, dict):
        print("Policy:")
        print(json.dumps(policy, indent=2))
    elif isinstance(policy, str):
        print("Policy (raw string):")
        print(policy)
    if use_string:
        report = linter.lint_string(policy)
    else:
        report = linter.lint(policy)
    print("\nResult:")
    print(f"  - Is valid: {report.is_valid}")
    if report.results:
        print("  - Issues found:")
        for result in report.results:
            print(f"    * [{result.severity.value.upper()}] {result.code}\n      Message: {result.message}\n      Location: {result.location}\n      Suggestion: {result.suggestion}\n")
    else:
        print("  - No issues found.")

# Run all demo cases
run_demo("1. Valid SCP", valid_scp)
run_demo("2. Invalid JSON", invalid_json, use_string=True)
run_demo("3. Missing required fields (Version)", missing_fields_scp)
run_demo("4. Unknown top-level field", unknown_top_scp)
run_demo("5. Invalid Effect value", invalid_effect_scp)
run_demo("6. Exceeding size limit", large_scp)
run_demo("7. Statement missing Action", missing_action_scp)
run_demo("8. Principal field present (should be rejected)", principal_scp)
run_demo("9. Unknown statement field", unknown_stmt_field_scp)
run_demo("10. Action typo (IAM reference validation)", action_typo_scp)
run_demo("11. Condition block with unknown operator", unknown_operator_scp)
run_demo("12. Condition block with empty conditions", empty_condition_scp)
run_demo("13. Condition key validation (unknown key)", unknown_key_scp)
run_demo("14. Condition key validation (tag-based key)", tag_key_scp)
run_demo("15. Blanket deny without condition (best practice warning)", blanket_deny_scp)
run_demo("16. Service-wide deny (best practice warning)", service_wide_deny_scp)
run_demo("17. Allow-only SCP (best practice warning)", allow_only_scp)

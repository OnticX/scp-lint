"""SCP Linter - Validates and analyzes SCP policies for issues."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from dateutil.parser import ParserError  # type: ignore[import-untyped]
from dateutil.parser import parse as parse_date  # type: ignore[import-untyped]

from data.iam_reference import AWSIAMReference, get_iam_reference


class LintSeverity(Enum):
    """Severity levels for lint issues."""

    ERROR = "error"  # Invalid, will not work
    WARNING = "warning"  # Valid but potentially problematic
    INFO = "info"  # Informational, best practices


@dataclass
class LintResult:
    """A single lint issue found in an SCP."""

    severity: LintSeverity
    code: str  # e.g., "E001", "W001", "I001"
    message: str
    location: str | None = None  # e.g., "Statement[0].Action"
    suggestion: str | None = None

    def __str__(self) -> str:
        loc = f" at {self.location}" if self.location else ""
        sug = f" Suggestion: {self.suggestion}" if self.suggestion else ""
        return f"[{self.severity.value.upper()}] {self.code}: {self.message}{loc}{sug}"


@dataclass
class LintReport:
    """Complete lint report for an SCP."""

    results: list[LintResult] = field(default_factory=list)
    policy_size: int = 0
    statement_count: int = 0
    is_valid: bool = True

    @property
    def errors(self) -> list[LintResult]:
        return [r for r in self.results if r.severity == LintSeverity.ERROR]

    @property
    def warnings(self) -> list[LintResult]:
        return [r for r in self.results if r.severity == LintSeverity.WARNING]

    @property
    def infos(self) -> list[LintResult]:
        return [r for r in self.results if r.severity == LintSeverity.INFO]

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    def add(self, result: LintResult) -> None:
        self.results.append(result)
        if result.severity == LintSeverity.ERROR:
            self.is_valid = False


class SCPLinter:
    """
    Linter for AWS Service Control Policies.

    Validates JSON syntax, structure, and best practices.
    """

    # AWS SCP limits
    MAX_POLICY_SIZE = 5120  # characters
    SIZE_WARNING_THRESHOLD = 0.75  # warn at 75% capacity
    MAX_STATEMENTS = 20  # soft limit, warn if exceeded

    # Valid values
    VALID_EFFECTS = {"Allow", "Deny"}
    VALID_VERSIONS = {"2012-10-17", "2008-10-17"}

    # Valid condition operators (base operators, without modifiers)
    VALID_CONDITION_OPERATORS = {
        # String operators
        "StringEquals",
        "StringNotEquals",
        "StringEqualsIgnoreCase",
        "StringNotEqualsIgnoreCase",
        "StringLike",
        "StringNotLike",
        # ARN operators
        "ArnEquals",
        "ArnNotEquals",
        "ArnLike",
        "ArnNotLike",
        # Numeric operators
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
        # Date operators
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        # Boolean and Null
        "Bool",
        "Null",
        # IP address operators
        "IpAddress",
        "NotIpAddress",
        # Binary operators
        "BinaryEquals",
    }

    def __init__(self, iam_reference: AWSIAMReference | None = None) -> None:
        self.report: LintReport = LintReport()
        self._iam_ref = iam_reference

    @property
    def iam_reference(self) -> AWSIAMReference:
        """Get the IAM reference, loading lazily if needed."""
        if self._iam_ref is None:
            self._iam_ref = get_iam_reference()
        return self._iam_ref

    def lint(self, policy: str | Path | dict) -> LintReport:
        """
        Lint an SCP policy.

        Args:
            policy: JSON string, file path, or parsed dict

        Returns:
            LintReport with all issues found
        """
        self.report = LintReport()

        # Step 1: Parse/load the policy
        policy_dict, policy_str = self._load_policy(policy)
        if policy_dict is None:
            return self.report

        # Step 2: Check size limits
        self._check_size(policy_str)

        # Step 3: Validate structure
        self._validate_structure(policy_dict)

        # Step 4: Validate statements
        if "Statement" in policy_dict:
            self._validate_statements(policy_dict["Statement"])

        # Step 5: Check for best practices
        self._check_best_practices(policy_dict)

        return self.report

    def lint_file(self, file_path: str | Path) -> LintReport:
        """Lint an SCP from a file."""
        return self.lint(Path(file_path))

    def lint_string(self, json_str: str) -> LintReport:
        """Lint an SCP from a JSON string."""
        return self.lint(json_str)

    def _load_policy(self, policy: str | Path | dict) -> tuple[dict | None, str]:
        """Load and parse policy, returning (dict, original_string)."""
        policy_str = ""
        policy_dict = None

        if isinstance(policy, dict):
            policy_dict = policy
            policy_str = json.dumps(policy)
            return policy_dict, policy_str

        if isinstance(policy, Path):
            if not policy.exists():
                self.report.add(
                    LintResult(
                        severity=LintSeverity.ERROR,
                        code="E001",
                        message=f"File not found: {policy}",
                    )
                )
                return None, ""

            try:
                policy_str = policy.read_text(encoding="utf-8")
            except Exception as e:
                self.report.add(
                    LintResult(
                        severity=LintSeverity.ERROR,
                        code="E002",
                        message=f"Cannot read file: {e}",
                    )
                )
                return None, ""
        else:
            policy_str = policy

        # Parse JSON
        try:
            policy_dict = json.loads(policy_str)
        except json.JSONDecodeError as e:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E003",
                    message=f"Invalid JSON syntax: {e.msg}",
                    location=f"line {e.lineno}, column {e.colno}",
                    suggestion="Check for missing commas, brackets, or quotes",
                )
            )
            return None, policy_str

        return policy_dict, policy_str

    def _check_size(self, policy_str: str) -> None:
        """Check policy size against AWS limits."""
        # Get size without whitespace (AWS counts minified)
        minified = json.dumps(json.loads(policy_str), separators=(",", ":"))
        size = len(minified)
        self.report.policy_size = size

        if size > self.MAX_POLICY_SIZE:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E010",
                    message=f"Policy exceeds max size: {size}/{self.MAX_POLICY_SIZE} chars",
                    suggestion="Split into multiple SCPs or remove unused statements",
                )
            )
        elif size > self.MAX_POLICY_SIZE * self.SIZE_WARNING_THRESHOLD:
            percent = (size / self.MAX_POLICY_SIZE) * 100
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W010",
                    message=f"Policy is {percent:.0f}% of max size ({size}/{self.MAX_POLICY_SIZE})",
                    suggestion="Consider splitting before adding more statements",
                )
            )

    def _validate_structure(self, policy_dict: dict) -> None:
        """Validate top-level policy structure."""
        # Check Version
        if "Version" not in policy_dict:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E020",
                    message="Missing required field: Version",
                    suggestion='Add "Version": "2012-10-17"',
                )
            )
        elif policy_dict["Version"] not in self.VALID_VERSIONS:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W020",
                    message=f"Unusual Version value: {policy_dict['Version']}",
                    location="Version",
                    suggestion='Use "2012-10-17" (recommended) or "2008-10-17"',
                )
            )

        # Check Statement
        if "Statement" not in policy_dict:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E021",
                    message="Missing required field: Statement",
                    suggestion="Add a Statement array with at least one statement",
                )
            )
        elif not isinstance(policy_dict["Statement"], (list, dict)):
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E022",
                    message="Statement must be an object or array",
                    location="Statement",
                )
            )

        # Check for unknown top-level fields
        valid_fields = {"Version", "Statement", "Id"}
        unknown = set(policy_dict.keys()) - valid_fields
        for field_name in unknown:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W021",
                    message=f"Unknown top-level field: {field_name}",
                    location=field_name,
                    suggestion="Only Version, Statement, and Id are valid at top level",
                )
            )

    def _validate_statements(self, statements: list | dict) -> None:
        """Validate all statements in the policy."""
        if isinstance(statements, dict):
            statements = [statements]

        self.report.statement_count = len(statements)

        if len(statements) == 0:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W030",
                    message="Policy has no statements",
                    suggestion="Add at least one statement to the policy",
                )
            )
            return

        if len(statements) > self.MAX_STATEMENTS:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W031",
                    message=f"Policy has {len(statements)} statements (max: {self.MAX_STATEMENTS})",
                    suggestion="Consider splitting into multiple SCPs for maintainability",
                )
            )

        for i, stmt in enumerate(statements):
            self._validate_statement(stmt, i)

        # W060: Duplicate Sid detection
        sids_seen: dict[str, list[int]] = {}
        for i, stmt in enumerate(statements):
            if isinstance(stmt, dict) and "Sid" in stmt:
                sid = stmt["Sid"]
                if sid not in sids_seen:
                    sids_seen[sid] = []
                sids_seen[sid].append(i)

        for sid, indices in sids_seen.items():
            if len(indices) > 1:
                locations = ", ".join(f"Statement[{i}]" for i in indices)
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W060",
                        message=f"Duplicate Sid '{sid}' found in multiple statements",
                        location=locations,
                        suggestion="Each statement should have a unique Sid for clarity",
                    )
                )

        # W061: Duplicate statement detection
        stmt_signatures: dict[tuple, list[int]] = {}
        for i, stmt in enumerate(statements):
            if isinstance(stmt, dict):
                sig = self._normalize_statement_for_comparison(stmt)
                if sig not in stmt_signatures:
                    stmt_signatures[sig] = []
                stmt_signatures[sig].append(i)

        for _sig, indices in stmt_signatures.items():
            if len(indices) > 1:
                locations = ", ".join(f"Statement[{i}]" for i in indices)
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W061",
                        message="Duplicate statements found (identical Effect, Action, Resource, Condition)",
                        location=locations,
                        suggestion="Remove duplicate statements to improve policy clarity",
                    )
                )

    def _normalize_statement_for_comparison(self, stmt: dict) -> tuple:
        """Normalize a statement for comparison, excluding Sid."""

        def normalize_value(val: Any) -> Any:
            if isinstance(val, list):
                return tuple(sorted(str(v) for v in val))
            elif isinstance(val, dict):
                return tuple(sorted((k, normalize_value(v)) for k, v in val.items()))
            else:
                return str(val)

        compare_fields = ["Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"]
        normalized: list[tuple[str, Any]] = []
        for fld in compare_fields:
            if fld in stmt:
                normalized.append((fld, normalize_value(stmt[fld])))
        return tuple(normalized)

    def _validate_statement(self, stmt: dict, index: int) -> None:
        """Validate a single statement."""
        loc_prefix = f"Statement[{index}]"

        if not isinstance(stmt, dict):
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E030",
                    message="Statement must be an object",
                    location=loc_prefix,
                )
            )
            return

        # Check Effect (required)
        if "Effect" not in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E031",
                    message="Missing required field: Effect",
                    location=loc_prefix,
                    suggestion='Add "Effect": "Deny" or "Effect": "Allow"',
                )
            )
        elif stmt["Effect"] not in self.VALID_EFFECTS:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E032",
                    message=f"Invalid Effect value: {stmt['Effect']}",
                    location=f"{loc_prefix}.Effect",
                    suggestion='Must be "Allow" or "Deny"',
                )
            )

        # Check Action (required for SCPs)
        if "Action" not in stmt and "NotAction" not in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E033",
                    message="Missing required field: Action or NotAction",
                    location=loc_prefix,
                    suggestion='Add "Action": ["service:Action"] or "Action": "*"',
                )
            )
        else:
            action_field = "Action" if "Action" in stmt else "NotAction"
            self._validate_actions(stmt[action_field], f"{loc_prefix}.{action_field}")

        # Check Resource
        if "Resource" not in stmt and "NotResource" not in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.INFO,
                    code="I030",
                    message="No Resource specified, defaults to '*'",
                    location=loc_prefix,
                    suggestion='Explicitly add "Resource": "*" for clarity',
                )
            )

        # Validate Resource ARN format (W080)
        if "Resource" in stmt:
            self._validate_resources(stmt["Resource"], f"{loc_prefix}.Resource")
        elif "NotResource" in stmt:
            self._validate_resources(stmt["NotResource"], f"{loc_prefix}.NotResource")

        # W090: NotAction warning (inverse logic)
        if "NotAction" in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.INFO,
                    code="W090",
                    message="Statement uses NotAction (inverse logic)",
                    location=f"{loc_prefix}.NotAction",
                    suggestion="NotAction can be error-prone; consider using Action with explicit list",
                )
            )

        # W091: NotResource warning (inverse logic)
        if "NotResource" in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.INFO,
                    code="W091",
                    message="Statement uses NotResource (inverse logic)",
                    location=f"{loc_prefix}.NotResource",
                    suggestion="NotResource can be error-prone; consider using Resource with explicit ARNs",
                )
            )

        # Check for Sid
        if "Sid" not in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.INFO,
                    code="I031",
                    message="Statement has no Sid (identifier)",
                    location=loc_prefix,
                    suggestion="Add a Sid for easier debugging and management",
                )
            )

        # Check for Principal in SCP (should not be present)
        if "Principal" in stmt or "NotPrincipal" in stmt:
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E034",
                    message="SCPs cannot have Principal or NotPrincipal",
                    location=loc_prefix,
                    suggestion="Remove Principal - SCPs apply to all principals in the account",
                )
            )

        # Check valid statement fields
        valid_stmt_fields = {
            "Sid",
            "Effect",
            "Action",
            "NotAction",
            "Resource",
            "NotResource",
            "Condition",
        }
        unknown = set(stmt.keys()) - valid_stmt_fields
        for field_name in unknown:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W032",
                    message=f"Unknown statement field: {field_name}",
                    location=f"{loc_prefix}.{field_name}",
                )
            )

        # Validate Condition block (NEW)
        if "Condition" in stmt:
            self._validate_condition_block(stmt["Condition"], f"{loc_prefix}.Condition")

    def _validate_actions(self, actions: str | list, location: str) -> None:
        """Validate action format."""
        if isinstance(actions, str):
            actions = [actions]

        if not isinstance(actions, list):
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E040",
                    message="Action must be a string or array of strings",
                    location=location,
                )
            )
            return

        for i, action in enumerate(actions):
            if not isinstance(action, str):
                self.report.add(
                    LintResult(
                        severity=LintSeverity.ERROR,
                        code="E041",
                        message=f"Action must be a string, got {type(action).__name__}",
                        location=f"{location}[{i}]",
                    )
                )
                continue

            # Check action format (service:action or *)
            if action != "*" and ":" not in action:
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W040",
                        message=f"Action '{action}' missing service prefix",
                        location=f"{location}[{i}]",
                        suggestion='Use format "service:Action" (e.g., "s3:GetObject")',
                    )
                )
            else:
                # Validate action exists in IAM reference (NEW)
                self._validate_action_exists(action, f"{location}[{i}]")

    def _check_best_practices(self, policy_dict: dict) -> None:
        """Check for best practices and common issues."""
        if "Statement" not in policy_dict:
            return

        statements = policy_dict["Statement"]
        if isinstance(statements, dict):
            statements = [statements]

        deny_all_count = 0
        allow_all_count = 0

        for i, stmt in enumerate(statements):
            if not isinstance(stmt, dict):
                continue

            effect = stmt.get("Effect")
            actions_raw = stmt.get("Action", stmt.get("NotAction", []))
            if isinstance(actions_raw, str):
                actions: list[str] = [actions_raw]
            elif isinstance(actions_raw, list):
                actions = actions_raw
            else:
                actions = []

            conditions = stmt.get("Condition")

            # Check for overly broad deny without conditions
            if effect == "Deny" and "*" in actions and not conditions:
                deny_all_count += 1
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W050",
                        message="Blanket Deny on all actions without conditions",
                        location=f"Statement[{i}]",
                        suggestion="Add conditions or be more specific about actions",
                    )
                )

            # Check for service-wide deny without conditions
            if effect == "Deny" and not conditions:
                for action in actions:
                    if isinstance(action, str) and action.endswith(":*") and action != "*":
                        service = action.split(":")[0]
                        self.report.add(
                            LintResult(
                                severity=LintSeverity.WARNING,
                                code="W051",
                                message=f"Denies all {service} actions without conditions",
                                location=f"Statement[{i}]",
                                suggestion=f"Add conditions or specify {service} actions",
                            )
                        )

            # Check for Allow statements (unusual in SCPs)
            if effect == "Allow":
                if "*" in actions:
                    allow_all_count += 1

        # SCP with only Allow * (probably wrong)
        if allow_all_count > 0 and deny_all_count == 0 and len(statements) == allow_all_count:
            self.report.add(
                LintResult(
                    severity=LintSeverity.INFO,
                    code="I050",
                    message="SCP only contains Allow statements",
                    suggestion="SCPs typically use Deny statements to restrict actions",
                )
            )

    # =========================================================================
    # NEW: IAM Reference-based validation
    # =========================================================================

    def _validate_action_exists(self, action: str, location: str) -> None:
        """
        Validate that an action exists in the IAM reference database.

        Checks service prefix validity and action name validity.
        Handles wildcards appropriately.

        Error codes:
            W041: Unknown service prefix
            W042: Unknown action (service exists but action doesn't)
        """
        # Skip universal wildcard
        if action == "*":
            return

        # Skip actions with wildcards in action part (can't validate)
        if ":" in action:
            service, action_name = action.split(":", 1)
            if "*" in action_name or "?" in action_name:
                # Can only validate the service prefix
                if service.lower() not in [s.lower() for s in self.iam_reference.service_prefixes]:
                    suggestion = self._find_similar_service(service)
                    self.report.add(
                        LintResult(
                            severity=LintSeverity.WARNING,
                            code="W041",
                            message=f"Unknown service prefix: '{service}'",
                            location=location,
                            suggestion=suggestion,
                        )
                    )
                return

        # Full action validation
        if not self._is_valid_action_with_case_insensitive(action):
            if ":" in action:
                service, action_name = action.split(":", 1)
                # Check if service exists
                if service.lower() not in [s.lower() for s in self.iam_reference.service_prefixes]:
                    suggestion = self._find_similar_service(service)
                    self.report.add(
                        LintResult(
                            severity=LintSeverity.WARNING,
                            code="W041",
                            message=f"Unknown service prefix: '{service}'",
                            location=location,
                            suggestion=suggestion,
                        )
                    )
                else:
                    # Service exists, but action doesn't
                    suggestion = self._find_similar_action(service, action_name)
                    self.report.add(
                        LintResult(
                            severity=LintSeverity.WARNING,
                            code="W042",
                            message=f"Unknown action: '{action}'",
                            location=location,
                            suggestion=suggestion,
                        )
                    )

    def _is_valid_action_with_case_insensitive(self, action: str) -> bool:
        """Check if action is valid (case-insensitive matching)."""
        if ":" not in action:
            return False

        service, action_name = action.split(":", 1)

        # Find the service (case-insensitive)
        actual_service = None
        for svc_prefix in self.iam_reference.service_prefixes:
            if svc_prefix.lower() == service.lower():
                actual_service = svc_prefix
                break

        if not actual_service:
            return False

        svc_info = self.iam_reference.get_service(actual_service)
        if not svc_info:
            return False

        # Check action (case-insensitive)
        for act in svc_info.all_actions:
            if act.lower() == action_name.lower():
                return True

        return False

    def _find_similar_service(self, service: str) -> str | None:
        """Find similar service prefixes for suggestions."""
        service_lower = service.lower()
        candidates = []

        for svc in self.iam_reference.service_prefixes:
            svc_lower = svc.lower()
            # Check for common typos
            if self._levenshtein_distance(service_lower, svc_lower) <= 2:
                candidates.append(svc)
            elif service_lower in svc_lower or svc_lower in service_lower:
                candidates.append(svc)

        if candidates:
            return f"Did you mean: {', '.join(candidates[:3])}?"
        return None

    def _find_similar_action(self, service: str, action_name: str) -> str | None:
        """Find similar action names for suggestions."""
        # Find actual service prefix (case-insensitive)
        actual_service = None
        for svc_prefix in self.iam_reference.service_prefixes:
            if svc_prefix.lower() == service.lower():
                actual_service = svc_prefix
                break

        if not actual_service:
            return None

        svc_info = self.iam_reference.get_service(actual_service)
        if not svc_info:
            return None

        action_lower = action_name.lower()
        candidates = []

        for act in svc_info.all_actions:
            act_lower = act.lower()
            # Check for common typos
            if self._levenshtein_distance(action_lower, act_lower) <= 2:
                candidates.append(f"{actual_service}:{act}")
            elif action_lower in act_lower or act_lower in action_lower:
                candidates.append(f"{actual_service}:{act}")

        if candidates:
            return f"Did you mean: {', '.join(candidates[:3])}?"
        return None

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return SCPLinter._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row: list[int] = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row: list[int] = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    # =========================================================================
    # NEW: Condition key validation
    # =========================================================================

    def _validate_condition_key(self, key: str, location: str) -> None:
        """
        Validate that a condition key exists in the IAM reference database.

        Error codes:
            W043: Unknown condition key
        """
        # Check if key exists in IAM reference
        key_info = self.iam_reference.get_condition_key(key)

        if key_info is None:
            # Key not found - check for common aws: global keys that might
            # not be in reference but are valid
            if key.lower().startswith("aws:"):
                # Some common global keys that are always valid
                common_global_keys = {
                    "aws:sourceip",
                    "aws:sourcevpc",
                    "aws:sourcevpce",
                    "aws:principalarn",
                    "aws:principalaccount",
                    "aws:principalorgid",
                    "aws:principalorgpaths",
                    "aws:principaltag/",
                    "aws:principaltype",
                    "aws:requesttag/",
                    "aws:resourcetag/",
                    "aws:tagkeys",
                    "aws:requestedregion",
                    "aws:currenttime",
                    "aws:epochtime",
                    "aws:tokenissuetime",
                    "aws:multifactorauthpresent",
                    "aws:multifactorauthage",
                    "aws:securetransport",
                    "aws:useragent",
                    "aws:userid",
                    "aws:username",
                    "aws:via-awsservice",
                    "aws:calledalias",
                    "aws:calledviaservice",
                    "aws:referer",
                    "aws:fatalerror",
                }
                key_lower = key.lower()
                # Check exact match or prefix match (for tag keys)
                if key_lower in common_global_keys:
                    return
                for common_key in common_global_keys:
                    if common_key.endswith("/") and key_lower.startswith(common_key):
                        return

            suggestion = self._find_similar_condition_key(key)
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W043",
                    message=f"Unknown condition key: '{key}'",
                    location=location,
                    suggestion=suggestion,
                )
            )

    def _find_similar_condition_key(self, key: str) -> str | None:
        """Find similar condition keys for suggestions."""
        key_lower = key.lower()
        candidates = []

        # Check global keys
        for gk in self.iam_reference.global_condition_keys:
            if self._levenshtein_distance(key_lower, gk.lower()) <= 3:
                candidates.append(gk)

        # Check service-specific keys if key has service prefix
        if ":" in key:
            prefix = key.split(":")[0]
            svc = self.iam_reference.get_service(prefix)
            if svc:
                for ck in svc.condition_keys:
                    if self._levenshtein_distance(key_lower, ck.lower()) <= 3:
                        candidates.append(ck)

        if candidates:
            return f"Did you mean: {', '.join(candidates[:3])}?"
        return None

    # =========================================================================
    # NEW: Condition block syntax validation
    # =========================================================================

    def _validate_condition_block(self, conditions: Any, location: str) -> None:
        """
        Validate the structure and content of a Condition block.

        Expected structure:
        {
            "Operator": {
                "ConditionKey": "value" | ["value1", "value2"]
            }
        }

        Error codes:
            E050: Condition block must be an object
            E051: Condition operator value must be an object
            E052: Unknown condition operator
            W043: Unknown condition key (via _validate_condition_key)
            W044: Empty condition block
            W045: Empty operator block
            W046: Empty condition values
        """
        if conditions is None:
            return

        if not isinstance(conditions, dict):
            self.report.add(
                LintResult(
                    severity=LintSeverity.ERROR,
                    code="E050",
                    message="Condition block must be an object",
                    location=location,
                )
            )
            return

        if len(conditions) == 0:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W044",
                    message="Empty Condition block",
                    location=location,
                    suggestion="Remove empty Condition or add conditions",
                )
            )
            return

        for operator, key_values in conditions.items():
            op_location = f"{location}.{operator}"

            # Validate operator
            base_operator = self._extract_base_operator(operator)
            if base_operator not in self.VALID_CONDITION_OPERATORS:
                suggestion = self._find_similar_operator(base_operator)
                self.report.add(
                    LintResult(
                        severity=LintSeverity.ERROR,
                        code="E052",
                        message=f"Unknown condition operator: '{operator}'",
                        location=op_location,
                        suggestion=suggestion,
                    )
                )
                continue

            # Validate operator value is a dict
            if not isinstance(key_values, dict):
                self.report.add(
                    LintResult(
                        severity=LintSeverity.ERROR,
                        code="E051",
                        message=f"Condition operator '{operator}' value must be an object",
                        location=op_location,
                        suggestion="Use format: {\"ConditionKey\": \"value\"}",
                    )
                )
                continue

            if len(key_values) == 0:
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W045",
                        message=f"Empty condition operator block: '{operator}'",
                        location=op_location,
                        suggestion="Add condition keys or remove the operator",
                    )
                )
                continue

            # Validate each condition key
            for cond_key, cond_values in key_values.items():
                key_location = f"{op_location}.{cond_key}"

                # Validate condition key exists
                self._validate_condition_key(cond_key, key_location)

                # W070: IP address format validation for IpAddress/NotIpAddress operators
                if base_operator in ("IpAddress", "NotIpAddress"):
                    self._validate_ip_address_format(cond_values, key_location)

                # W071: Date format validation for Date* operators
                if base_operator.startswith("Date"):
                    self._validate_date_format(cond_values, key_location)

                # Validate condition values are not empty
                if cond_values is None:
                    self.report.add(
                        LintResult(
                            severity=LintSeverity.WARNING,
                            code="W046",
                            message=f"Null condition value for key: '{cond_key}'",
                            location=key_location,
                            suggestion="Provide a value or remove the condition",
                        )
                    )
                elif isinstance(cond_values, list) and len(cond_values) == 0:
                    self.report.add(
                        LintResult(
                            severity=LintSeverity.WARNING,
                            code="W046",
                            message=f"Empty condition values for key: '{cond_key}'",
                            location=key_location,
                            suggestion="Provide values or remove the condition",
                        )
                    )

    def _extract_base_operator(self, operator: str) -> str:
        """
        Extract the base operator from an operator string.

        Handles modifiers like IfExists suffix and ForAllValues/ForAnyValue prefix.
        """
        base = operator

        # Remove IfExists suffix
        if base.endswith("IfExists"):
            base = base[:-8]

        # Remove ForAllValues/ForAnyValue prefix
        if base.startswith("ForAllValues:"):
            base = base[13:]
        elif base.startswith("ForAnyValue:"):
            base = base[12:]

        return base

    def _find_similar_operator(self, operator: str) -> str | None:
        """Find similar operator names for suggestions."""
        op_lower = operator.lower()
        candidates = []

        for valid_op in self.VALID_CONDITION_OPERATORS:
            if self._levenshtein_distance(op_lower, valid_op.lower()) <= 3:
                candidates.append(valid_op)

        if candidates:
            return f"Did you mean: {', '.join(candidates[:3])}?"
        return None

    # =========================================================================
    # NEW v0.2.0: IP address, date, and ARN validation
    # =========================================================================

    def _validate_ip_address_format(self, value: Any, location: str) -> None:
        """
        Validate IP address or CIDR format.

        Error codes:
            W070: Invalid IP address or CIDR format
        """
        if isinstance(value, list):
            for i, v in enumerate(value):
                self._validate_ip_address_format(v, f"{location}[{i}]")
            return

        if not isinstance(value, str):
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W070",
                    message=f"IP address value must be a string, got {type(value).__name__}",
                    location=location,
                    suggestion="Use string format like '192.0.2.0/24' or '192.0.2.1'",
                )
            )
            return

        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
        except ValueError:
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W070",
                    message=f"Invalid IP address or CIDR format: '{value}'",
                    location=location,
                    suggestion="Use valid IPv4 (192.0.2.0/24) or IPv6 (2001:db8::/32) format",
                )
            )

    def _validate_date_format(self, value: Any, location: str) -> None:
        """
        Validate date format for date condition operators.

        Error codes:
            W071: Invalid date format
        """
        if isinstance(value, list):
            for i, v in enumerate(value):
                self._validate_date_format(v, f"{location}[{i}]")
            return

        if not isinstance(value, str):
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W071",
                    message=f"Date value must be a string, got {type(value).__name__}",
                    location=location,
                    suggestion="Use ISO 8601 format like '2023-01-15T00:00:00Z'",
                )
            )
            return

        try:
            parse_date(value)
        except (ParserError, ValueError):
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W071",
                    message=f"Invalid date format: '{value}'",
                    location=location,
                    suggestion="Use ISO 8601 format like '2023-01-15T00:00:00Z'",
                )
            )

    def _validate_resources(self, resources: Any, location: str) -> None:
        """
        Validate Resource/NotResource ARN format.

        Error codes:
            W080: Invalid ARN format
        """
        if isinstance(resources, str):
            resources = [resources]

        if not isinstance(resources, list):
            self.report.add(
                LintResult(
                    severity=LintSeverity.WARNING,
                    code="W080",
                    message="Resource must be a string or array of strings",
                    location=location,
                )
            )
            return

        for i, resource in enumerate(resources):
            res_location = f"{location}[{i}]" if len(resources) > 1 else location

            if not isinstance(resource, str):
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W080",
                        message=f"Resource must be a string, got {type(resource).__name__}",
                        location=res_location,
                    )
                )
                continue

            # "*" is always valid (matches all resources)
            if resource == "*":
                continue

            # Wildcard patterns not starting with arn: are allowed
            if not resource.startswith("arn:"):
                if "*" not in resource and "?" not in resource:
                    self.report.add(
                        LintResult(
                            severity=LintSeverity.WARNING,
                            code="W080",
                            message=f"Resource '{resource}' does not appear to be a valid ARN",
                            location=res_location,
                            suggestion="ARNs should follow format: arn:partition:service:region:account:resource",
                        )
                    )
                continue

            # Parse ARN components
            parts = resource.split(":")
            if len(parts) < 6:
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W080",
                        message=f"ARN has too few components: '{resource}'",
                        location=res_location,
                        suggestion="ARN format: arn:partition:service:region:account:resource",
                    )
                )
                continue

            # Validate partition (parts[1])
            partition = parts[1]
            valid_partitions = {"aws", "aws-cn", "aws-us-gov", "*"}
            if partition not in valid_partitions and "*" not in partition and "?" not in partition:
                self.report.add(
                    LintResult(
                        severity=LintSeverity.WARNING,
                        code="W080",
                        message=f"Unknown partition in ARN: '{partition}'",
                        location=res_location,
                        suggestion="Valid partitions: aws, aws-cn, aws-us-gov",
                    )
                )

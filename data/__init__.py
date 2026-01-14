"""AWS IAM Reference Data module.

This module provides utilities for querying AWS IAM actions, resources,
and condition keys for test case generation and SCP validation.
"""

## Removed imports from scp_simulator.data.fixture_generator and scp_simulator.data.iam_reference

__all__ = [
    "AWSIAMReference",
    "ServiceInfo",
    "ResourceInfo",
    "ConditionKeyInfo",
    "get_iam_reference",
    "FixtureGenerator",
    "GeneratorConfig",
    "generate_deny_policy",
    "generate_test_events",
]

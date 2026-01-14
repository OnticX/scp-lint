"""AWS IAM Reference Data module.

This module provides utilities for querying AWS IAM actions, resources,
and condition keys for test case generation and SCP validation.
"""

from .iam_reference import (
    AWSIAMReference,
    ConditionKeyInfo,
    ResourceInfo,
    ServiceInfo,
    get_iam_reference,
)

__all__ = [
    "AWSIAMReference",
    "ServiceInfo",
    "ResourceInfo",
    "ConditionKeyInfo",
    "get_iam_reference",
]

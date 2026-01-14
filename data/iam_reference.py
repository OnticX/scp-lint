"""AWS IAM Reference Data utilities.

This module provides a Python interface for querying AWS IAM actions,
resources, and condition keys from the reference database.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ConditionKeyInfo:
    """Information about a condition key."""

    name: str
    type: str
    description: str
    values: list[str] = field(default_factory=list)


@dataclass
class ResourceInfo:
    """Information about a resource type."""

    name: str
    arn_pattern: str
    example: str
    condition_keys: list[str] = field(default_factory=list)


@dataclass
class ServiceInfo:
    """Information about an AWS service."""

    name: str
    prefix: str
    actions_by_access_level: dict[str, list[str]]
    resources: dict[str, ResourceInfo]
    condition_keys: dict[str, ConditionKeyInfo]

    @property
    def all_actions(self) -> list[str]:
        """Get all actions for this service."""
        actions = []
        for action_list in self.actions_by_access_level.values():
            actions.extend(action_list)
        return sorted(set(actions))

    def get_actions_by_level(self, level: str) -> list[str]:
        """Get actions for a specific access level."""
        return self.actions_by_access_level.get(level, [])

    def get_iam_action(self, action_name: str) -> str:
        """Get the full IAM action string (prefix:action)."""
        return f"{self.prefix}:{action_name}"


class AWSIAMReference:
    """AWS IAM Reference database for actions, resources, and condition keys."""

    def __init__(self, data_path: Path | str | None = None):
        """Initialize the reference database.

        Args:
            data_path: Path to the JSON reference file. If None, uses the
                default bundled reference file.
        """
        if data_path is None:
            data_path = Path(__file__).parent / "aws_iam_reference.json"
        elif isinstance(data_path, str):
            data_path = Path(data_path)

        self._data_path = data_path
        self._data: dict[str, Any] = {}
        self._services: dict[str, ServiceInfo] = {}
        self._global_condition_keys: dict[str, ConditionKeyInfo] = {}
        self._condition_operators: dict[str, dict[str, str]] = {}
        self._loaded = False

    def _load(self) -> None:
        """Load the reference data from JSON."""
        if self._loaded:
            return

        with open(self._data_path, encoding="utf-8") as f:
            self._data = json.load(f)

        # Parse services
        for prefix, service_data in self._data.get("services", {}).items():
            resources = {}
            for res_name, res_data in service_data.get("resources", {}).items():
                resources[res_name] = ResourceInfo(
                    name=res_name,
                    arn_pattern=res_data.get("arn_pattern", ""),
                    example=res_data.get("example", ""),
                    condition_keys=res_data.get("condition_keys", []),
                )

            condition_keys = {}
            for key_name, key_data in service_data.get("condition_keys", {}).items():
                condition_keys[key_name] = ConditionKeyInfo(
                    name=key_name,
                    type=key_data.get("type", "String"),
                    description=key_data.get("description", ""),
                    values=key_data.get("values", []),
                )

            self._services[prefix] = ServiceInfo(
                name=service_data.get("name", prefix),
                prefix=prefix,
                actions_by_access_level=service_data.get("actions", {}),
                resources=resources,
                condition_keys=condition_keys,
            )

        # Parse global condition keys
        for key_name, key_data in self._data.get("global_condition_keys", {}).items():
            self._global_condition_keys[key_name] = ConditionKeyInfo(
                name=key_name,
                type=key_data.get("type", "String"),
                description=key_data.get("description", ""),
                values=key_data.get("values", []),
            )

        # Parse condition operators
        self._condition_operators = self._data.get("condition_operators", {})

        self._loaded = True

    @property
    def services(self) -> dict[str, ServiceInfo]:
        """Get all services."""
        self._load()
        return self._services

    @property
    def service_prefixes(self) -> list[str]:
        """Get all service prefixes."""
        self._load()
        return list(self._services.keys())

    @property
    def global_condition_keys(self) -> dict[str, ConditionKeyInfo]:
        """Get global condition keys."""
        self._load()
        return self._global_condition_keys

    @property
    def condition_operators(self) -> dict[str, dict[str, str]]:
        """Get condition operators by category."""
        self._load()
        return self._condition_operators

    def get_service(self, prefix: str) -> ServiceInfo | None:
        """Get a service by prefix."""
        self._load()
        return self._services.get(prefix)

    def get_all_actions(self, prefix: str | None = None) -> list[str]:
        """Get all actions, optionally filtered by service prefix.

        Args:
            prefix: Service prefix to filter by. If None, returns all actions.

        Returns:
            List of full action strings (prefix:action).
        """
        self._load()
        actions = []

        if prefix:
            service = self._services.get(prefix)
            if service:
                for action in service.all_actions:
                    actions.append(f"{prefix}:{action}")
        else:
            for svc_prefix, service in self._services.items():
                for action in service.all_actions:
                    actions.append(f"{svc_prefix}:{action}")

        return sorted(actions)

    def get_actions_by_access_level(self, level: str, prefix: str | None = None) -> list[str]:
        """Get actions by access level.

        Args:
            level: Access level (read, write, list, permissions_management, tagging).
            prefix: Service prefix to filter by. If None, returns all services.

        Returns:
            List of full action strings (prefix:action).
        """
        self._load()
        actions = []

        if prefix:
            service = self._services.get(prefix)
            if service:
                for action in service.get_actions_by_level(level):
                    actions.append(f"{prefix}:{action}")
        else:
            for svc_prefix, service in self._services.items():
                for action in service.get_actions_by_level(level):
                    actions.append(f"{svc_prefix}:{action}")

        return sorted(actions)

    def get_resource_arn_pattern(self, prefix: str, resource_type: str) -> str | None:
        """Get the ARN pattern for a resource type.

        Args:
            prefix: Service prefix.
            resource_type: Resource type name.

        Returns:
            ARN pattern string or None if not found.
        """
        self._load()
        service = self._services.get(prefix)
        if service:
            resource = service.resources.get(resource_type)
            if resource:
                return resource.arn_pattern
        return None

    def get_example_arn(self, prefix: str, resource_type: str) -> str | None:
        """Get an example ARN for a resource type.

        Args:
            prefix: Service prefix.
            resource_type: Resource type name.

        Returns:
            Example ARN string or None if not found.
        """
        self._load()
        service = self._services.get(prefix)
        if service:
            resource = service.resources.get(resource_type)
            if resource:
                return resource.example
        return None

    def get_condition_key(self, key_name: str) -> ConditionKeyInfo | None:
        """Get information about a condition key.

        Args:
            key_name: The condition key name (e.g., 'aws:SourceIp' or 's3:prefix').

        Returns:
            ConditionKeyInfo or None if not found.
        """
        self._load()

        # Check global keys first
        if key_name in self._global_condition_keys:
            return self._global_condition_keys[key_name]

        # Check service-specific keys
        if ":" in key_name:
            prefix = key_name.split(":")[0]
            service = self._services.get(prefix)
            if service and key_name in service.condition_keys:
                return service.condition_keys[key_name]

        return None

    def is_valid_action(self, action: str) -> bool:
        """Check if an action is valid.

        Args:
            action: Full action string (prefix:action).

        Returns:
            True if the action is in the reference database.
        """
        self._load()

        if ":" not in action:
            return False

        prefix, action_name = action.split(":", 1)

        # Handle wildcards
        if action_name == "*":
            return prefix in self._services

        service = self._services.get(prefix)
        if not service:
            return False

        return action_name in service.all_actions

    def random_action(self, prefix: str | None = None) -> str:
        """Get a random action.

        Args:
            prefix: Service prefix to filter by. If None, picks from all services.

        Returns:
            A random action string (prefix:action).
        """
        actions = self.get_all_actions(prefix)
        if not actions:
            raise ValueError(f"No actions found for prefix: {prefix}")
        return random.choice(actions)

    def random_actions(
        self, count: int, prefix: str | None = None, unique: bool = True
    ) -> list[str]:
        """Get multiple random actions.

        Args:
            count: Number of actions to return.
            prefix: Service prefix to filter by. If None, picks from all services.
            unique: If True, returns unique actions (no duplicates).

        Returns:
            List of random action strings.
        """
        actions = self.get_all_actions(prefix)
        if not actions:
            raise ValueError(f"No actions found for prefix: {prefix}")

        if unique:
            if count > len(actions):
                count = len(actions)
            return random.sample(actions, count)
        else:
            return [random.choice(actions) for _ in range(count)]


# Module-level singleton instance
_instance: AWSIAMReference | None = None


def get_iam_reference() -> AWSIAMReference:
    """Get the singleton IAM reference instance."""
    global _instance
    if _instance is None:
        _instance = AWSIAMReference()
    return _instance

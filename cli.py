"""
CLI for SCP Linter
Usage:
  python cli.py <policy_file.json>
  python cli.py <directory_with_json_files>
"""
import sys
import os
import json
from linter.scp_linter import SCPLinter

def lint_file(path):
    # Check if file is a valid SCP (has 'Version' and 'Statement')
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"\nFAILED: {path} (invalid JSON: {e})")
        return False
    if not (isinstance(data, dict) and 'Version' in data and 'Statement' in data):
        print(f"\nSkipping: {path} (not an SCP policy)")
        return None
    linter = SCPLinter()
    report = linter.lint(data)
    return report

def print_report(report, file_path):
    if report is None:
        return False
    if report is False:
        # This means JSON was invalid
        return False

    # Group results by severity
    errors = [r for r in report.results if r.severity.value == "error"]
    warnings = [r for r in report.results if r.severity.value == "warning"]
    infos = [r for r in report.results if r.severity.value == "info"]

    # Status indicator
    if not report.is_valid:
        status = "FAILED"
    elif errors or warnings:
        status = "PASSED with warnings"
    else:
        status = "PASSED"

    print(f"\n{'='*60}")
    print(f"File: {file_path}")
    print(f"Status: {status}")
    print(f"{'='*60}")

    if not report.results:
        print("  No issues found.")
        return report.is_valid

    # Print errors first
    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for result in errors:
            print(f"    [{result.code}] {result.message}")
            if result.location:
                print(f"           Location: {result.location}")
            if result.suggestion:
                print(f"           Suggestion: {result.suggestion}")

    # Then warnings
    if warnings:
        print(f"\n  WARNINGS ({len(warnings)}):")
        for result in warnings:
            print(f"    [{result.code}] {result.message}")
            if result.location:
                print(f"           Location: {result.location}")
            if result.suggestion:
                print(f"           Suggestion: {result.suggestion}")

    # Then info
    if infos:
        print(f"\n  INFO ({len(infos)}):")
        for result in infos:
            print(f"    [{result.code}] {result.message}")
            if result.location:
                print(f"           Location: {result.location}")
            if result.suggestion:
                print(f"           Suggestion: {result.suggestion}")

    return report.is_valid

def main():
    if len(sys.argv) != 2:
        print("Usage: python cli.py <policy_file.json> or <directory>")
        sys.exit(1)
    target = sys.argv[1]

    # Track statistics
    stats = {"passed": 0, "failed": 0, "skipped": 0, "invalid_json": 0}

    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fname in files:
                if fname.endswith('.json'):
                    fpath = os.path.join(root, fname)
                    report = lint_file(fpath)
                    if report is None:
                        stats["skipped"] += 1
                    elif report is False:
                        stats["invalid_json"] += 1
                    else:
                        valid = print_report(report, fpath)
                        if valid:
                            stats["passed"] += 1
                        else:
                            stats["failed"] += 1
    else:
        report = lint_file(target)
        if report is None:
            stats["skipped"] += 1
        elif report is False:
            stats["invalid_json"] += 1
        else:
            valid = print_report(report, target)
            if valid:
                stats["passed"] += 1
            else:
                stats["failed"] += 1

    # Print summary
    total = stats["passed"] + stats["failed"]
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"  SCPs linted:    {total}")
    print(f"  Passed:         {stats['passed']}")
    print(f"  Failed:         {stats['failed']}")
    if stats["skipped"]:
        print(f"  Skipped:        {stats['skipped']} (not SCP files)")
    if stats["invalid_json"]:
        print(f"  Invalid JSON:   {stats['invalid_json']}")
    print(f"{'='*60}")

    if stats["failed"] > 0 or stats["invalid_json"] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()

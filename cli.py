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
        if not (isinstance(data, dict) and 'Version' in data and 'Statement' in data):
            print(f"\nSkipping: {path} (not an SCP policy)")
            return None
    except Exception as e:
        print(f"\nSkipping: {path} (invalid JSON: {e})")
        return None
    linter = SCPLinter()
    report = linter.lint(data)
    return report

def print_report(report, file_path):
    if report is None:
        return False
    print(f"\nLinting: {file_path}")
    print(f"  - Is valid: {report.is_valid}")
    if report.results:
        print("  - Issues found:")
        for result in report.results:
            print(f"    * [{result.severity.value.upper()}] {result.code}\n      Message: {result.message}\n      Location: {result.location}\n      Suggestion: {result.suggestion}\n")
    else:
        print("  - No issues found.")
    return report.is_valid

def main():
    if len(sys.argv) != 2:
        print("Usage: python cli.py <policy_file.json> or <directory>")
        sys.exit(1)
    target = sys.argv[1]
    all_valid = True
    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fname in files:
                if fname.endswith('.json'):
                    fpath = os.path.join(root, fname)
                    report = lint_file(fpath)
                    valid = print_report(report, fpath)
                    if valid is False:
                        all_valid = False
    else:
        report = lint_file(target)
        valid = print_report(report, target)
        if valid is False:
            all_valid = False
    if not all_valid:
        sys.exit(1)

if __name__ == "__main__":
    main()

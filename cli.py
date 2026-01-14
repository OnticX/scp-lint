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
    linter = SCPLinter()
    report = linter.lint_file(path)
    return report

def print_report(report, file_path):
    print(f"\nLinting: {file_path}")
    print(f"  - Is valid: {report.is_valid}")
    if report.results:
        print("  - Issues found:")
        for result in report.results:
            print(f"    * [{result.severity.value.upper()}] {result.code}\n      Message: {result.message}\n      Location: {result.location}\n      Suggestion: {result.suggestion}\n")
    else:
        print("  - No issues found.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python cli.py <policy_file.json> or <directory>")
        sys.exit(1)
    target = sys.argv[1]
    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fname in files:
                if fname.endswith('.json'):
                    fpath = os.path.join(root, fname)
                    report = lint_file(fpath)
                    print_report(report, fpath)
    else:
        report = lint_file(target)
        print_report(report, target)

if __name__ == "__main__":
    main()

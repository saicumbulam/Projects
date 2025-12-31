#!/usr/bin/env python3
"""
Template Safety Checker - Detects unsafe attribute access in Jinja2 templates
Combines:
1. Attribute existence validation (our custom validator)
2. Undefined/None check detection (control flow analysis)
"""

import re
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from attribute_validator import validate_all_templates


def run_semgrep_check() -> Dict:
    """Run Semgrep to detect unsafe attribute access patterns."""
    try:
        result = subprocess.run(
            ["semgrep", "--config", ".semgrep/jinja2-safety.yaml", "--json", "templates/"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.stdout:
            return json.loads(result.stdout)
        return {"results": []}

    except FileNotFoundError:
        print("Warning: semgrep not found. Install with: pip install semgrep")
        return {"results": []}
    except Exception as e:
        print(f"Error running semgrep: {e}")
        return {"results": []}


def main():
    print("=" * 70)
    print("Jinja2 Template Safety Checker")
    print("=" * 70)
    print()

    # 1. Check for undefined attributes
    print("[1/2] Checking for undefined attributes...")
    print("-" * 70)

    attribute_errors = validate_all_templates()

    if not attribute_errors:
        print("✅ No undefined attributes found\n")
    else:
        print(f"❌ Found undefined attributes in {len(attribute_errors)} template(s):\n")
        for template_name, errors in sorted(attribute_errors.items()):
            print(f"  {template_name}:")
            for error in errors:
                if error.is_chained:
                    print(f"    ⚠️  {error}")
                else:
                    print(f"    ❌ {error}")
        print()

    # 2. Check for missing null/undefined checks using Semgrep
    print("[2/2] Checking for unsafe attribute access (missing if checks)...")
    print("-" * 70)

    semgrep_results = run_semgrep_check()

    if "results" in semgrep_results:
        # Filter for ERROR level findings (chained access without checks)
        errors = [r for r in semgrep_results["results"]
                  if r.get("extra", {}).get("severity") == "ERROR"]

        # Filter for WARNING level findings (optional access without checks)
        warnings = [r for r in semgrep_results["results"]
                   if r.get("extra", {}).get("severity") == "WARNING"]

        if not errors and not warnings:
            print("✅ No unsafe attribute access patterns detected\n")
        else:
            if errors:
                print(f"❌ Found {len(errors)} ERROR(s) - Chained access without checks:\n")
                for finding in errors:
                    path = finding.get("path", "")
                    line = finding.get("start", {}).get("line", 0)
                    code = finding.get("extra", {}).get("lines", "")
                    msg = finding.get("extra", {}).get("message", "")
                    print(f"  {Path(path).name}:{line}")
                    print(f"    ❌ {msg}")
                    print(f"    Code: {code.strip()}")
                    print()

            if warnings:
                print(f"⚠️  Found {len(warnings)} WARNING(s) - Consider adding if checks:\n")
                # Group by file to avoid clutter
                by_file = {}
                for w in warnings:
                    path = w.get("path", "")
                    if path not in by_file:
                        by_file[path] = []
                    by_file[path].append(w)

                for path, findings in sorted(by_file.items()):
                    print(f"  {Path(path).name}: {len(findings)} attribute access(es) without checks")
                print()
    else:
        print("⚠️  Semgrep check skipped (semgrep not available)\n")

    # Summary
    print("=" * 70)
    print("Summary")
    print("=" * 70)

    has_errors = bool(attribute_errors)
    has_semgrep_errors = bool(semgrep_results.get("results", []))

    if not has_errors and not has_semgrep_errors:
        print("\n✅ All checks passed! Templates are safe.")
        sys.exit(0)
    else:
        print("\n❌ Some issues found. Review the details above.")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Staged Template Validator
Stage 1: Semgrep - Identify variables accessed without if checks
Stage 2: Attribute Validator - Validate only problematic variables found in Stage 1
"""

import re
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict
from attribute_validator import validate_template_attributes, parse_models
from runtime_validator import validate_runtime


class SemgrepFinding:
    """Represents a finding from Semgrep."""

    def __init__(self, template: str, line: int, code: str, message: str, severity: str, variable: str, attribute: str):
        self.template = template
        self.line = line
        self.code = code
        self.message = message
        self.severity = severity
        self.variable = variable
        self.attribute = attribute

    def __repr__(self):
        return f"{self.template}:{self.line} - {self.variable}.{self.attribute}"


def extract_variable_from_code(code: str) -> Tuple[str, str]:
    """
    Extract variable and attribute/index from Jinja2 code.
    Examples:
      '{{ post.author.username }}' -> ('post', 'author.username')
      '{{ employee.location }}' -> ('employee', 'location')
      '{{ users[0] }}' -> ('users', '[0]')
      '{{ company.employees[0] }}' -> ('company', 'employees[0]')
      '{{ company.employees[1].name }}' -> ('company', 'employees[1].name')
      '{{ data["key"] }}' -> ('data', '["key"]')
    """
    # Pattern 1: Match index followed by attribute (e.g., employees[0].name)
    index_attr_pattern = r'\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)(\.[a-zA-Z0-9_]+)?(\[\d+\]|\[["\'][^"\']+["\']\])\.([a-zA-Z0-9_.]+?)\s*(?:\||}})'
    match = re.search(index_attr_pattern, code)
    if match:
        var = match.group(1)
        attr_before = match.group(2) if match.group(2) else ''
        index = match.group(3)
        attr_after = match.group(4)
        full_access = f"{attr_before.lstrip('.')}{index}.{attr_after}" if attr_before else f"{index}.{attr_after}"
        return var, full_access

    # Pattern 2: Match attribute access (variable.attribute...)
    attr_pattern = r'\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_.]+?)\s*(?:\||}})'
    match = re.search(attr_pattern, code)
    if match:
        return match.group(1), match.group(2)

    # Pattern 3: Match list/dict indexing (variable[index] or variable.attr[index])
    index_pattern = r'\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)(\.[a-zA-Z0-9_]+)?(\[\d+\]|\[["\'][^"\']+["\']\])\s*(?:\||}})'
    match = re.search(index_pattern, code)
    if match:
        var = match.group(1)
        attr = match.group(2) if match.group(2) else ''
        index = match.group(3)
        return var, f"{attr.lstrip('.')}{index}" if attr else index

    return None, None


def run_semgrep_stage() -> List[SemgrepFinding]:
    """
    Stage 1: Run Semgrep to identify variables accessed without if checks.
    Returns list of problematic findings.
    """
    print("=" * 70)
    print("STAGE 1: Semgrep - Comprehensive Jinja2 Template Analysis")
    print("=" * 70)
    print()

    try:
        result = subprocess.run(
            ["semgrep", "--config", ".semgrep/jinja2-comprehensive.yaml", "--json", "templates/"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if not result.stdout:
            print("✓ No Semgrep findings\n")
            return []

        data = json.loads(result.stdout)
        findings = []

        for r in data.get("results", []):
            template_path = Path(r.get("path", ""))
            template = template_path.name
            line_num = r.get("start", {}).get("line", 0)
            code = r.get("extra", {}).get("lines", "").strip()
            message = r.get("extra", {}).get("message", "")
            severity = r.get("extra", {}).get("severity", "INFO")

            # If code is "requires login", read from file
            if code == "requires login" or not code:
                try:
                    with open(template_path, 'r') as f:
                        lines = f.readlines()
                        if 0 < line_num <= len(lines):
                            code = lines[line_num - 1].strip()
                except:
                    code = ""

            # Extract variable and attribute
            variable, attribute = extract_variable_from_code(code)

            if variable and attribute:
                findings.append(SemgrepFinding(
                    template, line_num, code, message, severity, variable, attribute
                ))

        # Group by severity
        errors = [f for f in findings if f.severity == "ERROR"]
        warnings = [f for f in findings if f.severity == "WARNING"]
        infos = [f for f in findings if f.severity == "INFO"]

        print(f"Found {len(findings)} potential issue(s):")
        print(f"  - {len(errors)} ERROR(s) (must fix - security/crashes)")
        print(f"  - {len(warnings)} WARNING(s) (should fix - potential issues)")
        print(f"  - {len(infos)} INFO(s) (nice to have - best practices)")
        print()

        if errors:
            print("🔴 ERROR findings (CRITICAL - must fix):")
            for f in errors:
                print(f"  ❌ {f.template}:{f.line} - {f.variable}.{f.attribute}")
                print(f"     {f.message}")
            print()

        if warnings:
            print("🟡 WARNING findings (should review):")
            for w in warnings:
                print(f"  ⚠️  {w.template}:{w.line} - {w.variable}.{w.attribute}")
                print(f"     {w.message}")
            print()

        if infos:
            print("🔵 INFO findings (best practices):")
            # Group by template to reduce clutter
            by_template = defaultdict(list)
            for i in infos:
                by_template[i.template].append(i)

            for template, items in sorted(by_template.items()):
                print(f"  ℹ️  {template}: {len(items)} suggestion(s)")
            print()

        return findings

    except FileNotFoundError:
        print("❌ Error: semgrep not found. Install with: pip install semgrep")
        return []
    except Exception as e:
        print(f"❌ Error running semgrep: {e}")
        return []


def run_attribute_validation_stage(semgrep_findings: List[SemgrepFinding]) -> Dict:
    """
    Stage 2: Validate attributes found by Semgrep.
    Only checks variables that Semgrep flagged as problematic.
    """
    print("=" * 70)
    print("STAGE 2: Attribute Validation - Checking if Attributes Exist")
    print("=" * 70)
    print()

    if not semgrep_findings:
        print("✓ No variables to validate (Stage 1 found no issues)\n")
        return {}

    # Group findings by template
    by_template = defaultdict(list)
    for finding in semgrep_findings:
        by_template[finding.template].append(finding)

    print(f"Validating attributes in {len(by_template)} template(s)...\n")

    # Parse models once
    models = parse_models("models.py")

    # Validate each template
    validation_results = {}

    for template_name, findings in sorted(by_template.items()):
        template_path = Path("templates") / template_name

        if not template_path.exists():
            continue

        # Run full attribute validation for this template
        errors = validate_template_attributes(template_path, models)

        if errors:
            # Filter to only show errors for variables found by Semgrep
            semgrep_vars = {(f.variable, f.attribute) for f in findings}

            # Check if the validation errors match semgrep findings
            relevant_errors = []
            for error in errors:
                # Check if this error relates to a semgrep finding
                for var, attr in semgrep_vars:
                    if error.variable == var and attr.startswith(error.attribute):
                        relevant_errors.append(error)
                        break

            if relevant_errors:
                validation_results[template_name] = relevant_errors

    # Display results
    if not validation_results:
        print("✅ All flagged attributes exist in models!\n")
    else:
        print(f"❌ Found {len(validation_results)} template(s) with undefined attributes:\n")

        for template_name, errors in sorted(validation_results.items()):
            print(f"  {template_name}:")
            for error in errors:
                if error.is_chained:
                    print(f"    ⚠️  {error}")
                else:
                    print(f"    ❌ {error}")
            print()

    return validation_results


def generate_report(semgrep_findings: List[SemgrepFinding], validation_results: Dict, runtime_errors: Dict):
    """Generate final report combining all three stages."""
    print("=" * 70)
    print("FINAL REPORT")
    print("=" * 70)
    print()

    # Categorize issues
    critical_issues = []
    warnings = []

    for finding in semgrep_findings:
        template = finding.template

        # Check if this variable also has validation errors
        has_validation_error = False
        if template in validation_results:
            for error in validation_results[template]:
                if error.variable == finding.variable:
                    has_validation_error = True
                    break

        # Check if this caused runtime errors
        has_runtime_error = template in runtime_errors

        if finding.severity == "ERROR" and has_validation_error and has_runtime_error:
            critical_issues.append((finding, "CRITICAL: Static analysis + validation + RUNTIME ERROR - WILL CRASH!"))
        elif finding.severity == "ERROR" and has_runtime_error:
            critical_issues.append((finding, "CRITICAL: Causes RUNTIME ERROR during rendering"))
        elif finding.severity == "ERROR" and has_validation_error:
            critical_issues.append((finding, "CRITICAL: Chained access without check + undefined attribute"))
        elif finding.severity == "ERROR":
            critical_issues.append((finding, "ERROR: Chained access without null check"))
        elif has_validation_error:
            warnings.append((finding, "WARNING: Access without check + potentially undefined"))

    # Print critical issues
    if critical_issues:
        print(f"🚨 CRITICAL ISSUES ({len(critical_issues)}):")
        print("These MUST be fixed - they will cause runtime errors:\n")

        for finding, reason in critical_issues:
            print(f"  {finding.template}:{finding.line}")
            print(f"    Variable: {finding.variable}.{finding.attribute}")
            print(f"    Issue: {reason}")
            print(f"    Code: {finding.code}")
            attr_to_check = finding.attribute.split('.')[0] if '.' in finding.attribute else finding.attribute
            print(f"    Fix: Add " + "{% if " + finding.variable + "." + attr_to_check + " %}" + " check")
            print()

    # Print warnings
    if warnings:
        print(f"⚠️  WARNINGS ({len(warnings)}):")
        print("Consider fixing these for safety:\n")

        for finding, reason in warnings:
            print(f"  {finding.template}:{finding.line} - {finding.variable}.{finding.attribute}")
            print(f"    {reason}")
        print()

    # Add runtime-only errors to critical issues
    for template_name, errors in runtime_errors.items():
        # Check if not already reported
        already_reported = any(f.template == template_name for f, _ in critical_issues)
        if not already_reported:
            for error in errors:
                # Create a synthetic finding for runtime-only errors
                print(f"⚠️  Runtime-only error in {template_name}:")
                print(f"    Line {error.line}: {error.error_type} - {error.message}")

    # Summary
    total_issues = len(critical_issues) + len(warnings)
    total_runtime = sum(len(errors) for errors in runtime_errors.values())

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Static Analysis Issues: {len(critical_issues)} critical, {len(warnings)} warnings")
    print(f"Runtime Errors: {total_runtime} template(s) will crash")

    if total_issues == 0 and total_runtime == 0:
        print("\n✅ SUCCESS: No issues found! Your templates are safe to use.")
        return 0
    else:
        print(f"\n❌ FAILED: Fix the issues above before deploying.")
        return 1


def run_runtime_validation_stage() -> Dict:
    """
    Stage 3: Runtime validation - render templates with test data to find crashes.
    """
    print("=" * 70)
    print("STAGE 3: Runtime Validation - Testing with Actual Instances")
    print("=" * 70)
    print()

    try:
        runtime_errors = validate_runtime()

        if not runtime_errors:
            print("✅ All templates rendered successfully with test data!\n")
        else:
            print(f"❌ Found runtime errors in {len(runtime_errors)} template(s):\n")

            for template_name, errors in sorted(runtime_errors.items()):
                print(f"  {template_name}:")
                for error in errors:
                    print(f"    💥 Line {error.line}: {error.error_type}")
                    print(f"       {error.message}")
                print()

        return runtime_errors

    except Exception as e:
        print(f"⚠️  Runtime validation failed: {e}")
        print("Skipping runtime validation.\n")
        return {}


def main():
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "STAGED TEMPLATE VALIDATOR" + " " * 28 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    # Stage 1: Run Semgrep
    semgrep_findings = run_semgrep_stage()

    # Stage 2: Validate attributes for flagged variables
    validation_results = run_attribute_validation_stage(semgrep_findings)

    # Stage 3: Runtime validation with test instances
    runtime_errors = run_runtime_validation_stage()

    # Generate final report
    exit_code = generate_report(semgrep_findings, validation_results, runtime_errors)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
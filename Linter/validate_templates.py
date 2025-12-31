#!/usr/bin/env python3
"""
Jinja2 Template Validation Script
Validates all .jinja templates in the templates/ directory using j2lint
and custom attribute validation against models.py.

Usage:
    python validate_templates.py --mode all          # Run both validations (default)
    python validate_templates.py --mode j2lint       # Run only j2lint validation
    python validate_templates.py --mode attributes   # Run only attribute validation
"""

import sys
import subprocess
import argparse
from pathlib import Path
from attribute_validator import validate_all_templates


def find_jinja_templates(templates_dir: str = "templates") -> list:
    """Find all .jinja files in the templates directory."""
    template_path = Path(templates_dir)
    if not template_path.exists():
        print(f"Error: Templates directory '{templates_dir}' not found.")
        return []

    templates = list(template_path.glob("*.jinja"))
    return sorted(templates)


def validate_template(template_file: Path) -> tuple[bool, str]:
    """
    Validate a single template using j2lint.
    Returns (is_valid, output_message).
    """
    try:
        result = subprocess.run(
            ["j2lint", str(template_file)],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return True, "✓ Valid"
        else:
            return False, result.stdout + result.stderr

    except FileNotFoundError:
        return False, "Error: j2lint not found. Install with: pip install j2lint"
    except subprocess.TimeoutExpired:
        return False, "Error: Validation timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"


def run_j2lint_validation() -> bool:
    """
    Run j2lint validation on all templates.
    Returns True if all templates are valid, False otherwise.
    """
    print("=" * 60)
    print("j2lint Syntax & Style Validation")
    print("=" * 60)
    print()

    templates = find_jinja_templates()

    if not templates:
        print("No .jinja templates found in templates/ directory.")
        return False

    print(f"Found {len(templates)} template(s) to validate:\n")

    results = []
    all_valid = True

    for template in templates:
        print(f"Validating: {template.name}...", end=" ")
        is_valid, message = validate_template(template)
        results.append((template.name, is_valid, message))

        if is_valid:
            print(message)
        else:
            print("✗ Failed")
            all_valid = False

    print("\n" + "=" * 60)
    print("j2lint Results")
    print("=" * 60)

    for name, is_valid, message in results:
        if not is_valid:
            print(f"\n{name}:")
            print(message)

    if all_valid:
        print("\n✓ All templates passed j2lint validation!")
    else:
        print(f"\n✗ {sum(1 for _, valid, _ in results if not valid)} template(s) failed j2lint validation.")

    return all_valid


def run_attribute_validation() -> bool:
    """
    Run custom attribute validation against models.py.
    Returns True if all attributes are valid, False otherwise.
    """
    print("=" * 60)
    print("Custom Attribute Validation (against models.py)")
    print("=" * 60)
    print()

    try:
        attribute_errors = validate_all_templates()

        if not attribute_errors:
            print("✓ All template attributes are valid!")
            return True
        else:
            print(f"✗ Found undefined attributes in {len(attribute_errors)} template(s):\n")

            for template_name, errors in sorted(attribute_errors.items()):
                print(f"{template_name}:")
                for error in errors:
                    print(f"  ✗ {error}")
                print()

            return False

    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Attribute validation failed.")
        return False
    except Exception as e:
        print(f"Error during attribute validation: {e}")
        return False


def main():
    """Main validation function."""
    parser = argparse.ArgumentParser(
        description="Validate Jinja2 templates using j2lint and/or custom attribute validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_templates.py                    # Run both validations (default)
  python validate_templates.py --mode all         # Run both validations
  python validate_templates.py --mode j2lint      # Run only j2lint validation
  python validate_templates.py --mode attributes  # Run only attribute validation
        """
    )

    parser.add_argument(
        "--mode",
        choices=["all", "j2lint", "attributes"],
        default="all",
        help="Validation mode: 'all' (both), 'j2lint' (syntax/style only), or 'attributes' (model validation only)"
    )

    args = parser.parse_args()

    # Track overall validation status
    all_valid = True

    # Run validations based on mode
    if args.mode in ["all", "j2lint"]:
        j2lint_valid = run_j2lint_validation()
        all_valid = all_valid and j2lint_valid
        if args.mode == "all":
            print()  # Add spacing between validations

    if args.mode in ["all", "attributes"]:
        attribute_valid = run_attribute_validation()
        all_valid = all_valid and attribute_valid

    # Final summary
    if args.mode == "all":
        print("\n" + "=" * 60)
        print("Overall Validation Summary")
        print("=" * 60)

    if all_valid:
        print("\n✓ All validations passed!")
        sys.exit(0)
    else:
        print("\n✗ Some validations failed. See details above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
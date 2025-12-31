#!/usr/bin/env python3
"""
Use jinja2schema to analyze template variable usage
"""

from pathlib import Path
from jinja2schema import infer, to_json_schema
import json


def analyze_template(template_file: Path):
    """Analyze a template using jinja2schema."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {template_file.name}")
    print('='*60)

    with open(template_file, 'r') as f:
        template_content = f.read()

    try:
        # Infer the schema from the template
        schema = infer(template_content)

        print("\nInferred Schema:")
        print(json.dumps(to_json_schema(schema), indent=2))

    except Exception as e:
        print(f"Error analyzing template: {e}")


def main():
    templates_dir = Path("templates")

    if not templates_dir.exists():
        print("templates/ directory not found")
        return

    print("jinja2schema Template Analysis")
    print("="*60)

    for template_file in sorted(templates_dir.glob("*.jinja")):
        analyze_template(template_file)


if __name__ == "__main__":
    main()
"""
Template Parser - Extract variable attribute access from Jinja2 templates
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from jinja2 import Environment, meta


def extract_attribute_access(template_content: str) -> Dict[str, Set[str]]:
    """
    Extract variable attribute access patterns from Jinja2 template.
    Now supports chained attribute access (e.g., post.published.lint).

    Returns:
        Dict mapping variable names to their accessed attributes (including chains)
        Example: {'user': {'username', 'email'}, 'post': {'title', 'published.lint'}}
    """
    env = Environment()

    try:
        ast = env.parse(template_content)
    except Exception as e:
        print(f"Error parsing template: {e}")
        return {}

    # Get all undeclared variables (those used but not defined in template)
    undeclared = meta.find_undeclared_variables(ast)

    access_map: Dict[str, Set[str]] = {}

    # Pattern to match full attribute chains: variable.attr1.attr2.attr3...
    # Captures variable name and the full attribute chain
    # Matches: {{ var.attr }}, {{ var.attr.nested }}, {{ var.attr.deeply.nested }}
    chain_pattern = r'\{\{[\s]*([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_.]+?)[\s]*(?:\||}})'

    for match in re.finditer(chain_pattern, template_content):
        var_name = match.group(1)
        attr_chain = match.group(2)  # Full chain like "published.lint" or just "username"

        if var_name not in access_map:
            access_map[var_name] = set()
        access_map[var_name].add(attr_chain)

    # Also check in {% %} blocks (for loops, if statements)
    # Pattern for control structures
    block_pattern = r'\{%[^%]*?([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_.]+?)[\s]*(?:[%}]|\s)'

    for match in re.finditer(block_pattern, template_content):
        var_name = match.group(1)
        attr_chain = match.group(2)

        if var_name not in access_map:
            access_map[var_name] = set()
        access_map[var_name].add(attr_chain)

    return access_map


def parse_template(template_file: Path) -> Dict[str, Set[str]]:
    """
    Parse a Jinja2 template file and extract attribute access patterns.

    Returns:
        Dict mapping variable names to their accessed attributes
    """
    if not template_file.exists():
        raise FileNotFoundError(f"Template file not found: {template_file}")

    with open(template_file, 'r') as f:
        content = f.read()

    return extract_attribute_access(content)


if __name__ == "__main__":
    # Test the parser on all templates
    templates_dir = Path("templates")

    if not templates_dir.exists():
        print("templates/ directory not found")
        exit(1)

    print("Template Attribute Access Analysis:")
    print("=" * 60)

    for template_file in sorted(templates_dir.glob("*.jinja")):
        print(f"\n{template_file.name}:")
        access_map = parse_template(template_file)

        for var_name, attributes in sorted(access_map.items()):
            print(f"  {var_name}:")
            for attr in sorted(attributes):
                print(f"    - {attr}")
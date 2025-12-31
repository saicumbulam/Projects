#!/usr/bin/env python3
"""
Runtime Validator - Create model instances and render templates to detect runtime errors
"""

from pathlib import Path
from typing import Dict, List, Tuple
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError
import traceback
import sys
import importlib.util


class RuntimeError:
    """Represents a runtime error found during template rendering."""

    def __init__(self, template: str, line: int, error_type: str, message: str, variable_access: str):
        self.template = template
        self.line = line
        self.error_type = error_type
        self.message = message
        self.variable_access = variable_access

    def __str__(self):
        return f"{self.template}:{self.line} - {self.error_type}: {self.message}"

    def __repr__(self):
        return str(self)


def load_models_module(models_file: str = "models.py"):
    """Dynamically load the models.py module."""
    spec = importlib.util.spec_from_file_location("models", models_file)
    models = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(models)
    return models


def create_test_instances(models):
    """
    Create test instances of model classes with various edge cases.
    Returns dict of template name -> context data.
    """
    test_data = {}

    # User template - test with None posts
    try:
        user = models.User(
            user_id=1,
            username="testuser",
            email="test@example.com",
            created_at="2024-01-01"
        )
        user.posts = []  # Empty list to test iteration
        test_data['user.jinja'] = {'user': user}
    except Exception as e:
        print(f"Warning: Could not create User instance: {e}")

    # Post template - test with None author and None published
    try:
        post = models.Post(
            post_id=1,
            title="Test Post",
            content="Content here",
            author=None,  # This will cause errors if accessed
            created_at="2024-01-01",
            published=None  # This will cause errors if .lint is accessed
        )
        post.tags = None  # Test None instead of empty list
        test_data['post.jinja'] = {'post': post}
    except Exception as e:
        print(f"Warning: Could not create Post instance: {e}")

    # Product template
    try:
        product = models.Product(
            product_id=1,
            name="Test Product",
            description="Description",
            category="Electronics",
            price=99.99,
            stock=10,
            rating=4.5
        )
        test_data['product.jinja'] = {'product': product}
    except Exception as e:
        print(f"Warning: Could not create Product instance: {e}")

    # Company template - test with empty employees
    try:
        company = models.Company(
            name="Test Company",
            industry="Tech",
            founded_year=2020
        )
        company.employees = []  # Empty list to test indexing
        test_data['company.jinja'] = {'company': company}
    except Exception as e:
        print(f"Warning: Could not create Company instance: {e}")

    # Employee template - test with None company
    try:
        employee = models.Employee(
            employee_id=1,
            name="Test Employee",
            department="Engineering",
            salary=75000.00,
            hire_date="2023-01-01",
            company=None  # This will cause errors if company.name is accessed
        )
        test_data['employee.jinja'] = {'employee': employee}
    except Exception as e:
        print(f"Warning: Could not create Employee instance: {e}")

    return test_data


def render_template_safely(env: Environment, template_name: str, context: Dict) -> Tuple[bool, List[RuntimeError]]:
    """
    Attempt to render a template and catch any runtime errors.
    Returns (success, list of errors).
    """
    errors = []

    try:
        template = env.get_template(template_name)

        # Try to render - this will raise errors for undefined access
        try:
            rendered = template.render(**context)
            return True, []
        except Exception as e:
            # Extract line number from traceback
            tb = traceback.extract_tb(sys.exc_info()[2])

            # Find the line in the template (not in our code)
            template_line = None
            for frame in tb:
                if template_name in frame.filename:
                    template_line = frame.lineno
                    break

            # Determine error type and extract variable access
            error_type = type(e).__name__
            error_msg = str(e)

            # Try to extract what variable was being accessed
            variable_access = "unknown"
            if "NoneType" in error_msg and "attribute" in error_msg:
                # AttributeError on None
                import re
                match = re.search(r"'(\w+)'", error_msg)
                if match:
                    variable_access = match.group(1)
            elif "list index out of range" in error_msg:
                variable_access = "list indexing"
            elif "KeyError" in error_type:
                variable_access = error_msg

            errors.append(RuntimeError(
                template=template_name,
                line=template_line or 0,
                error_type=error_type,
                message=error_msg,
                variable_access=variable_access
            ))

            return False, errors

    except TemplateError as e:
        errors.append(RuntimeError(
            template=template_name,
            line=e.lineno or 0,
            error_type="TemplateError",
            message=str(e),
            variable_access="template syntax"
        ))
        return False, errors


def validate_runtime(templates_dir: str = "templates", models_file: str = "models.py") -> Dict[str, List[RuntimeError]]:
    """
    Create test instances and render templates to find runtime errors.

    Returns:
        Dict mapping template names to their runtime errors
    """
    # Load models module
    try:
        models = load_models_module(models_file)
    except Exception as e:
        print(f"Error loading models: {e}")
        return {}

    # Create test instances
    test_data = create_test_instances(models)

    # Set up Jinja2 environment with StrictUndefined
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        undefined=StrictUndefined  # This makes undefined access raise errors
    )

    # Validate each template
    all_errors = {}

    for template_name, context in test_data.items():
        success, errors = render_template_safely(env, template_name, context)

        if errors:
            all_errors[template_name] = errors

    return all_errors


if __name__ == "__main__":
    print("Runtime Template Validation")
    print("=" * 70)
    print()

    errors = validate_runtime()

    if not errors:
        print("✅ All templates rendered successfully with test data!")
    else:
        print(f"❌ Found runtime errors in {len(errors)} template(s):\n")

        for template_name, template_errors in sorted(errors.items()):
            print(f"{template_name}:")
            for error in template_errors:
                print(f"  Line {error.line}: {error.error_type}")
                print(f"    {error.message}")
            print()

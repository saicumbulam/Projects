"""
Attribute Validator - Validate that template attributes exist in models
"""

from pathlib import Path
from typing import Dict, Set, List, Tuple
from model_parser import parse_models
from template_parser import parse_template


class ValidationError:
    """Represents a validation error for an undefined attribute."""

    def __init__(self, template_file: str, variable: str, attribute: str, model_class: str = None, is_chained: bool = False):
        self.template_file = template_file
        self.variable = variable
        self.attribute = attribute
        self.model_class = model_class
        self.is_chained = is_chained

    def __str__(self):
        if self.model_class:
            if self.is_chained:
                return (f"{self.template_file}: "
                       f"Cannot fully validate chained attribute '{self.variable}.{self.attribute}' "
                       f"('{self.attribute}' not found as direct attribute in {self.model_class} model - may be valid if intermediate attributes return correct types)")
            else:
                return (f"{self.template_file}: "
                       f"Undefined attribute '{self.variable}.{self.attribute}' "
                       f"('{self.attribute}' not found in {self.model_class} model)")
        else:
            return (f"{self.template_file}: "
                   f"Cannot validate '{self.variable}.{self.attribute}' "
                   f"(no model mapping for variable '{self.variable}')")

    def __repr__(self):
        return str(self)


def infer_model_from_variable(variable_name: str, models: Dict[str, Set[str]]) -> str:
    """
    Infer the model class from variable name.
    Example: 'user' -> 'User', 'employee' -> 'Employee'
    """
    # Try exact match with capitalized name
    capitalized = variable_name.capitalize()
    if capitalized in models:
        return capitalized

    # Try common patterns
    if variable_name.endswith('s'):
        # Handle plurals: 'users' -> 'User', 'employees' -> 'Employee'
        singular = variable_name[:-1].capitalize()
        if singular in models:
            return singular

    return None


def validate_template_attributes(
    template_file: Path,
    models: Dict[str, Set[str]],
    variable_to_model: Dict[str, str] = None
) -> List[ValidationError]:
    """
    Validate that all attributes accessed in a template exist in their corresponding models.

    Args:
        template_file: Path to the Jinja2 template file
        models: Dict mapping model class names to their attributes
        variable_to_model: Optional explicit mapping of template variables to model classes
                          Example: {'user': 'User', 'post': 'Post'}

    Returns:
        List of ValidationError objects for undefined attributes
    """
    errors = []

    # Parse template to get attribute access
    access_map = parse_template(template_file)

    for variable, attributes in access_map.items():
        # Determine which model class this variable represents
        if variable_to_model and variable in variable_to_model:
            model_class = variable_to_model[variable]
        else:
            model_class = infer_model_from_variable(variable, models)

        if not model_class:
            # Can't determine model class, report as warning
            for attr in attributes:
                errors.append(ValidationError(
                    template_file.name,
                    variable,
                    attr,
                    None
                ))
            continue

        # Check if model class exists
        if model_class not in models:
            for attr in attributes:
                errors.append(ValidationError(
                    template_file.name,
                    variable,
                    attr,
                    model_class
                ))
            continue

        # Validate each attribute (including chained attributes)
        model_attributes = models[model_class]
        for attr in attributes:
            # Check if this is a chained attribute access (e.g., "published.lint")
            if '.' in attr:
                # Split the chain and validate each level
                attr_parts = attr.split('.')
                first_attr = attr_parts[0]

                # Validate the first attribute exists in the model
                if first_attr not in model_attributes:
                    errors.append(ValidationError(
                        template_file.name,
                        variable,
                        first_attr,
                        model_class
                    ))
                else:
                    # Report chained access as potential issue since we can't validate deeper levels without type info
                    # Mark it as a chained access so the error message is more informative
                    errors.append(ValidationError(
                        template_file.name,
                        variable,
                        attr,  # Full chain like "published.lint"
                        model_class,
                        is_chained=True
                    ))
            else:
                # Simple attribute access
                if attr not in model_attributes:
                    errors.append(ValidationError(
                        template_file.name,
                        variable,
                        attr,
                        model_class
                    ))

    return errors


def validate_all_templates(
    templates_dir: str = "templates",
    models_file: str = "models.py",
    variable_mappings: Dict[str, Dict[str, str]] = None
) -> Dict[str, List[ValidationError]]:
    """
    Validate all templates in a directory.

    Args:
        templates_dir: Directory containing Jinja2 templates
        models_file: Path to models.py file
        variable_mappings: Optional dict mapping template filenames to variable->model mappings
                          Example: {'user.jinja': {'user': 'User', 'post': 'Post'}}

    Returns:
        Dict mapping template filenames to their validation errors
    """
    templates_path = Path(templates_dir)
    if not templates_path.exists():
        raise FileNotFoundError(f"Templates directory not found: {templates_dir}")

    # Parse models
    models = parse_models(models_file)

    # Validate each template
    all_errors = {}

    for template_file in sorted(templates_path.glob("*.jinja")):
        var_mapping = None
        if variable_mappings and template_file.name in variable_mappings:
            var_mapping = variable_mappings[template_file.name]

        errors = validate_template_attributes(template_file, models, var_mapping)
        if errors:
            all_errors[template_file.name] = errors

    return all_errors


if __name__ == "__main__":
    print("Validating Template Attributes Against Models")
    print("=" * 60)

    # Run validation
    all_errors = validate_all_templates()

    if not all_errors:
        print("\n✓ All templates are valid! No undefined attributes found.")
    else:
        print(f"\n✗ Found undefined attributes in {len(all_errors)} template(s):\n")

        for template_name, errors in sorted(all_errors.items()):
            print(f"{template_name}:")
            for error in errors:
                print(f"  ✗ {error}")
            print()
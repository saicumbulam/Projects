"""
Model Parser - Extract attributes from Python model classes
"""

import ast
from pathlib import Path
from typing import Dict, Set


class ModelAttributeExtractor(ast.NodeVisitor):
    """Extract attributes from Python model classes."""

    def __init__(self):
        self.models: Dict[str, Set[str]] = {}
        self.current_class = None

    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definitions and extract their attributes."""
        self.current_class = node.name
        self.models[node.name] = set()

        # Extract attributes from __init__ method
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == '__init__':
                for stmt in item.body:
                    # Regular assignments: self.attr = value
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                                if target.value.id == 'self':
                                    self.models[node.name].add(target.attr)
                    # Annotated assignments: self.attr: Type = value
                    elif isinstance(stmt, ast.AnnAssign):
                        if isinstance(stmt.target, ast.Attribute) and isinstance(stmt.target.value, ast.Name):
                            if stmt.target.value.id == 'self':
                                self.models[node.name].add(stmt.target.attr)

        # Extract dataclass fields and properties
        for item in node.body:
            # Dataclass fields (annotated assignments)
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                self.models[node.name].add(item.target.id)

            # Properties
            if isinstance(item, ast.FunctionDef):
                for decorator in item.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id == 'property':
                        self.models[node.name].add(item.name)
                # Regular methods (user might call them)
                if not item.name.startswith('_'):
                    self.models[node.name].add(item.name)

        self.generic_visit(node)
        self.current_class = None


def parse_models(models_file: str = "models.py") -> Dict[str, Set[str]]:
    """
    Parse models.py and extract all attributes for each model class.

    Returns:
        Dict mapping class names to their available attributes
    """
    models_path = Path(models_file)
    if not models_path.exists():
        raise FileNotFoundError(f"Models file not found: {models_file}")

    with open(models_path, 'r') as f:
        tree = ast.parse(f.read())

    extractor = ModelAttributeExtractor()
    extractor.visit(tree)

    return extractor.models


if __name__ == "__main__":
    # Test the parser
    models = parse_models()
    print("Extracted Model Attributes:")
    print("=" * 60)
    for model_name, attributes in sorted(models.items()):
        print(f"\n{model_name}:")
        for attr in sorted(attributes):
            print(f"  - {attr}")
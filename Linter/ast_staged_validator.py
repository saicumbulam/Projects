#!/usr/bin/env python3
"""
AST Staged Validator - Two-stage Jinja2 template security analysis.

Stage 1: Semgrep Scan
    - Runs semgrep with Jinja2 security rules to identify problematic patterns
    - Extracts variable names and access patterns from findings

Stage 2: AST Analysis
    - Parses Jinja2 templates into AST
    - Checks if variables flagged by semgrep are properly guarded
    - Provides detailed guard status for each finding

This validator provides:
1. Integration with semgrep for initial pattern detection
2. Full AST parsing of Jinja2 templates
3. A hashmap mapping each AST node to its parent node
4. Detailed analysis of whether flagged variables are guarded or unguarded
"""

import sys
import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from jinja2 import Environment, nodes


# ============================================================================
# SEMGREP INTEGRATION
# ============================================================================

@dataclass
class SemgrepFinding:
    """Represents a finding from semgrep scan."""
    rule_id: str
    message: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    column_start: int
    column_end: int
    matched_code: str
    # Extracted variable information
    variables: List[str] = field(default_factory=list)
    full_expression: str = ""

    def __repr__(self):
        return f"SemgrepFinding({self.rule_id}, line={self.line_start}, vars={self.variables})"


def run_semgrep(template_path: Path, rules_path: Optional[Path] = None) -> List[SemgrepFinding]:
    """
    Run semgrep on a template file and return parsed findings.

    Args:
        template_path: Path to the Jinja2 template file
        rules_path: Path to semgrep rules file (defaults to .semgrep/jinja2-comprehensive.yaml)

    Returns:
        List of SemgrepFinding objects
    """
    if rules_path is None:
        # Default to the comprehensive rules file
        rules_path = template_path.parent.parent / ".semgrep" / "jinja2-comprehensive.yaml"
        if not rules_path.exists():
            rules_path = template_path.parent / ".semgrep" / "jinja2-comprehensive.yaml"

    if not rules_path.exists():
        print(f"Warning: Semgrep rules not found at {rules_path}")
        return []

    # Read the template content for extracting matched code
    template_content = ""
    try:
        with open(template_path, 'r') as f:
            template_content = f.read()
    except Exception as e:
        print(f"Warning: Could not read template file: {e}")

    try:
        # Run semgrep with JSON output
        result = subprocess.run(
            [
                "semgrep",
                "--config", str(rules_path),
                "--json",
                "--no-git-ignore",
                str(template_path)
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        # Parse JSON output
        if result.stdout:
            data = json.loads(result.stdout)
            return _parse_semgrep_output(data, template_content)

        return []

    except subprocess.TimeoutExpired:
        print("Error: Semgrep timed out")
        return []
    except FileNotFoundError:
        print("Error: Semgrep not found. Please install semgrep: pip install semgrep")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing semgrep output: {e}")
        return []
    except Exception as e:
        print(f"Error running semgrep: {e}")
        return []


def _parse_semgrep_output(data: Dict, template_content: str = "") -> List[SemgrepFinding]:
    """Parse semgrep JSON output into SemgrepFinding objects."""
    findings = []

    results = data.get("results", [])
    for result in results:
        # Get the matched code - prefer extracting from template if "lines" is not available
        matched_code = result.get("extra", {}).get("lines", "").strip()

        # If matched_code is empty or shows "requires login", extract from template using offsets
        if not matched_code or matched_code == "requires login":
            if template_content:
                start_offset = result.get("start", {}).get("offset", 0)
                end_offset = result.get("end", {}).get("offset", 0)
                if start_offset < len(template_content) and end_offset <= len(template_content):
                    matched_code = template_content[start_offset:end_offset]

        # Also try to extract variables from the message (e.g., "'post.post_id'")
        message = result.get("extra", {}).get("message", "")

        finding = SemgrepFinding(
            rule_id=result.get("check_id", "unknown"),
            message=message,
            severity=result.get("extra", {}).get("severity", "INFO"),
            file_path=result.get("path", ""),
            line_start=result.get("start", {}).get("line", 0),
            line_end=result.get("end", {}).get("line", 0),
            column_start=result.get("start", {}).get("col", 0),
            column_end=result.get("end", {}).get("col", 0),
            matched_code=matched_code
        )

        # Extract variables from the matched code
        finding.variables = _extract_variables_from_code(finding.matched_code)

        # If no variables found, try to extract from message
        if not finding.variables:
            finding.variables = _extract_variables_from_message(message)

        finding.full_expression = _extract_jinja_expression(finding.matched_code)

        findings.append(finding)

    return findings


def _extract_variables_from_message(message: str) -> List[str]:
    """
    Extract variable names from semgrep message.
    Messages often contain patterns like 'post.author' or '$VAR.$ATTR'.
    """
    variables = []

    # Find quoted variable names in the message
    quoted_vars = re.findall(r"'([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'", message)

    for var in quoted_vars:
        # Build access chain for each variable
        chain = _build_access_chain(var)
        variables.extend(chain)

    # Remove duplicates while preserving order
    seen = set()
    unique_vars = []
    for var in variables:
        if var not in seen:
            seen.add(var)
            unique_vars.append(var)

    return unique_vars


def _extract_variables_from_code(code: str) -> List[str]:
    """
    Extract variable names and access chains from Jinja2 code.

    Examples:
        "{{ post.author.username }}" -> ["post", "post.author", "post.author.username"]
        "{{ items[0].name }}" -> ["items", "items[0]", "items[0].name"]
    """
    variables = []

    # Match Jinja2 expressions: {{ ... }}
    expr_pattern = r'\{\{\s*([^}|]+?)(?:\s*\||s*\}\})'
    matches = re.findall(expr_pattern, code)

    for match in matches:
        # Clean up the expression
        expr = match.strip()

        # Build the access chain
        chain = _build_access_chain(expr)
        variables.extend(chain)

    # Remove duplicates while preserving order
    seen = set()
    unique_vars = []
    for var in variables:
        if var not in seen:
            seen.add(var)
            unique_vars.append(var)

    return unique_vars


def _build_access_chain(expression: str) -> List[str]:
    """
    Build access chain from an expression.

    Example: "post.author.username" -> ["post", "post.author", "post.author.username"]
    """
    chain = []

    # Pattern to match variable access: word.word.word or word[index].word
    parts_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)|\[([^\]]+)\]'
    parts = re.findall(parts_pattern, expression)

    current = ""
    for word, index in parts:
        if word:
            if current:
                current += "." + word
            else:
                current = word
            chain.append(current)
        elif index:
            current += f"[{index}]"
            chain.append(current)

    return chain


def _extract_jinja_expression(code: str) -> str:
    """Extract the full Jinja2 expression from code."""
    # Match {{ ... }}
    match = re.search(r'\{\{([^}]+)\}\}', code)
    if match:
        return "{{" + match.group(1) + "}}"
    return code


@dataclass
class SemgrepFindingAnalysis:
    """Analysis result for a semgrep finding after AST validation."""
    finding: SemgrepFinding
    is_guarded: bool
    guard_type: Optional[str]  # "conditional", "loop_variable", "defined_check", etc.
    guard_expression: Optional[str]  # The actual guard condition
    unguarded_variables: List[str]
    guarded_variables: List[str]
    ast_safety_analysis: Optional[Dict[str, Any]] = None

    def __repr__(self):
        status = "GUARDED" if self.is_guarded else "UNGUARDED"
        return f"SemgrepFindingAnalysis({self.finding.rule_id}, {status}, line={self.finding.line_start})"


# ============================================================================
# AST NODE CLASSES
# ============================================================================

@dataclass
class ASTNode:
    """Represents an AST node with metadata."""
    node: nodes.Node
    node_type: str
    line_number: Optional[int]
    code_repr: str
    parent: Optional['ASTNode'] = None
    children: List['ASTNode'] = field(default_factory=list)

    def __hash__(self):
        return id(self.node)

    def __eq__(self, other):
        if isinstance(other, ASTNode):
            return id(self.node) == id(other.node)
        return False

    def __repr__(self):
        parent_type = self.parent.node_type if self.parent else "None"
        return f"ASTNode({self.node_type}, line={self.line_number}, parent={parent_type})"


class JinjaASTParser:
    """
    Parses Jinja2 templates into AST and builds parent-child relationships.

    The hashmap structure maps each node to its parent, allowing for:
    - Bottom-up traversal (child to parent)
    - Understanding context of each code element
    - Scope analysis (what's inside loops, conditionals, etc.)
    """

    def __init__(self, template_content: str, template_name: str = "template"):
        self.template_content = template_content
        self.template_name = template_name
        self.env = Environment()

        # Core data structures
        self.parent_map: Dict[ASTNode, ASTNode] = {}  # child -> parent mapping
        self.children_map: Dict[ASTNode, List[ASTNode]] = defaultdict(list)  # parent -> children
        self.all_nodes: List[ASTNode] = []
        self.nodes_by_type: Dict[str, List[ASTNode]] = defaultdict(list)
        self.nodes_by_line: Dict[int, List[ASTNode]] = defaultdict(list)

        # Root node
        self.root: Optional[ASTNode] = None

        # Parse the template
        self._parse()

    def _parse(self):
        """Parse the template and build the AST hashmap."""
        try:
            ast = self.env.parse(self.template_content)
            self.root = self._build_ast_node(ast, parent=None)
            self._walk_ast(ast, self.root)
        except Exception as e:
            print(f"Error parsing template {self.template_name}: {e}")

    def _get_node_code_repr(self, node: nodes.Node) -> str:
        """Get a string representation of the code this node represents."""
        node_type = type(node).__name__

        if isinstance(node, nodes.Name):
            return f"{{ {node.name} }}"
        elif isinstance(node, nodes.Getattr):
            return self._reconstruct_getattr(node)
        elif isinstance(node, nodes.Getitem):
            return self._reconstruct_getitem(node)
        elif isinstance(node, nodes.Output):
            return "{{ ... }}"
        elif isinstance(node, nodes.For):
            target = self._get_target_name(node.target)
            iter_name = self._get_iter_name(node.iter)
            return f"{{% for {target} in {iter_name} %}}"
        elif isinstance(node, nodes.If):
            test_repr = self._get_test_repr(node.test)
            return f"{{% if {test_repr} %}}"
        elif isinstance(node, nodes.TemplateData):
            # Truncate long template data
            data = node.data[:50] + "..." if len(node.data) > 50 else node.data
            return f"TemplateData({repr(data)})"
        elif isinstance(node, nodes.Const):
            return f"Const({repr(node.value)})"
        elif isinstance(node, nodes.Filter):
            return f"Filter({node.name})"
        elif isinstance(node, nodes.Call):
            return "Call(...)"
        elif isinstance(node, nodes.Compare):
            return "Compare(...)"
        elif isinstance(node, nodes.Template):
            return f"Template({self.template_name})"
        else:
            return f"{node_type}()"

    def _reconstruct_getattr(self, node: nodes.Getattr) -> str:
        """Reconstruct the full attribute access chain."""
        parts = []
        current = node

        while isinstance(current, nodes.Getattr):
            parts.append(current.attr)
            current = current.node

        if isinstance(current, nodes.Name):
            parts.append(current.name)
        elif isinstance(current, nodes.Getitem):
            parts.append(self._reconstruct_getitem(current))

        parts.reverse()
        return "{{ " + ".".join(parts) + " }}"

    def _reconstruct_getitem(self, node: nodes.Getitem) -> str:
        """Reconstruct item access (e.g., list[0])."""
        if isinstance(node.node, nodes.Name):
            base = node.node.name
        elif isinstance(node.node, nodes.Getattr):
            base = self._reconstruct_getattr(node.node).strip("{ }")
        else:
            base = "?"

        if isinstance(node.arg, nodes.Const):
            index = repr(node.arg.value)
        else:
            index = "?"

        return f"{{ {base}[{index}] }}"

    def _get_target_name(self, node: nodes.Node) -> str:
        """Get the name of a for loop target."""
        if isinstance(node, nodes.Name):
            return node.name
        elif isinstance(node, nodes.Tuple):
            names = [self._get_target_name(item) for item in node.items]
            return ", ".join(names)
        return "?"

    def _get_iter_name(self, node: nodes.Node) -> str:
        """Get the name of a for loop iterable."""
        if isinstance(node, nodes.Name):
            return node.name
        elif isinstance(node, nodes.Getattr):
            return self._reconstruct_getattr(node).strip("{ }")
        return "?"

    def _get_test_repr(self, node: nodes.Node) -> str:
        """Get string representation of an if test."""
        if isinstance(node, nodes.Name):
            return node.name
        elif isinstance(node, nodes.Getattr):
            return self._reconstruct_getattr(node).strip("{ }")
        elif isinstance(node, nodes.Compare):
            return "comparison"
        return "test"

    def _build_ast_node(self, node: nodes.Node, parent: Optional[ASTNode]) -> ASTNode:
        """Build an ASTNode wrapper for a Jinja2 node."""
        ast_node = ASTNode(
            node=node,
            node_type=type(node).__name__,
            line_number=getattr(node, 'lineno', None),
            code_repr=self._get_node_code_repr(node),
            parent=parent
        )

        # Register in data structures
        self.all_nodes.append(ast_node)
        self.nodes_by_type[ast_node.node_type].append(ast_node)

        if ast_node.line_number:
            self.nodes_by_line[ast_node.line_number].append(ast_node)

        # Build parent mapping
        if parent is not None:
            self.parent_map[ast_node] = parent
            self.children_map[parent].append(ast_node)
            parent.children.append(ast_node)

        return ast_node

    def _walk_ast(self, node: nodes.Node, ast_node: ASTNode):
        """Recursively walk the AST and build the hashmap."""
        for child in node.iter_child_nodes():
            child_ast_node = self._build_ast_node(child, ast_node)
            self._walk_ast(child, child_ast_node)

    def get_parent(self, node: ASTNode) -> Optional[ASTNode]:
        """Get the parent of a node."""
        return self.parent_map.get(node)

    def get_children(self, node: ASTNode) -> List[ASTNode]:
        """Get the children of a node."""
        return self.children_map.get(node, [])

    def get_ancestors(self, node: ASTNode) -> List[ASTNode]:
        """Get all ancestors of a node (parent, grandparent, etc.)."""
        ancestors = []
        current = self.get_parent(node)
        while current is not None:
            ancestors.append(current)
            current = self.get_parent(current)
        return ancestors

    def get_nodes_by_type(self, node_type: str) -> List[ASTNode]:
        """Get all nodes of a specific type."""
        return self.nodes_by_type.get(node_type, [])

    def get_nodes_at_line(self, line_number: int) -> List[ASTNode]:
        """Get all nodes at a specific line."""
        return self.nodes_by_line.get(line_number, [])

    def find_scope(self, node: ASTNode) -> Optional[ASTNode]:
        """
        Find the scope (For, If, Block, etc.) that contains this node.
        Returns the nearest scope-defining ancestor.
        """
        scope_types = {'For', 'If', 'Block', 'Macro', 'CallBlock'}
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type in scope_types:
                return ancestor
        return None

    def is_inside_loop(self, node: ASTNode) -> bool:
        """Check if a node is inside a for loop."""
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type == 'For':
                return True
        return False

    def is_inside_conditional(self, node: ASTNode) -> bool:
        """Check if a node is inside an if block."""
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type == 'If':
                return True
        return False

    def get_containing_conditionals(self, node: ASTNode) -> List[ASTNode]:
        """Get all If nodes that contain this node (from innermost to outermost)."""
        conditionals = []
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type == 'If':
                conditionals.append(ancestor)
        return conditionals

    def get_containing_loops(self, node: ASTNode) -> List[ASTNode]:
        """Get all For nodes that contain this node (from innermost to outermost)."""
        loops = []
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type == 'For':
                loops.append(ancestor)
        return loops

    def get_condition_being_checked(self, if_node: ASTNode) -> Optional[str]:
        """Get the condition expression from an If node."""
        if if_node.node_type != 'If':
            return None
        # Extract from code_repr: "{% if condition %}" -> "condition"
        code = if_node.code_repr
        if code.startswith("{% if ") and code.endswith(" %}"):
            return code[6:-3]
        return code

    def get_node_context(self, node: ASTNode) -> Dict[str, Any]:
        """
        Get full context information for a node.

        Returns a dict with:
        - in_conditional: bool - whether node is inside any if block
        - in_loop: bool - whether node is inside any for loop
        - conditions: list of condition strings that guard this node
        - loops: list of loop expressions that contain this node
        - scope_chain: list of all scope-defining ancestors
        - is_guarded: bool - whether this access is protected by a condition
        """
        conditionals = self.get_containing_conditionals(node)
        loops = self.get_containing_loops(node)

        # Extract condition expressions
        conditions = []
        for cond_node in conditionals:
            cond_expr = self.get_condition_being_checked(cond_node)
            if cond_expr:
                conditions.append(cond_expr)

        # Extract loop expressions
        loop_exprs = []
        for loop_node in loops:
            loop_exprs.append(loop_node.code_repr)

        # Build scope chain
        scope_chain = []
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type in {'For', 'If', 'Block', 'Macro', 'CallBlock'}:
                scope_chain.append({
                    'type': ancestor.node_type,
                    'code': ancestor.code_repr,
                    'line': ancestor.line_number
                })

        # Check if the node's variable access is guarded by a condition
        is_guarded = False
        if node.node_type in ('Getattr', 'Getitem', 'Name'):
            # Check if any condition checks the same variable
            node_var = self._extract_base_variable(node)
            for cond in conditions:
                if node_var and node_var in cond:
                    is_guarded = True
                    break

        return {
            'in_conditional': len(conditionals) > 0,
            'in_loop': len(loops) > 0,
            'conditions': conditions,
            'loops': loop_exprs,
            'scope_chain': scope_chain,
            'is_guarded': is_guarded
        }

    def _extract_base_variable(self, node: ASTNode) -> Optional[str]:
        """Extract the base variable name from a node."""
        if node.node_type == 'Name':
            # Extract from "{ varname }"
            code = node.code_repr
            if code.startswith("{ ") and code.endswith(" }"):
                return code[2:-2]
        elif node.node_type in ('Getattr', 'Getitem'):
            # Extract base variable from "{{ var.attr }}"
            code = node.code_repr
            if code.startswith("{{ ") or code.startswith("{ "):
                # Find the first identifier
                import re
                match = re.match(r'\{+\s*([a-zA-Z_][a-zA-Z0-9_]*)', code)
                if match:
                    return match.group(1)
        return None

    def _extract_full_access_chain(self, node: ASTNode) -> List[str]:
        """
        Extract the full attribute/index access chain from a node.
        e.g., {{ post.author.username }} -> ['post', 'post.author', 'post.author.username']
        e.g., {{ items[0].name }} -> ['items', 'items[0]', 'items[0].name']
        """
        import re
        code = node.code_repr.strip("{ }")

        # Parse the chain
        chain = []
        # Match variable followed by .attr or [index] patterns
        pattern = r'^([a-zA-Z_][a-zA-Z0-9_]*)((?:\.[a-zA-Z_][a-zA-Z0-9_]*|\[[^\]]+\])*)'
        match = re.match(pattern, code)

        if match:
            base = match.group(1)
            chain.append(base)

            rest = match.group(2)
            if rest:
                # Split into individual accesses
                access_pattern = r'(\.[a-zA-Z_][a-zA-Z0-9_]*|\[[^\]]+\])'
                accesses = re.findall(access_pattern, rest)

                current = base
                for access in accesses:
                    current += access
                    chain.append(current)

        return chain

    def _parse_condition_expression(self, if_node: ASTNode) -> Dict[str, Any]:
        """
        Parse an If node's condition to extract detailed information.
        Returns dict with:
        - raw: the raw condition string
        - checked_vars: list of variables/attributes being checked
        - is_defined_check: bool if using 'is defined'
        - is_none_check: bool if checking for None
        - length_check: dict with var and operator if checking length
        - truthiness_check: list of vars being checked for truthiness
        """
        import re

        result = {
            'raw': '',
            'checked_vars': [],
            'is_defined_check': False,
            'is_none_check': False,
            'is_not_none_check': False,
            'length_check': None,
            'length_gt_zero': False,
            'truthiness_check': []
        }

        if if_node.node_type != 'If':
            return result

        # Get the actual Jinja2 If node to inspect the test
        jinja_node = if_node.node
        if not isinstance(jinja_node, nodes.If):
            return result

        test = jinja_node.test
        code = if_node.code_repr
        result['raw'] = code

        # Check for 'is defined' test
        if isinstance(test, nodes.Test):
            if test.name == 'defined':
                result['is_defined_check'] = True
                if isinstance(test.node, nodes.Name):
                    result['checked_vars'].append(test.node.name)
                elif isinstance(test.node, nodes.Getattr):
                    result['checked_vars'].append(self._reconstruct_getattr(test.node).strip("{ }"))

        # Check for 'is none' or 'is not none'
        if isinstance(test, nodes.Test):
            if test.name == 'none':
                result['is_none_check'] = True
                if isinstance(test.node, nodes.Name):
                    result['checked_vars'].append(test.node.name)
                elif isinstance(test.node, nodes.Getattr):
                    result['checked_vars'].append(self._reconstruct_getattr(test.node).strip("{ }"))

        # Check for negated none check (is not none)
        if isinstance(test, nodes.Not):
            inner = test.node
            if isinstance(inner, nodes.Test) and inner.name == 'none':
                result['is_not_none_check'] = True
                if isinstance(inner.node, nodes.Name):
                    result['checked_vars'].append(inner.node.name)
                elif isinstance(inner.node, nodes.Getattr):
                    result['checked_vars'].append(self._reconstruct_getattr(inner.node).strip("{ }"))

        # Check for comparison with length filter (e.g., list|length > 0)
        if isinstance(test, nodes.Compare):
            # Check left side for length filter
            expr = test.expr
            if isinstance(expr, nodes.Filter) and expr.name == 'length':
                filter_node = expr.node
                var_name = None
                if isinstance(filter_node, nodes.Name):
                    var_name = filter_node.name
                elif isinstance(filter_node, nodes.Getattr):
                    var_name = self._reconstruct_getattr(filter_node).strip("{ }")

                if var_name and test.ops:
                    op, comparator = test.ops[0]
                    op_name = type(op).__name__
                    if isinstance(comparator, nodes.Const):
                        value = comparator.value
                        result['length_check'] = {
                            'var': var_name,
                            'operator': op_name,
                            'value': value
                        }
                        # Check if this means length > 0
                        if (op_name == 'Gt' and value == 0) or \
                           (op_name == 'Ge' and value == 1) or \
                           (op_name == 'Ne' and value == 0):
                            result['length_gt_zero'] = True
                            result['checked_vars'].append(var_name)

        # Check for simple truthiness ({% if var %} or {% if var.attr %})
        if isinstance(test, nodes.Name):
            result['truthiness_check'].append(test.name)
            result['checked_vars'].append(test.name)
        elif isinstance(test, nodes.Getattr):
            var_chain = self._reconstruct_getattr(test).strip("{ }")
            result['truthiness_check'].append(var_chain)
            result['checked_vars'].append(var_chain)

        return result

    def get_loop_variables(self, node: ASTNode) -> Set[str]:
        """
        Get all loop variables that are in scope for this node.
        These are variables defined by {% for x in items %} that contain this node.
        """
        loop_vars = set()
        for ancestor in self.get_ancestors(node):
            if ancestor.node_type == 'For':
                jinja_node = ancestor.node
                if isinstance(jinja_node, nodes.For):
                    target = jinja_node.target
                    if isinstance(target, nodes.Name):
                        loop_vars.add(target.name)
                    elif isinstance(target, nodes.Tuple):
                        for item in target.items:
                            if isinstance(item, nodes.Name):
                                loop_vars.add(item.name)
        return loop_vars

    def analyze_access_safety(self, node: ASTNode) -> Dict[str, Any]:
        """
        Comprehensive safety analysis for a variable access.

        Returns dict with:
        - expression: the full expression being accessed
        - access_chain: list of all access levels (e.g., ['post', 'post.author', 'post.author.name'])
        - base_variable: the root variable name
        - is_index_access: bool if this involves array indexing
        - index_value: the index being accessed (if applicable)

        Safety checks:
        - is_defined_checked: bool if variable has 'is defined' check
        - is_none_checked: bool if variable has none check
        - is_truthy_checked: bool if variable has truthiness check
        - is_length_checked: bool if list length is checked before index access
        - is_loop_variable: bool if variable comes from a for loop
        - all_levels_guarded: bool if all access levels are protected
        - unguarded_levels: list of access levels that are not guarded
        - safety_issues: list of specific safety concerns
        - is_safe: bool overall safety assessment
        """
        import re

        result = {
            'expression': node.code_repr,
            'access_chain': [],
            'base_variable': None,
            'is_index_access': False,
            'index_value': None,

            # Safety checks
            'is_defined_checked': False,
            'is_none_checked': False,
            'is_truthy_checked': False,
            'is_length_checked': False,
            'is_loop_variable': False,
            'all_levels_guarded': False,
            'unguarded_levels': [],
            'guarded_levels': [],
            'safety_issues': [],
            'is_safe': False
        }

        # Extract access chain
        chain = self._extract_full_access_chain(node)
        result['access_chain'] = chain
        result['base_variable'] = chain[0] if chain else None

        # Check if this is an index access
        code = node.code_repr
        if '[' in code:
            result['is_index_access'] = True
            index_match = re.search(r'\[(\d+)\]', code)
            if index_match:
                result['index_value'] = int(index_match.group(1))

        # Get loop variables in scope
        loop_vars = self.get_loop_variables(node)
        if result['base_variable'] in loop_vars:
            result['is_loop_variable'] = True

        # Analyze all containing conditionals
        conditionals = self.get_containing_conditionals(node)
        all_checked_vars = set()
        has_defined_check = False
        has_none_check = False
        has_length_check = False
        length_checked_vars = set()

        for cond_node in conditionals:
            cond_info = self._parse_condition_expression(cond_node)

            if cond_info['is_defined_check']:
                has_defined_check = True
            if cond_info['is_not_none_check']:
                has_none_check = True
            if cond_info['length_gt_zero']:
                has_length_check = True
                if cond_info['length_check']:
                    length_checked_vars.add(cond_info['length_check']['var'])

            for var in cond_info['checked_vars']:
                all_checked_vars.add(var)
            for var in cond_info['truthiness_check']:
                all_checked_vars.add(var)

        result['is_defined_checked'] = has_defined_check
        result['is_none_checked'] = has_none_check
        result['is_length_checked'] = has_length_check

        # Expand all_checked_vars to include implicit parent guards
        # e.g., if 'company.employees' is checked, 'company' is implicitly guarded
        expanded_checked_vars = set(all_checked_vars)
        for checked_var in all_checked_vars:
            # Add all parent levels as implicitly guarded
            parts = checked_var.replace('[', '.').replace(']', '').split('.')
            current = ''
            for part in parts:
                if current:
                    current += '.' + part
                else:
                    current = part
                expanded_checked_vars.add(current)

        # Check which levels of the access chain are guarded
        for level in chain:
            # Check if this level or a parent level is checked
            is_guarded = False

            # Direct check (including implicit parent guards)
            if level in expanded_checked_vars:
                is_guarded = True

            # Check if a child level is checked (which implicitly guards this level)
            for checked_var in all_checked_vars:
                if checked_var.startswith(level + '.') or checked_var.startswith(level + '['):
                    is_guarded = True
                    break

            # Check if it's a loop variable
            base = level.split('.')[0].split('[')[0]
            if base in loop_vars:
                is_guarded = True

            # For index access, check if the list has length check
            if '[' in level:
                list_part = re.sub(r'\[.*$', '', level)
                if list_part in length_checked_vars or list_part in expanded_checked_vars:
                    is_guarded = True

            if is_guarded:
                result['guarded_levels'].append(level)
            else:
                result['unguarded_levels'].append(level)

        # Check if base variable has truthiness check (including implicit)
        if result['base_variable'] in expanded_checked_vars:
            result['is_truthy_checked'] = True

        result['all_levels_guarded'] = len(result['unguarded_levels']) == 0

        # Identify specific safety issues
        issues = []

        # Issue 1: Undefined variable access
        if not result['is_truthy_checked'] and not result['is_defined_checked'] and not result['is_loop_variable']:
            if result['base_variable'] and result['base_variable'] not in expanded_checked_vars:
                issues.append(f"Variable '{result['base_variable']}' may be undefined - add '{{%% if {result['base_variable']} %%}}' or '{{%% if {result['base_variable']} is defined %%}}'")

        # Issue 2: Unsafe attribute access
        if len(chain) > 1:
            for i, level in enumerate(chain[1:], 1):
                if level in result['unguarded_levels']:
                    parent_level = chain[i-1]
                    if parent_level not in expanded_checked_vars and parent_level not in result['guarded_levels']:
                        issues.append(f"Attribute access '{level}' may fail - add '{{%% if {parent_level} %%}}' check")

        # Issue 3: Unsafe index access
        if result['is_index_access']:
            list_var = re.sub(r'\[.*$', '', code.strip("{ }"))
            if list_var not in length_checked_vars and list_var not in expanded_checked_vars:
                issues.append(f"Index access on '{list_var}' without length check - add '{{%% if {list_var}|length > {result['index_value'] or 0} %%}}'")

        # Issue 4: Chained access without intermediate checks
        if len(chain) > 2:
            for i in range(1, len(chain) - 1):
                if chain[i] in result['unguarded_levels']:
                    issues.append(f"Chained access through '{chain[i]}' is not guarded")

        result['safety_issues'] = issues
        result['is_safe'] = len(issues) == 0

        return result

    def get_variable_accesses(self) -> List[ASTNode]:
        """Get all variable access nodes (Name, Getattr, Getitem)."""
        result = []
        result.extend(self.nodes_by_type.get('Name', []))
        result.extend(self.nodes_by_type.get('Getattr', []))
        result.extend(self.nodes_by_type.get('Getitem', []))
        return result

    def get_jinja_expressions(self) -> List[ASTNode]:
        """
        Get only Jinja expression nodes ({{ ... }}).
        Filters to only include Getattr and Getitem nodes that represent
        actual template expressions, excluding intermediate nodes.
        """
        result = []
        # Only get top-level Getattr/Getitem (those whose parent is Output, Filter, If, For, etc.)
        # This excludes nested Getattr like post.author in {{ post.author.username }}
        for node in self.nodes_by_type.get('Getattr', []):
            parent = self.get_parent(node)
            # Include if parent is not another Getattr (i.e., this is the top-level expression)
            if parent and parent.node_type != 'Getattr':
                result.append(node)

        for node in self.nodes_by_type.get('Getitem', []):
            parent = self.get_parent(node)
            if parent and parent.node_type not in ('Getattr', 'Getitem'):
                result.append(node)

        return result

    def get_jinja_hashmap(self) -> Dict[str, Dict]:
        """
        Return hashmap containing only Jinja expressions ({{ ... }}).
        Excludes TemplateData, structural nodes, and intermediate nodes.
        """
        hashmap = {}
        jinja_nodes = self.get_jinja_expressions()

        for node in jinja_nodes:
            key = f"{node.node_type}:{node.line_number}:{id(node.node)}"
            parent = self.parent_map.get(node)
            context = self.get_node_context(node)

            hashmap[key] = {
                'node_type': node.node_type,
                'code': node.code_repr,
                'line': node.line_number,
                'parent': {
                    'node_type': parent.node_type,
                    'code': parent.code_repr,
                    'line': parent.line_number
                } if parent else None,
                'context': context
            }
        return hashmap

    def get_parent_hashmap(self) -> Dict[str, Dict]:
        """
        Return the parent hashmap in a serializable format.
        Each entry maps a node's code representation to its parent info and context.
        """
        hashmap = {}
        for node in self.all_nodes:
            key = f"{node.node_type}:{node.line_number}:{id(node.node)}"
            parent = self.parent_map.get(node)
            context = self.get_node_context(node)

            hashmap[key] = {
                'node_type': node.node_type,
                'code': node.code_repr,
                'line': node.line_number,
                'parent': {
                    'node_type': parent.node_type,
                    'code': parent.code_repr,
                    'line': parent.line_number
                } if parent else None,
                'context': context
            }
        return hashmap


def parse_template_to_ast(template_path: Path) -> JinjaASTParser:
    """Parse a template file and return the AST parser."""
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")

    with open(template_path, 'r') as f:
        content = f.read()

    return JinjaASTParser(content, template_path.name)


# ============================================================================
# SEMGREP + AST INTEGRATION
# ============================================================================

def analyze_semgrep_findings(
    findings: List[SemgrepFinding],
    parser: JinjaASTParser
) -> List[SemgrepFindingAnalysis]:
    """
    Analyze semgrep findings using the AST parser to determine guard status.

    For each semgrep finding, this function:
    1. Finds the corresponding AST nodes at the finding's line
    2. Analyzes whether the variables are properly guarded
    3. Returns detailed analysis for each finding

    Args:
        findings: List of semgrep findings to analyze
        parser: JinjaASTParser instance for the template

    Returns:
        List of SemgrepFindingAnalysis with guard status for each finding
    """
    analyses = []

    for finding in findings:
        # Find AST nodes at the finding's line
        nodes_at_line = parser.get_nodes_at_line(finding.line_start)

        # Look for the expression node that matches the finding
        matching_node = None
        for node in nodes_at_line:
            if node.node_type in ('Getattr', 'Getitem', 'Name'):
                # Check if this node's code matches the finding's expression
                if _code_matches_finding(node.code_repr, finding):
                    matching_node = node
                    break

        # If no exact match, try to find the most relevant node
        if not matching_node:
            for node in nodes_at_line:
                if node.node_type in ('Getattr', 'Getitem'):
                    matching_node = node
                    break

        # Analyze the finding
        analysis = _analyze_single_finding(finding, matching_node, parser)
        analyses.append(analysis)

    return analyses


def _code_matches_finding(code_repr: str, finding: SemgrepFinding) -> bool:
    """Check if an AST node's code representation matches a semgrep finding."""
    # Clean up both for comparison
    code_clean = code_repr.strip("{ }").strip()
    finding_expr = finding.full_expression.strip("{ }").strip()

    # Check for substring match
    return code_clean in finding_expr or finding_expr in code_clean


def _analyze_single_finding(
    finding: SemgrepFinding,
    node: Optional[ASTNode],
    parser: JinjaASTParser
) -> SemgrepFindingAnalysis:
    """Analyze a single semgrep finding using AST context."""

    guarded_vars = []
    unguarded_vars = []
    guard_type = None
    guard_expression = None
    ast_analysis = None

    if node:
        # Use the parser's comprehensive safety analysis
        ast_analysis = parser.analyze_access_safety(node)

        # Determine guard status from AST analysis
        is_guarded = ast_analysis.get('is_safe', False)

        # Get guard details
        if ast_analysis.get('is_loop_variable'):
            guard_type = "loop_variable"
            guard_expression = "Variable from for loop iteration"
        elif ast_analysis.get('is_defined_checked'):
            guard_type = "defined_check"
            guard_expression = "{% if var is defined %}"
        elif ast_analysis.get('is_none_checked'):
            guard_type = "none_check"
            guard_expression = "{% if var is not none %}"
        elif ast_analysis.get('is_truthy_checked'):
            guard_type = "truthiness_check"
            context = parser.get_node_context(node)
            if context.get('conditions'):
                guard_expression = f"{{% if {context['conditions'][0]} %}}"
        elif ast_analysis.get('is_length_checked'):
            guard_type = "length_check"
            guard_expression = "{% if var|length > 0 %}"

        guarded_vars = ast_analysis.get('guarded_levels', [])
        unguarded_vars = ast_analysis.get('unguarded_levels', [])

    else:
        # No matching AST node found - analyze based on finding variables
        # Try to find guard status from finding's line context
        is_guarded = False
        unguarded_vars = finding.variables.copy()

        # Check if any variable is in a loop or conditional by inspecting nearby nodes
        for var in finding.variables:
            # Try to find if this variable appears in a guarded context elsewhere
            for ast_node in parser.all_nodes:
                if ast_node.line_number == finding.line_start:
                    context = parser.get_node_context(ast_node)
                    if context.get('in_conditional') or context.get('in_loop'):
                        # Check if the condition/loop relates to our variable
                        for cond in context.get('conditions', []):
                            base_var = var.split('.')[0].split('[')[0]
                            if base_var in cond:
                                is_guarded = True
                                guard_type = "conditional"
                                guard_expression = f"{{% if {cond} %}}"
                                if var in unguarded_vars:
                                    unguarded_vars.remove(var)
                                    guarded_vars.append(var)
                                break

    return SemgrepFindingAnalysis(
        finding=finding,
        is_guarded=is_guarded if node else (len(unguarded_vars) == 0),
        guard_type=guard_type,
        guard_expression=guard_expression,
        unguarded_variables=unguarded_vars,
        guarded_variables=guarded_vars,
        ast_safety_analysis=ast_analysis
    )


def run_semgrep_stage(template_path: Path) -> List[SemgrepFinding]:
    """
    Stage 1: Semgrep Scan - Run semgrep to identify problematic patterns.

    Args:
        template_path: Path to the Jinja2 template file

    Returns:
        List of SemgrepFinding objects
    """
    print("=" * 70)
    print("STAGE 1: SEMGREP SCAN")
    print("=" * 70)
    print()

    if not template_path.exists():
        print(f"Error: Template not found: {template_path}")
        return []

    print(f"Scanning: {template_path}\n")

    findings = run_semgrep(template_path)

    if findings:
        print(f"✓ Found {len(findings)} potential issues:\n")
        for i, finding in enumerate(findings, 1):
            severity_icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(finding.severity, "⚪")
            print(f"  {i}. {severity_icon} [{finding.severity}] {finding.rule_id}")
            print(f"     Line {finding.line_start}: {finding.matched_code}")
            print(f"     Variables: {finding.variables}")
            print()
    else:
        print("✓ No issues found by semgrep\n")

    return findings


def run_ast_analysis_stage(template_path: Path) -> Optional[JinjaASTParser]:
    """
    Stage: AST Analysis - Parse a single template and build parent hashmap.

    Args:
        template_path: Path to the Jinja2 template file

    Returns:
        JinjaASTParser instance or None if parsing failed
    """
    print("=" * 70)
    print("AST ANALYSIS STAGE: Parsing Jinja2 Template")
    print("=" * 70)
    print()

    if not template_path.exists():
        print(f"Error: Template not found: {template_path}")
        return None

    print(f"Analyzing: {template_path}\n")

    try:
        parser = parse_template_to_ast(template_path)
        print(f"✓ {template_path.name}: {len(parser.all_nodes)} AST nodes")
        print()
        return parser
    except Exception as e:
        print(f"✗ {template_path.name}: Error - {e}")
        return None


def display_ast_structure(parser: JinjaASTParser, indent: int = 0):
    """Display the AST structure with indentation."""
    def display_node(node: ASTNode, level: int):
        prefix = "  " * level
        line_info = f" (line {node.line_number})" if node.line_number else ""
        print(f"{prefix}├─ {node.node_type}{line_info}: {node.code_repr}")
        for child in node.children:
            display_node(child, level + 1)

    if parser.root:
        display_node(parser.root, indent)


def display_parent_hashmap(parser: JinjaASTParser):
    """Display the parent hashmap in a readable format."""
    print("\nParent Hashmap (child -> parent):")
    print("-" * 50)

    for node in parser.all_nodes:
        parent = parser.get_parent(node)
        if parent:
            print(f"  {node.code_repr}")
            print(f"    └─ parent: {parent.code_repr}")


def generate_report(parser: JinjaASTParser) -> int:
    """Generate a summary report for the parsed template."""
    print("=" * 70)
    print("AST ANALYSIS REPORT")
    print("=" * 70)
    print()

    print(f"📄 {parser.template_name}")
    print("-" * 40)

    # Get Jinja expressions only
    jinja_expressions = parser.get_jinja_expressions()
    print(f"  Total Jinja Expressions: {len(jinja_expressions)}")

    # Display detailed safety analysis for each Jinja expression
    print("\n" + "=" * 70)
    print("SAFETY ANALYSIS")
    print("=" * 70)

    safe_count = 0
    unsafe_count = 0
    all_issues = []

    for expr_node in jinja_expressions:
        safety = parser.analyze_access_safety(expr_node)

        status = "✅ SAFE" if safety['is_safe'] else "❌ UNSAFE"
        print(f"\n  {expr_node.code_repr}")
        print(f"    Line: {expr_node.line_number}")
        print(f"    Status: {status}")

        # Access chain
        if len(safety['access_chain']) > 1:
            print(f"    Access Chain: {' -> '.join(safety['access_chain'])}")

        # Safety checks performed
        checks = []
        if safety['is_loop_variable']:
            checks.append("Loop variable (safe)")
        if safety['is_defined_checked']:
            checks.append("'is defined' check")
        if safety['is_none_checked']:
            checks.append("'is not none' check")
        if safety['is_truthy_checked']:
            checks.append("Truthiness check")
        if safety['is_length_checked']:
            checks.append("Length check")

        if checks:
            print(f"    Safety Checks: {', '.join(checks)}")

        # Index access info
        if safety['is_index_access']:
            print(f"    Index Access: YES (index={safety['index_value']})")
            if safety['is_length_checked']:
                print(f"      Length Check: YES")
            else:
                print(f"      Length Check: NO ⚠️")

        # Guarded levels
        if safety['guarded_levels']:
            print(f"    Guarded Levels: {safety['guarded_levels']}")
        if safety['unguarded_levels']:
            print(f"    Unguarded Levels: {safety['unguarded_levels']} ⚠️")

        # Safety issues
        if safety['safety_issues']:
            print(f"    Issues:")
            for issue in safety['safety_issues']:
                print(f"      ⚠️  {issue}")
                all_issues.append({
                    'line': expr_node.line_number,
                    'expression': expr_node.code_repr,
                    'issue': issue
                })

        if safety['is_safe']:
            safe_count += 1
        else:
            unsafe_count += 1

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total Jinja Expressions: {len(jinja_expressions)}")
    print(f"Safe Expressions: {safe_count}")
    print(f"Unsafe Expressions: {unsafe_count}")

    if all_issues:
        print(f"\n❌ ISSUES FOUND ({len(all_issues)}):")
        for issue in all_issues:
            print(f"  Line {issue['line']}: {issue['expression']}")
            print(f"    → {issue['issue']}")

    print()

    return 1 if unsafe_count > 0 else 0


def generate_combined_report(
    findings: List[SemgrepFinding],
    analyses: List[SemgrepFindingAnalysis],
    parser: JinjaASTParser
) -> int:
    """
    Generate a combined report showing semgrep findings with AST guard analysis.

    Args:
        findings: Original semgrep findings
        analyses: AST analysis results for each finding
        parser: JinjaASTParser instance

    Returns:
        Exit code (0 if all findings are guarded, 1 if unguarded issues exist)
    """
    print("=" * 70)
    print("STAGE 3: COMBINED ANALYSIS REPORT")
    print("=" * 70)
    print()

    if not analyses:
        print("No semgrep findings to analyze.\n")
        return 0

    guarded_count = 0
    unguarded_count = 0
    unguarded_issues = []

    for analysis in analyses:
        finding = analysis.finding
        severity_icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(finding.severity, "⚪")

        # Determine final status
        if analysis.is_guarded:
            status = "✅ GUARDED"
            guarded_count += 1
        else:
            status = "❌ UNGUARDED"
            unguarded_count += 1
            unguarded_issues.append(analysis)

        print(f"{severity_icon} [{finding.severity}] {finding.rule_id}")
        print(f"   Line {finding.line_start}: {finding.matched_code}")
        print(f"   Status: {status}")

        # Show guard details if guarded
        if analysis.is_guarded and analysis.guard_type:
            print(f"   Guard Type: {analysis.guard_type}")
            if analysis.guard_expression:
                print(f"   Guard Expression: {analysis.guard_expression}")

        # Show variables breakdown
        if analysis.guarded_variables:
            print(f"   Guarded Variables: {analysis.guarded_variables}")
        if analysis.unguarded_variables:
            print(f"   Unguarded Variables: {analysis.unguarded_variables} ⚠️")

        # Show AST safety issues if available
        if analysis.ast_safety_analysis:
            issues = analysis.ast_safety_analysis.get('safety_issues', [])
            if issues:
                print(f"   Safety Issues:")
                for issue in issues:
                    print(f"      → {issue}")

        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total Semgrep Findings: {len(analyses)}")
    print(f"  ✅ Guarded (Safe): {guarded_count}")
    print(f"  ❌ Unguarded (Unsafe): {unguarded_count}")
    print()

    if unguarded_issues:
        print("❌ UNGUARDED ISSUES REQUIRING ATTENTION:")
        print("-" * 50)
        for analysis in unguarded_issues:
            finding = analysis.finding
            print(f"\n  Line {finding.line_start}: {finding.matched_code}")
            print(f"    Rule: {finding.rule_id}")
            print(f"    Message: {finding.message}")
            if analysis.unguarded_variables:
                print(f"    Unguarded: {analysis.unguarded_variables}")
            print(f"    Suggested Fix: Add guard condition, e.g.:")
            # Generate fix suggestion
            base_var = analysis.unguarded_variables[0].split('.')[0] if analysis.unguarded_variables else "var"
            print(f"      {{% if {base_var} %}}")
            print(f"        {finding.matched_code}")
            print(f"      {{% endif %}}")
    else:
        print("✅ All semgrep findings are properly guarded!")

    print()

    return 1 if unguarded_count > 0 else 0


def main():
    # ============================================================
    # CONFIGURATION: Set the template path here
    # ============================================================
    template_path = Path("templates/post.jinja")
    # ============================================================

    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 10 + "TWO-STAGE JINJA2 TEMPLATE VALIDATOR" + " " * 22 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    # ================================================================
    # STAGE 1: Semgrep Scan
    # ================================================================
    findings = run_semgrep_stage(template_path)

    if not findings:
        print("No semgrep findings. Template appears clean.")
        print("Running AST analysis for comprehensive check...\n")

    # ================================================================
    # STAGE 2: AST Analysis
    # ================================================================
    parser = run_ast_analysis_stage(template_path)

    if not parser:
        print("Template parsing failed.")
        sys.exit(1)

    # ================================================================
    # STAGE 3: Combine Semgrep findings with AST guard analysis
    # ================================================================
    if findings:
        print("=" * 70)
        print("STAGE 2.5: ANALYZING SEMGREP FINDINGS WITH AST")
        print("=" * 70)
        print()
        print("Checking if flagged variables are properly guarded...\n")

        analyses = analyze_semgrep_findings(findings, parser)

        # Generate combined report
        exit_code = generate_combined_report(findings, analyses, parser)
    else:
        # No semgrep findings, run standard AST analysis
        exit_code = generate_report(parser)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

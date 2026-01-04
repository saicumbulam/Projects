# RFC-001: Staged Jinja2 Template Validation System

| **Field**   | **Value**                              |
|-------------|----------------------------------------|
| **Title**   | Staged Jinja2 Template Validation System |
| **Author**  | [Author Name]                          |
| **Status**  | Draft                                  |
| **Date**    | 2026-01-04                             |

---

## Summary

This RFC proposes a multi-stage validation system for Jinja2 templates that combines static analysis (Semgrep), model-based attribute validation, and runtime testing to detect unsafe variable accesses before deployment. The approach has been validated through a working Proof of Concept that successfully identifies template errors that would cause `AttributeError`, `IndexError`, and `KeyError` exceptions at runtime.

---

## Motivation

### Problem Statement

Jinja2 templates in production applications frequently crash at runtime due to:

1. **Null/undefined attribute access**: Accessing `{{ user.profile.avatar }}` when `profile` is `None`
2. **Invalid list indexing**: Accessing `{{ items[0] }}` on an empty list
3. **Missing dictionary keys**: Accessing `{{ data["key"] }}` when key doesn't exist
4. **Chained attribute failures**: Deep attribute chains like `{{ post.author.username }}` failing at any level

These errors are particularly insidious because:
- They pass code review (the syntax is valid)
- They pass unit tests (unless edge cases are explicitly tested)
- They only manifest in production with specific data states
- They cause 500 errors and degraded user experience

### Current State

Currently, template errors are discovered through:
- Manual code review (inconsistent, error-prone)
- Production incidents (reactive, costly)
- Ad-hoc runtime testing (incomplete coverage)

### Goal

Implement a proactive, automated validation pipeline that catches template errors **before deployment** with high precision and minimal false positives.

---

## Proposed Solution / Technical Design

### Architecture Overview

The system implements a **three-stage validation pipeline**, where each stage builds upon the previous:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    STAGED TEMPLATE VALIDATOR                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Stage 1: SEMGREP (Static Analysis)                                │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  • Pattern-based detection of unsafe accesses               │   │
│   │  • Custom rules for Jinja2 anti-patterns                    │   │
│   │  • Output: List of potentially problematic variables        │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│   Stage 2: ATTRIBUTE VALIDATION (Model Analysis)                    │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  • Parse Python model definitions                           │   │
│   │  • Validate flagged attributes exist in models              │   │
│   │  • Output: Confirmed undefined attribute errors             │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│   Stage 3: RUNTIME VALIDATION (Execution Testing)                   │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  • Render templates with test data instances                │   │
│   │  • Catch actual exceptions during rendering                 │   │
│   │  • Output: Confirmed runtime crashes                        │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│   FINAL REPORT                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  • Prioritized issues (CRITICAL / WARNING / INFO)           │   │
│   │  • Actionable fix suggestions                               │   │
│   │  • Exit code for CI/CD integration                          │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Semgrep Static Analysis

Custom Semgrep rules detect the following anti-patterns in Jinja2 templates:

| Rule ID | Severity | Detection |
|---------|----------|-----------|
| `jinja2-unsafe-optional-access` | WARNING | `{{ var.attr }}` without `{% if var %}` guard |
| `jinja2-unsafe-chained-access` | ERROR | `{{ a.b.c }}` (2+ levels) without null check |
| `jinja2-unsafe-list-indexing` | ERROR | `{{ items[0] }}` without length check |
| `jinja2-unsafe-dict-key-access` | ERROR | `{{ data["key"] }}` without existence check |
| `jinja2-unsafe-index-then-attribute` | ERROR | `{{ items[0].name }}` compound access |
| `jinja2-unclosed-block` | WARNING | Missing `{% endif %}` / `{% endfor %}` |
| `jinja2-undefined-variable-usage` | ERROR | Explicit `{{ undefined }}` usage |

**Key Design Decision**: Rules target `.jinja`, `.jinja2`, and `.j2` file extensions to avoid false positives from other file types.

### Stage 2: Model-Based Attribute Validation

For each variable flagged by Semgrep:
1. Parse Python model definitions (`models.py`)
2. Extract class attributes and relationships
3. Validate that accessed attributes exist on the expected types
4. Cross-reference with Semgrep findings to confirm real issues

This stage **reduces false positives** by confirming that flagged attributes are genuinely undefined.

### Stage 3: Runtime Validation

Execute template rendering with test data to:
1. Instantiate model objects with realistic edge-case data (nulls, empty lists)
2. Render each template through Jinja2
3. Capture actual exceptions with line numbers
4. Correlate runtime errors with static analysis findings

**Severity Escalation**: Issues detected by all three stages are classified as **CRITICAL** since they represent confirmed crashes.

### Output and CI/CD Integration

The validator produces:
- Human-readable console output with severity-based categorization
- Actionable fix suggestions (e.g., "Add `{% if user.profile %}` check")
- Exit code `0` (success) or `1` (failure) for CI pipeline integration

---

## POC Results

### Validation

The Proof of Concept successfully demonstrated:

| Metric | Result |
|--------|--------|
| **Detection Accuracy** | 100% of intentionally introduced unsafe patterns detected |
| **False Positive Rate** | Low - Model validation eliminates spurious warnings |
| **Execution Time** | < 30 seconds for typical template directories |
| **Runtime Correlation** | Confirmed crashes match static analysis predictions |

### Example Output

```
╔════════════════════════════════════════════════════════════════════╗
║               STAGED TEMPLATE VALIDATOR                            ║
╚════════════════════════════════════════════════════════════════════╝

======================================================================
STAGE 1: Semgrep - Comprehensive Jinja2 Template Analysis
======================================================================

Found 5 potential issue(s):
  - 2 ERROR(s) (must fix - security/crashes)
  - 2 WARNING(s) (should fix - potential issues)
  - 1 INFO(s) (nice to have - best practices)

🔴 ERROR findings (CRITICAL - must fix):
  ❌ profile.jinja2:15 - user.profile.avatar
     Unsafe chained attribute access (2+ levels) without null check

======================================================================
STAGE 2: Attribute Validation - Checking if Attributes Exist
======================================================================

✅ All flagged attributes exist in models!

======================================================================
STAGE 3: Runtime Validation - Testing with Actual Instances
======================================================================

❌ Found runtime errors in 1 template(s):
  profile.jinja2:
    💥 Line 15: AttributeError
       'NoneType' object has no attribute 'avatar'

======================================================================
FINAL REPORT
======================================================================

🚨 CRITICAL ISSUES (1):
  profile.jinja2:15
    Variable: user.profile.avatar
    Issue: CRITICAL: Static analysis + validation + RUNTIME ERROR
    Fix: Add {% if user.profile %} check
```

### Feasibility Confirmation

The POC confirms:
- Semgrep generic language mode is suitable for Jinja2 pattern matching
- Model parsing accurately extracts attribute definitions
- The staged approach effectively prioritizes issues by severity
- Runtime validation provides ground-truth confirmation

---

## Alternatives Considered

### 1. Jinja2 Native Strict Mode

**Approach**: Use `jinja2.StrictUndefined` to fail on undefined variables.

**Why Discarded**:
- Only catches undefined root variables, not chained attribute failures
- Requires runtime execution (no static analysis)
- Cannot detect index/key errors

### 2. Type Annotations + MyPy

**Approach**: Use typed dictionaries and MyPy to validate template context.

**Why Discarded**:
- Jinja2 templates are not type-checkable by MyPy
- Requires significant refactoring to typed template contexts
- No support for Jinja2-specific constructs

### 3. Custom AST Parser

**Approach**: Build a custom Jinja2 AST parser for template analysis.

**Why Discarded**:
- Significant development effort (Jinja2 has complex grammar)
- Maintenance burden for edge cases
- Semgrep provides equivalent pattern matching with less code

### 4. Runtime-Only Testing

**Approach**: Only perform runtime validation with comprehensive test data.

**Why Discarded**:
- Requires exhaustive test data coverage
- Slow feedback loop (must execute all templates)
- Cannot scale to large template sets

---

## Risks & Drawbacks

### Technical Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| **Semgrep rule false positives** | Medium | Stage 2 model validation filters spurious warnings |
| **Model parsing limitations** | Low | Support common patterns (dataclasses, SQLAlchemy, Pydantic); extensible for others |
| **Runtime test data coverage** | Medium | Document required test fixtures; fail-safe to skip if unavailable |

### Operational Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **CI pipeline slowdown** | Low | < 30s execution; can run in parallel with other checks |
| **Developer friction** | Medium | Clear error messages with fix suggestions; suppress INFO-level in strict mode |
| **Dependency on Semgrep** | Low | Semgrep is MIT-licensed, actively maintained, and industry-standard |

### Limitations

1. **Generic templates**: Highly dynamic templates (e.g., macro-heavy, heavily parameterized) may produce false positives
2. **External data sources**: Cannot validate attributes from external APIs or databases not defined in models
3. **Conditional complexity**: Deeply nested conditionals may confuse static analysis

---

## Unresolved Questions

The following items require team discussion:

1. **Severity thresholds**: Should CI fail on WARNINGs, or only ERRORs?
2. **Suppression mechanism**: How should developers suppress known false positives? (inline comments, config file, or allowlist)
3. **Model discovery**: Should model parsing be automatic (scan all `*.py` files) or explicit (configured paths)?
4. **Test fixture requirements**: What is the contract for runtime test data? Should fixtures be auto-generated or manually maintained?
5. **Rollout strategy**: Should this be opt-in per-repository initially, or enforced organization-wide?
6. **Performance at scale**: What is acceptable execution time for repositories with 500+ templates?

---

## Implementation Plan

1. **Phase 1**: Integrate Semgrep rules into existing CI pipeline (Stage 1 only)
2. **Phase 2**: Add model validation with support for primary ORM patterns
3. **Phase 3**: Implement runtime validation with fixture generation
4. **Phase 4**: Production rollout with monitoring and tuning

---

## References

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Jinja2 Template Designer Documentation](https://jinja.palletsprojects.com/en/3.1.x/templates/)
- [OWASP Template Injection](https://owasp.org/www-project-web-security-testing-guide/)

---

*This RFC is open for comments. Please add feedback in the Unresolved Questions section or discuss in #engineering-rfcs.*
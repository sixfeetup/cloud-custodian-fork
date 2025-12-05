# Phase 1 Implementation Plan: c7n-org validate (MVP)

**Validation Team - Detailed Implementation Plan**

---

## Executive Summary

This document provides a detailed implementation plan for Phase 1 of adding validation support to c7n-org. Phase 1 represents the MVP (Minimum Viable Product) that delivers basic account-agnostic validation functionality.

**Phase 1 Goal:** Enable users to validate policy syntax and structure without requiring cloud credentials or account-specific context.

**Estimated Effort:** 2-4 days total
- Development: 1-2 days
- Testing: 0.5-1 day  
- Documentation: 0.5 day

---

## Phase 1 Scope

### In Scope

✅ **Core Validation Features:**
- JSON/YAML schema validation
- Policy structure validation using StructureParser
- Resource type loading and validation
- Policy object creation and validation (policy.validate())
- Duplicate policy name detection across files
- Optional deprecation checking (--check-deprecations flag)

✅ **CLI Features:**
- New `c7n-org validate` command
- Account config file input (-c/--config)
- Policy file input (-u/--use)
- Policy filtering (-p/--policy)
- Resource type filtering (--resource)
- Policy tag filtering (-l/--policytags)
- Debug mode (--debug)
- Verbose output (-v/--verbose)

✅ **Quality Assurance:**
- Unit tests for validation logic
- Integration tests with sample configurations
- Error handling and user-friendly messages

### Out of Scope (Future Phases)

❌ Account-specific validation
❌ Per-account variable expansion
❌ Account filtering (--accounts, --tags)
❌ JSON output format
❌ Validation of account configuration file
❌ Performance optimization for large policy sets

---

## Technical Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────┐
│              c7n-org validate command               │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│         Load & Parse Configuration Files            │
│  - Account config (for filtering only)              │
│  - Policy config (to validate)                      │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│              Apply Policy Filters                   │
│  - Filter by policy name (-p)                       │
│  - Filter by resource type (--resource)             │
│  - Filter by policy tags (-l)                       │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│          Core Validation Logic                      │
│  (Reuse from c7n.commands.validate)                 │
│  1. Structure validation                            │
│  2. Schema validation                               │
│  3. Resource type loading                           │
│  4. Policy object validation                        │
│  5. Duplicate name detection                        │
│  6. Deprecation checking (optional)                 │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│              Report Results                         │
│  - Success: exit 0                                  │
│  - Failure: error details, exit 1                   │
└─────────────────────────────────────────────────────┘
```

### Code Organization

**New Files:**
- None required - all changes in existing `tools/c7n_org/c7n_org/cli.py`

**Modified Files:**
- `tools/c7n_org/c7n_org/cli.py` - Add validate command

**Test Files:**
- `tools/c7n_org/tests/test_org.py` - Add validation tests

### Key Design Decisions

1. **Reuse vs Rewrite:** We will reuse the core validation logic from `c7n.commands.validate()` rather than rewriting it. This ensures consistency and reduces maintenance burden.

2. **Account Config Handling:** The account config file (-c) is loaded but NOT validated in Phase 1. It's only used for policy filtering purposes (if needed in future). This keeps Phase 1 simple and focused.

3. **No Account-Specific Context:** Validation uses dummy account_id='na' and region='na' just like base custodian validate. No variable expansion or account-specific checks.

4. **Exit Codes:** Follow base custodian pattern:
   - 0 = success (all policies valid)
   - 1 = failure (validation errors found)
   - For deprecations with --check-deprecations=strict: exit 1

5. **Logging:** Use c7n-org's existing logging setup with LogFilter to keep output clean.

---

## Implementation Details

### Step 1: Add Validate Command Structure

**File:** `tools/c7n_org/c7n_org/cli.py`

**Location:** After the `report` command definition (around line 430)

**Code Structure:**
```python
@cli.command()
@click.option('-c', '--config', required=True, help="Accounts config file")
@click.option('-u', '--use', required=True, help="Policy config file(s)")
@click.option('-p', '--policy', multiple=True, help="Policy name filter")
@click.option('-l', '--policytags', 'policy_tags',
              multiple=True, default=None, help="Policy tag filter")
@click.option('--resource', default=None, help="Resource type filter")
@click.option('--check-deprecations', 
              type=click.Choice(['skip', 'warn', 'strict']),
              default='warn',
              help="Check for deprecated features")
@click.option('--debug', default=False, is_flag=True)
@click.option('-v', '--verbose', default=False, help="Verbose", is_flag=True)
def validate(config, use, policy, policy_tags, resource, 
             check_deprecations, debug, verbose):
    """Validate policy files for c7n-org execution."""
    # Implementation here
```

### Step 2: Initialize Logging and Load Configurations

**Pseudocode:**
```python
def validate(...):
    # 1. Setup logging (reuse existing init pattern)
    level = verbose and logging.DEBUG or logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s: %(name)s:%(levelname)s %(message)s")
    
    # 2. Load account config (for future use, minimal validation)
    with open(config, 'rb') as fh:
        accounts_config = yaml.safe_load(fh.read())
        # Optional: validate against CONFIG_SCHEMA
    
    # 3. Load policy config
    with open(use) as fh:
        custodian_config = yaml.safe_load(fh.read())
    
    # 4. Apply policy filters
    filter_policies(custodian_config, policy_tags, policy, resource)
    
    # 5. Load available resources
    load_available()
```

### Step 3: Core Validation Logic

**Approach:** Extract reusable logic from `c7n.commands.validate()` or call it directly with adapted parameters.

**Option A - Direct Reuse (Preferred):**
Import and adapt the validation function:

```python
from c7n.commands import validate as c7n_validate
from c7n.parser import validate_check_deprecations

# Create a mock options object that matches what c7n validate expects
class ValidationOptions:
    def __init__(self, config_file, check_deprecations):
        self.configs = [config_file]
        self.dryrun = True
        self.check_deprecations = validate_check_deprecations(check_deprecations)

# Call validation
try:
    opts = ValidationOptions(use, check_deprecations)
    c7n_validate(opts)
except SystemExit as e:
    sys.exit(e.code)
```

**Option B - Inline Implementation:**
If direct reuse proves difficult, implement validation inline following the same pattern as c7n.commands.validate():

```python
from c7n import schema
from c7n.policy import Policy
from c7n.config import Config
from c7n.resources import load_resources
from c7n.structure import StructureParser
from c7n.policy import PolicyValidationError
from c7n import deprecated
from c7n.parser import DuplicateKeyCheckLoader, SourceLocator, Bag

def run_validation(policy_file, check_deprecations_mode):
    """Run validation on policy file."""
    used_policy_names = set()
    structure = StructureParser()
    all_errors = {}
    found_deprecations = False
    footnotes = deprecated.Footnotes()
    
    # Load policy file
    with open(policy_file) as fh:
        data = yaml.load(fh.read(), Loader=DuplicateKeyCheckLoader)
    
    # Structure validation
    try:
        structure.validate(data)
    except PolicyValidationError as e:
        log.error(f"Configuration invalid: {policy_file}")
        log.error(str(e))
        return False
    
    # Schema validation
    load_resources(structure.get_resource_types(data))
    schm = schema.generate()
    errors = schema.validate(data, schm)
    
    # Check for duplicate policy names
    conf_policy_names = {p.get('name', 'unknown') for p in data.get('policies', ())}
    dupes = conf_policy_names.intersection(used_policy_names)
    if dupes:
        errors.append(ValueError(f"Duplicate policy names: {', '.join(dupes)}"))
    used_policy_names.update(conf_policy_names)
    
    # Policy-level validation
    if not errors:
        null_config = Config.empty(dryrun=True, account_id='na', region='na')
        source_locator = SourceLocator(policy_file)
        
        for p in data.get('policies', ()):
            try:
                policy = Policy(p, null_config, Bag())
                policy.validate()
                
                # Check deprecations
                if check_deprecations_mode != deprecated.SKIP:
                    report = deprecated.report(policy)
                    if report:
                        found_deprecations = True
                        log.warning("deprecated usage found in policy\n" + 
                                    report.format(source_locator=source_locator,
                                                  footnotes=footnotes))
            except Exception as e:
                errors.append(f"Policy {p.get('name', 'unknown')} is invalid: {e}")
    
    # Report results
    if errors:
        log.error(f"Configuration invalid: {policy_file}")
        for e in errors:
            log.error(str(e))
        return False
    
    log.info(f"Configuration valid: {policy_file}")
    
    # Handle deprecations
    if found_deprecations:
        if footnotes():
            log.warning("deprecation footnotes:\n" + footnotes())
        if check_deprecations_mode == deprecated.STRICT:
            return False
    
    return True
```

### Step 4: Error Handling and Exit Codes

```python
def validate(...):
    # ... setup code ...
    
    success = run_validation(use, check_deprecations)
    
    if not success:
        sys.exit(1)
    else:
        sys.exit(0)
```

---

## Testing Strategy

### Unit Tests

**File:** `tools/c7n_org/tests/test_org.py`

**Test Cases:**

1. **test_validate_valid_policy**
   - Input: Valid policy file
   - Expected: Exit 0, success message

2. **test_validate_invalid_schema**
   - Input: Policy with schema errors
   - Expected: Exit 1, schema error messages

3. **test_validate_invalid_structure**
   - Input: Policy with structural errors
   - Expected: Exit 1, structure error messages

4. **test_validate_duplicate_policy_names**
   - Input: Multiple policies with same name
   - Expected: Exit 1, duplicate name error

5. **test_validate_with_policy_filter**
   - Input: Valid policy file with -p filter
   - Expected: Exit 0, only specified policy validated

6. **test_validate_with_resource_filter**
   - Input: Valid policy file with --resource filter
   - Expected: Exit 0, only policies for that resource validated

7. **test_validate_deprecated_features_warn**
   - Input: Policy using deprecated features, --check-deprecations=warn
   - Expected: Exit 0, warning messages

8. **test_validate_deprecated_features_strict**
   - Input: Policy using deprecated features, --check-deprecations=strict
   - Expected: Exit 1, warning messages

9. **test_validate_missing_policy_file**
   - Input: Non-existent policy file path
   - Expected: Exit 1, file not found error

10. **test_validate_invalid_policy_file_format**
    - Input: Policy file with .txt extension
    - Expected: Exit 1, format error

### Integration Tests

**Test with Real Configuration Files:**

Create test fixtures in `tools/c7n_org/tests/fixtures/`:
- `valid-policy.yml` - Valid policy
- `invalid-schema-policy.yml` - Schema violation
- `duplicate-names-policy.yml` - Duplicate policy names
- `deprecated-policy.yml` - Uses deprecated features
- `test-accounts.yml` - Sample account config

### Manual Testing Checklist

- [ ] Run on real custodian policy files
- [ ] Test with AWS, Azure, GCP policy files
- [ ] Test with large policy files (100+ policies)
- [ ] Test all command-line flags
- [ ] Test error messages are clear and actionable
- [ ] Verify exit codes

---

## Implementation Steps (Detailed)

### Day 1: Core Implementation

**Hour 1-2: Setup and Skeleton** ✅
- [x] Create validate command structure in cli.py
- [x] Add all Click options with proper help text
- [x] Implement basic logging setup
- [x] Test command is registered: `c7n-org validate --help`

**Hour 3-4: Configuration Loading** ✅
- [x] Implement account config loading
- [x] Implement policy config loading
- [x] Add error handling for missing/invalid files
- [x] Test config loading with sample files

**Hour 5-6: Core Validation Logic** ✅
- [x] Decide on Option A (reuse) vs Option B (inline) - Chose inline (Option B)
- [x] Implement chosen approach
- [x] Test with valid policy file
- [x] Test with invalid policy file

**Hour 7-8: Policy Filtering** ✅
- [x] Implement policy name filtering (-p)
- [x] Implement resource type filtering (--resource)
- [x] Implement policy tag filtering (-l)
- [x] Test filters work correctly

### Day 2: Testing and Polish

**Hour 1-3: Unit Tests** ✅
- [x] Write all 10 unit tests listed above
- [x] Create test fixtures
- [x] Ensure all tests pass
- [x] Achieve ≥90% code coverage for validate function

**Hour 4-5: Integration Testing**
- [ ] Test with real Cloud Custodian policies
- [ ] Test multi-cloud scenarios (AWS, Azure, GCP)
- [ ] Test edge cases and error conditions
- [ ] Fix any bugs discovered

**Hour 6-7: Error Messages and UX**
- [ ] Review all error messages for clarity
- [ ] Ensure consistent formatting
- [ ] Add helpful suggestions where possible
- [ ] Test verbose vs normal output

**Hour 8: Documentation**
- [ ] Update c7n-org README with validate command
- [ ] Add usage examples
- [ ] Document limitations (no account-specific validation)
- [ ] Add to --help output

---

## Code Review Checklist

Before submitting for review:

- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Lint checks pass (`make lint` in project root)
- [ ] Code follows project style guidelines
- [ ] Error messages are clear and actionable
- [ ] Logging is appropriate (not too verbose, not too quiet)
- [ ] Exit codes are correct (0 = success, 1 = failure)
- [ ] Help text is complete and accurate
- [ ] No hardcoded values or magic numbers
- [ ] Proper exception handling
- [ ] Documentation is updated

---

## Success Criteria

Phase 1 is complete when:

1. ✅ `c7n-org validate -c accounts.yml -u policies.yml` successfully validates policy files
2. ✅ All policy filters work (-p, --resource, -l)
3. ✅ Deprecation checking works (skip/warn/strict)
4. ✅ Exit codes are correct (0 for success, 1 for failure)
5. ✅ Error messages are clear and helpful
6. ✅ All unit tests pass with ≥90% coverage for new code
7. ✅ Lint checks pass (`make lint`)
8. ✅ Works with AWS, Azure, GCP policies
9. ✅ Documentation is complete
10. ✅ Performance is acceptable (<5 seconds for typical policy sets)
11. ✅ No regressions in existing c7n-org commands

---

## Risk Mitigation

### Risk 1: Difficulty Reusing c7n.commands.validate

**Likelihood:** Medium  
**Impact:** Medium  
**Mitigation:** 
- Try Option A (direct reuse) first
- Fall back to Option B (inline implementation) if needed
- Both approaches are proven and well-understood

### Risk 2: Test Coverage Gaps

**Likelihood:** Low  
**Impact:** Medium  
**Mitigation:**
- Comprehensive test plan defined above
- Use coverage tools to identify gaps
- Test with real-world policy files

### Risk 3: Inconsistent Behavior with Base Custodian

**Likelihood:** Low  
**Impact:** High  
**Mitigation:**
- Reuse core validation logic where possible
- Run parallel tests with both tools
- Document any intentional differences

---

## Future Considerations (Phase 2+)

Items deliberately deferred to keep Phase 1 focused:

1. **Account-Specific Validation:** Validate with per-account variable expansion
2. **Account Filtering:** Use --accounts and --tags to validate subset
3. **JSON Output:** Machine-readable validation results
4. **Account Config Validation:** Validate the accounts.yml file itself
5. **Parallel Validation:** For very large policy sets
6. **Caching:** Speed up repeated validations
7. **CI/CD Integration:** Exit codes and output optimized for automation

---

## Open Questions

(To be resolved during implementation)

1. Should we validate the account config file itself? 
   - **Tentative Answer:** No, not in Phase 1. Focus on policy validation only.

2. Should policy filtering require the account config file?
   - **Tentative Answer:** Yes, keep -c required for consistency with other commands.

3. How should we handle policies that reference unavailable resources?
   - **Tentative Answer:** Let base validation logic handle it - will error appropriately.

4. Should verbose mode show per-policy validation progress?
   - **Tentative Answer:** Yes, helpful for debugging large policy sets.

---

## Validation Team Notes

*This section for tracking decisions, blockers, and progress during implementation.*

### Decisions Made
- TBD

### Blockers Encountered
- TBD

### Progress Log
- TBD

---

**Document Status:** Initial Draft  
**Last Updated:** 2025-12-04  
**Next Review:** After implementation begins

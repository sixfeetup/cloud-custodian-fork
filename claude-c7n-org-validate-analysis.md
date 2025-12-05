# Feasibility Analysis: Adding `custodian validate` to c7n-org

## Executive Summary

**Verdict: FEASIBLE with moderate complexity**

Adding validation functionality to c7n-org is technically feasible and would provide value, but requires careful design decisions around account-specific vs. account-agnostic validation. The implementation would be straightforward for the core validation logic but needs thoughtful handling of multi-account/multi-cloud scenarios.

---

## Current State Analysis

### How `custodian validate` Works

**Location:** `c7n/commands.py:validate()` (lines 190-287)

**Core Functionality:**
1. **Schema Validation** - Validates YAML/JSON structure against JSON schema
2. **Policy Structure** - Uses `StructureParser` to check high-level policy structure
3. **Resource Type Loading** - Dynamically loads resource types referenced in policies
4. **Policy Object Creation** - Instantiates `Policy` objects with null config
5. **Policy-Level Validation** - Calls `policy.validate()` for business logic checks
6. **Deprecation Checking** - Optional checking for deprecated features (with `--strict` mode)
7. **Duplicate Detection** - Ensures unique policy names across files

**Key Characteristics:**
- **Account-agnostic**: Uses dummy values (`account_id='na'`, `region='na'`)
- **No cloud API calls**: Pure structural validation
- **File-focused**: Processes one or more policy files independently
- **Exit codes**: Returns 1 on any error, 0 on success

### How c7n-org Works

**Location:** `tools/c7n_org/c7n_org/cli.py`

**Architecture:**
- **Commands:** `run`, `report`, `run-script` (3 commands total)
- **Multi-account execution**: Parallel execution across accounts using `ProcessPoolExecutor`
- **Account config**: Separate YAML file defining accounts/subscriptions/projects/tenancies
- **Policy execution**: Uses standard custodian `PolicyCollection` and `Policy` classes
- **Validation in run**: Currently calls validation during execution (line 656-657):
  ```python
  p.expand_variables(p.get_variables(account.get('vars', {})))
  p.validate()
  ```

**Key Characteristics:**
- Uses Click framework (vs argparse in main custodian)
- Account-specific variable expansion
- Parallel execution model
- Multi-cloud support (AWS, Azure, GCP, OCI)

---

## Technical Feasibility Assessment

### ✅ What Makes This Feasible

1. **Reusable Core Logic**: The validate function in `c7n/commands.py` is well-encapsulated and can be reused or adapted
2. **Existing Dependencies**: c7n-org already imports necessary modules (`c7n.policy`, `c7n.schema`, etc.)
3. **Similar Patterns**: The `init()` function (lines 176-217) already loads and validates account configs
4. **Policy Loading**: c7n-org already knows how to load custodian policy files
5. **Test Infrastructure**: Validation tests exist in `tests/test_validation.py` that can be adapted

### ⚠️ Challenges & Design Decisions

#### 1. **Account-Specific vs Account-Agnostic Validation**

**The Core Question:** Should validation be:
- **Option A:** Account-agnostic (validate policy structure only, like base custodian)
- **Option B:** Account-specific (validate for each account's configuration)
- **Option C:** Hybrid (structural validation + optional per-account checks)

**Analysis:**
- **Account-agnostic (Option A):**
  - ✅ Faster - single pass validation
  - ✅ Simpler to implement
  - ✅ Matches custodian behavior
  - ❌ Misses account-specific variable expansion issues
  - ❌ Won't catch account-specific configuration problems

- **Account-specific (Option B):**
  - ✅ More thorough - catches per-account issues
  - ✅ Validates variable expansion per account
  - ✅ Can check account-specific policy conditions
  - ❌ Much slower (N accounts × validation time)
  - ❌ Generates verbose output
  - ❌ May validate against accounts user doesn't intend to run on

- **Hybrid (Option C):**
  - ✅ Best of both worlds
  - ✅ Fast base validation + optional detailed checks
  - ❌ More complex implementation
  - ❌ Two validation modes to maintain

**Recommendation:** Option C (Hybrid) with `--per-account` flag

#### 2. **Variable Expansion Validation**

c7n-org supports account-specific variables:
```yaml
accounts:
  - name: prod-account
    vars:
      environment: production
      charge_code: xyz
```

These get expanded in policies during execution (line 656):
```python
p.expand_variables(p.get_variables(account.get('vars', {})))
```

**Challenge:** Base custodian validate doesn't know about these variables.

**Solutions:**
- Parse account config to extract all unique variables
- Validate with "placeholder" variable values
- Add `--account` filter to validate specific account configurations
- Skip variable-dependent validation (may miss errors)

#### 3. **Multi-Cloud Validation**

c7n-org supports AWS, Azure, GCP, and OCI. Each has different:
- Account identifier formats
- Configuration structures
- Provider-specific resources

**Challenge:** Validation needs to work across all providers.

**Current state:** Base custodian already handles multi-cloud via provider system, so this should "just work" if we reuse the existing validation logic.

#### 4. **Parallel vs Sequential Validation**

**Options:**
- **Sequential:** Validate one policy file at a time (current custodian behavior)
- **Parallel:** Validate multiple accounts in parallel (c7n-org pattern)

**Recommendation:** Sequential for simplicity - validation is fast enough that parallelism isn't needed.

#### 5. **Output Format & Verbosity**

c7n-org uses different logging setup than base custodian (with `LogFilter` class).

**Considerations:**
- Should match c7n-org's quieter console output pattern
- Need clear per-account validation status if doing per-account validation
- Should support JSON output for automation (like `--format json`)

#### 6. **Duplicate Policy Names**

Base custodian validate checks for duplicate policy names across files.

**Question:** Should c7n-org validate check for duplicates:
- Across all accounts? (likely yes - policies run on all accounts)
- Within each account? (probably not needed)

**Recommendation:** Check globally, like base custodian.

---

## Implementation Complexity Assessment

### Low Complexity (Easy)
- ✅ Adding basic validate subcommand to CLI
- ✅ Reusing core validation logic from `c7n.commands.validate`
- ✅ Loading policy files (already done in `init()`)
- ✅ Basic schema validation

### Medium Complexity (Moderate)
- ⚠️ Integrating account configuration with validation
- ⚠️ Handling variable expansion validation
- ⚠️ Supporting account filtering (`--accounts`, `--tags`)
- ⚠️ Proper error reporting for multi-cloud scenarios
- ⚠️ Per-account validation option

### High Complexity (Challenging)
- ⚠️ Validating account-specific policy conditions
- ⚠️ Comprehensive variable substitution checking
- ⚠️ Integration testing across all cloud providers

---

## Recommended Implementation Approach

### Phase 1: Basic Account-Agnostic Validation (MVP)
```bash
c7n-org validate -c accounts.yml -u policies.yml
```

**Features:**
- Validate policy structure (schema, syntax)
- Check for duplicate policy names
- Basic deprecation checking
- Filter by policies (`-p`), resource types (`-t`)
- NO account-specific validation

**Effort:** ~1-2 days

### Phase 2: Account-Aware Enhancements
```bash
c7n-org validate -c accounts.yml -u policies.yml --per-account
c7n-org validate -c accounts.yml -u policies.yml -a prod-account
```

**Features:**
- Validate variable expansion per account
- Filter by account (`-a`, `--tags`)
- Per-account validation mode
- Detect missing variables

**Effort:** ~2-3 days

### Phase 3: Advanced Features
```bash
c7n-org validate -c accounts.yml -u policies.yml --output results.json
```

**Features:**
- JSON output format
- Detailed error reporting
- Validation caching
- Integration with CI/CD pipelines

**Effort:** ~1-2 days

---

## Potential Issues & Risks

### Technical Risks

1. **Variable Expansion Edge Cases**
   - **Risk:** Some variables may only be resolvable at runtime (e.g., from AWS SSM)
   - **Mitigation:** Clearly document limitations; allow placeholder values

2. **Provider-Specific Validation**
   - **Risk:** Some validation may require provider-specific logic
   - **Mitigation:** Reuse existing provider system; test across all providers

3. **Performance with Many Accounts**
   - **Risk:** Per-account validation could be slow with 100+ accounts
   - **Mitigation:** Make per-account validation optional; consider parallelization if needed

4. **Backwards Compatibility**
   - **Risk:** Changes to validation could break existing workflows
   - **Mitigation:** This is a new command, no backwards compatibility issues

### Operational Risks

1. **User Confusion**
   - **Risk:** Users may not understand difference between base custodian and c7n-org validate
   - **Mitigation:** Clear documentation; consistent flags where possible

2. **Incomplete Validation**
   - **Risk:** Users may expect validation to catch all possible errors
   - **Mitigation:** Document what is/isn't validated; explain runtime-only checks

---

## Effort Estimation

### Minimal Implementation (MVP)
- **Development:** 1-2 days
- **Testing:** 0.5-1 day
- **Documentation:** 0.5 day
- **Total:** ~2-4 days

### Full Implementation (All Phases)
- **Development:** 4-7 days
- **Testing:** 2-3 days
- **Documentation:** 1-2 days
- **Total:** ~7-12 days

---

## Recommendation: GO / NO-GO

### ✅ **GO - Recommend Implementation**

**Rationale:**
1. **Clear User Value**: Allows validation before expensive multi-account runs
2. **Reasonable Complexity**: Core functionality is straightforward; advanced features can be added iteratively
3. **Reuses Existing Code**: Leverages well-tested validation logic from base custodian
4. **Fills a Gap**: Currently no way to validate c7n-org policies without running them
5. **Low Risk**: New command doesn't affect existing functionality

**Suggested Approach:**
- Start with Phase 1 (MVP) - basic validation
- Gather user feedback
- Add Phase 2 features based on actual needs
- Phase 3 only if there's demand

---

## Alternative Approaches Considered

### Alternative 1: Just use `custodian validate`
**Pro:** No development needed
**Con:** Doesn't understand c7n-org account configs, variables, or multi-account context

**Verdict:** Insufficient - misses key c7n-org-specific concerns

### Alternative 2: Validate during `c7n-org run`
**Pro:** Already partially done (line 656-657)
**Con:** Requires full account access, slow, wastes resources

**Verdict:** Not ideal for pre-run validation

### Alternative 3: Separate validation tool
**Pro:** Clean separation
**Con:** Extra tool to maintain, install, learn

**Verdict:** Unnecessary - fits naturally in c7n-org

---

## Key Design Principles

If implementing, follow these principles:

1. **Fail Fast**: Catch errors before expensive multi-account runs
2. **Clear Output**: Make errors easy to understand and fix
3. **Consistent UX**: Match c7n-org command patterns and flags
4. **Incremental**: Start simple, add complexity as needed
5. **Documented Limitations**: Be clear about what is/isn't validated
6. **Cloud-Agnostic**: Work equally well for AWS, Azure, GCP, OCI

---

## Conclusion

Adding `validate` to c7n-org is **feasible and recommended**. The core implementation is straightforward, leveraging existing custodian validation logic. The main design challenge is deciding how to handle account-specific validation, which can be addressed with a hybrid approach (basic validation by default, optional per-account mode).

**Success Criteria:**
- Validates policy syntax and structure without requiring cloud credentials
- Works across all supported cloud providers
- Completes in reasonable time (< 5 seconds for typical policy sets)
- Provides clear, actionable error messages
- Integrates naturally with existing c7n-org workflows

The effort is justified by the value: preventing wasted time and resources on invalid policies, especially important when running across dozens or hundreds of accounts.

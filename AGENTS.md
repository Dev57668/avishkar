# Avishkar — Engineering Rules

## 1. Project Mission
Build Avishkar, an AI Generated Code Security Debt Scorer. The system must identify evidence-backed security issues and help developers prioritize remediation.
The project specification is the product requirements reference. Do not treat proposed features as implemented features.

## 2. Core Engineering Principles
- Correctness and security take priority over development speed.
- Prefer small, understandable modules over giant files.
- Every material behavior must have a clear contract and automated tests.
- Use deterministic security evidence as the source of truth.
- AI may explain or help triage existing evidence. AI must not invent a blocking vulnerability or independently certify code as safe.
- Never interpret zero findings as proof that code is secure.
- Clearly distinguish successful, failed, partial, and incomplete analyses.

## 3. Mandatory Workflow
### Before changing code:
1. Inspect relevant existing files and tests.
2. Identify the requirement and acceptance criteria.
3. Explain the intended change and affected components.
4. Check existing conventions and dependencies.

### While implementing:
1. Make the smallest coherent change.
2. Add or update tests alongside the implementation.
3. Preserve existing API contracts unless a change is explicitly approved.
4. Avoid unrelated refactoring.
5. Explain security-sensitive decisions.

### After implementing:
1. Run relevant tests and report the actual command and results.
2. Run linting and type checks when configured.
3. Inspect the final diff.
4. Report changed files, test evidence, limitations, and remaining risks.

Never claim a command succeeded if it was not executed.

## 4. Secure Coding Requirements
- Treat all uploaded archives, source code, filenames, scanner output, and model output as untrusted.
- Prevent archive path traversal, unsafe symbolic links, decompression bombs, and uncontrolled resource consumption.
- Apply explicit file-size, extraction-size, file-count, and execution-time limits.
- Never execute untrusted repository code on the API host.
- Run scanners with argument arrays, not shell-interpolated commands.
- Use timeouts, controlled environments, least privilege, and restricted network access for analysis workers.
- Do not log secrets, credentials, or unnecessary source-code contents.
- Redact detected secrets from user-facing output.
- Validate input at system boundaries.
- Fail closed for security enforcement, but report analysis failures honestly rather than fabricating findings.
- Do not expose raw internal errors or sensitive filesystem paths to API clients.

## 5. Finding Integrity and Provenance
Every normalized finding should retain the available evidence needed to investigate it, including:
- Stable finding or rule identifier
- Scanner and scanner version
- Affected file and source location
- Severity and confidence, when supplied or justified
- Evidence or a safe evidence reference
- Analysis and source revision identifiers
- Explicit limitations when context is incomplete

Do not manufacture evidence, confidence, severity, or source locations. Preserve the distinction between scanner output and any AI-generated explanation.

## 6. Scoring Rules
- Keep scoring logic deterministic, independently testable, and versioned.
- Document every factor, weight, range, default, and missing-data behavior.
- Do not silently substitute invented values for unknown inputs.
- Test boundary cases and repeatability.
- Treat the score as a prioritization index, not a probability of breach or proof of compliance.
- Do not enable blocking decisions based on uncalibrated scoring.

## 7. Dependencies and Architecture
- Prefer established, maintained dependencies with clear justification.
- Pin or constrain dependencies reproducibly.
- Do not add a dependency, external service, database, model provider, or integration without explaining why it is needed.
- Keep secrets out of source control.
- Keep scanner execution separate from API request handling.
- Do not introduce microservices merely for appearance.
- Document important architectural decisions and trade-offs.

## 8. Testing Requirements
- Write regression tests for confirmed defects.
- Cover valid inputs, invalid inputs, boundary conditions, and failure paths.
- Include safe and intentionally vulnerable scanner fixtures.
- Verify that scanner timeouts, crashes, missing executables, malformed output, and unsupported files do not produce a false clean result.
- Test archive traversal and resource-limit enforcement.
- Use deterministic tests that do not depend on live AI services or external networks unless explicitly required.
- Never delete or weaken a test just to make the build pass.

## 9. API and Data Contracts
- Validate request and response schemas.
- Use explicit, stable status values and error semantics.
- Do not expose partial results as complete.
- Keep API changes backward-compatible where practical.
- Introduce versioned migrations if persistent data is added.
- Do not claim authentication, authorization, tenant isolation, or persistence exists unless implemented and tested.

## 10. AI Agent Constraints
- Do not generate the entire application in one task.
- Do not add a frontend before the core analysis workflow is verified.
- Do not add AI explanations before deterministic findings are reliable.
- Do not use mocks as evidence that a real scanner or integration works.
- Do not fabricate test output, scan results, benchmarks, or security guarantees.
- Ask before destructive operations, major architecture changes, or new external services.
- If requirements are ambiguous, state the ambiguity and ask before making a consequential assumption.

## 11. Definition of Done
A task is complete only when:
- Its acceptance criteria are addressed.
- The implementation is understandable and appropriately scoped.
- Tests cover the new behavior and relevant failure cases.
- Relevant checks have been run and their results reported truthfully.
- The final diff has been reviewed.
- Remaining limitations and security risks are documented.

Passing tests alone does not establish production readiness.

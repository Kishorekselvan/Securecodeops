# SecureCodeOps AI — Security & Guardrails

## Platform Security Architecture

1. **Path Traversal & Zip Slip Protection**:
   - Every archive member path is sanitized and verified using `os.path.commonpath` against the designated extraction root.
   - Any relative path component traversing outside the sandbox raises an `ArchiveSecurityError`.

2. **Zip Bomb Prevention**:
   - Total uncompressed byte threshold enforced (`MAX_TOTAL_UNCOMPRESSED_SIZE_MB = 200MB`).
   - Maximum archive member count capped (`MAX_FILES_COUNT = 2000`).

3. **No Execution of User Source Code**:
   - Uploaded repository code is strictly analyzed statically (AST parsing, regex, linters).
   - User application code is NEVER executed, imported, or executed on the host runtime.

4. **Isolated Sandbox Patching**:
   - Proposed patches are applied exclusively to disposable, isolated sandbox directories (`./storage/sandboxes/<uuid>`) which are cleanly purged after verification.

5. **Secrets & Privacy**:
   - No cloud API keys or user credentials are leaked to the client.
   - Fallback offline rule engines allow full offline functionality with zero external API calls.

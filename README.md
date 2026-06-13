# Agent Audit Sandbox

A public AI safety and security portfolio project. This repository contains a toy AI agent sandbox that demonstrates how agent actions can be logged, checked against policy rules, and blocked when they are unsafe.

## Why Agent Auditing Matters

As AI agents become more autonomous and are granted access to tools (such as file systems, web browsers, or APIs), there is a critical need to monitor and control their behavior. Without strict policy checkers and audit logs, agents could:
* Read sensitive system files or credentials.
* Overwrite important data.
* Exfiltrate data via unauthorized network requests.
* Perform path traversal attacks to escape their sandbox.

An audit and policy enforcement layer provides a secure boundary around the agent. It inspects actions before they execute, blocks unsafe attempts, and maintains a transparent, tamper-evident record of all activities.

## Architecture and Capabilities

The sandbox implements the following security components:

1. **Dynamic Actor Context**:
   * **Why it matters**: AI safety auditing requires full attribution. Knowing which agent, subagent, or user session initiated an action helps track intent and locate vulnerabilities.
   * **Implementation**: The `ActorContext` class captures the actor name, session ID, purpose, and metadata. This structured metadata is serialized and written to the audit log.

2. **Tool Registry**:
   * **Why it matters**: Registering tools establishes an explicit boundary on what capabilities an agent has. Instead of letting agents execute arbitrary commands or access the file system directly, they must use registered tools. This enables centralized auditing and access control.
   * **Implementation**: The `ToolRegistry` registers tool callbacks by name (such as `file_read`) and manages their execution.

3. **Tool Argument Schema Validation**:
   * **Why it matters**: Validating input arguments at the boundary prevents malformed arguments, type injection attacks, or empty parameters from bypassing policy logic or throwing unexpected system errors.
   * **Implementation**: The `validate_tool_args` helper inspects tool arguments (for example, verifying that `file_read` has a non-empty string `path`) before executing policy rules or the tool function.

4. **Config-Based Policy Checker**:
   * **How it works**: Instead of relying on hardcoded directories or rules, the policy checker loads rules dynamically from a local configuration file.
   * **Rules enforced**:
     * Enforces tool allowlist (`allowed_tools`) and blocklist (`blocked_tools`).
     * Prevents reads to paths containing blacklisted substrings (`blocked_path_patterns`).
     * Verifies target files lie within one of the approved folders list (`allowed_directories`).
     * Blocks path traversal references (`..`).

5. **Audit Logger**:
   * Appends actions, results (allowed or blocked), actor contexts, and detailed policy check reasons into `logs/audit.jsonl`.

## Policy Configuration Guide

The policy configuration is defined in `policy_config.json` at the project root:
```json
{
  "allowed_directories": [
    "/absolute/path/to/sandbox"
  ],
  "allowed_tools": [
    "file_read"
  ],
  "blocked_tools": [
    "execute_command"
  ],
  "blocked_path_patterns": [
    "sensitive",
    "private_data",
    "secret_file",
    "password"
  ]
}
```

## How to Run the Demo

To run the sandbox demo, run the following command from the root of the repository:
```bash
python3 examples/demo.py
```
This runs the following scenarios and prints outputs and logs:
1. A successful file read by actor Alice (session 101, purpose: data inspection).
2. A blocked out-of-boundary file read by actor Bob (session 202, purpose: scanning directory files).
3. A blocked unregistered tool attempt (network_connect).

The resulting actions are written to `logs/audit.jsonl`.

## How to Run Tests

To run the automated test suite, execute:
```bash
python -m pytest
```
*(If pytest is in a specific environment path, invoke it directly or set PYTHONPATH as needed.)*

## Recommended Next Milestones

* **URL and Host Sandboxing**: Register a network access tool and enforce domain host policies (allowlist and blocklist).
* **Cryptographic Log Signature**: Sign audit log lines with a private key to detect log tampering or deletion.
* **Process and Command Parser Guardrails**: Inspect shell commands for pipeline injection, command chain combinations, or forbidden binary paths.

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
   * **Implementation**: The `ActorContext` class captures the actor name, session id, purpose, and metadata. This structured metadata is serialized and written to the audit log.

2. **Tool Registry**:
   * **Why it matters**: Registering tools establishes an explicit boundary on what capabilities an agent has. Instead of letting agents execute arbitrary commands or access the file system directly, they must use registered tools. This enables centralized auditing and access control.
   * **Implementation**: The `ToolRegistry` registers tool callbacks by name (such as `file_read`) and manages their execution.

3. **Action-Based Policy Checker**:
   * **How it works now**: Instead of running generic checks, policy rules are evaluated per action type. When a tool is invoked, the `PolicyChecker` evaluates the action name and its parameters.
   * **Rules enforced**:
     * `file_read` checks confirm that target files lie within base directories and contain no path traversal patterns (`..`).
     * Unknown tools are blocked by default.

4. **Audit Logger**:
   * Appends actions, results (allowed or blocked), actor contexts, and detailed policy check reasons into `logs/audit.jsonl`.

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

* **Dynamic Config-Based Policies**: Load allowed paths, tool access permissions, and blocking configurations dynamically from YAML or JSON.
* **Network Tool Sandboxing**: Register a network access tool and enforce URL host/IP blocklists.
* **Database Query Guardrails**: Add a database query tool that inspects SQL statements for dangerous operations before execution.

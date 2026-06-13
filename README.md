# Agent Audit Sandbox

A public AI safety and security portfolio project. This repository contains a toy AI agent sandbox that demonstrates how agent actions can be logged, checked against policy rules, and blocked when they are unsafe.

## Why Agent Auditing Matters

As AI agents become more autonomous and are granted access to tools (such as file systems, web browsers, or APIs), there is a critical need to monitor and control their behavior. Without strict policy checkers and audit logs, agents could:
* Read sensitive system files or credentials.
* Overwrite important data.
* Exfiltrate data via unauthorized network requests.
* Perform path traversal attacks to escape their sandbox.

An audit and policy enforcement layer provides a secure boundary around the agent. It inspects actions before they execute, blocks unsafe attempts, and maintains a transparent, tamper-evident record of all activities.

## What the First Version Does

The first version of the sandbox provides:
1. **Toy File Agent**: A simple agent that can request to read files from a specific allowed directory.
2. **Policy Checker**: A policy layer that checks if the requested paths are safe, allowing reads only from approved folders and explicitly blocking path traversal attempts (such as using `../` or relative parents).
3. **Audit Logger**: A structured logging component that writes action details (timestamp, actor, action type, path, decision, and reason) to a JSONL file in a local logs directory.
4. **Demo Script**: A runner that executes safe and unsafe file operations to show the sandbox in action.

## How to Run the Demo

To run the sandbox demo, run the following command from the root of the repository:
```bash
python examples/demo.py
```
This will run three scenarios:
1. A successful read of a file within the allowed folder.
2. A blocked read of a file outside the allowed folder.
3. A blocked read attempting a path traversal attack.

The resulting actions will be written to `logs/audit.jsonl`.

## How to Run Tests

First, install the development dependencies. You can install pytest directly or run it via a virtual environment.
To run the automated test suite, execute:
```bash
python -m pytest
```
The test suite covers safe reading, policy blocking, traversal attempts, error handling for missing files, and audit logging.

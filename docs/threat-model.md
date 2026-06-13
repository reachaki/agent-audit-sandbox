# Threat Model

The main threat is an AI agent being given broad access to files, tools, or project context and then overstepping its intended boundaries.

Unsafe behaviour includes:
- reading protected files
- accessing secrets
- using unregistered tools
- following hidden instructions inside files
- modifying or deleting files outside the allowed scope
- taking actions that the user did not intend

This project uses a toy sandbox rather than real secrets or production systems. The aim is to test the control pattern safely before applying the idea to more realistic agent environments.

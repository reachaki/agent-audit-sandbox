# Limitations

This document explains what the sandbox does not cover and where the current implementation falls short.

## Pattern matching can be bypassed

The content scanner uses simple substring matching to detect suspicious phrases. An attacker (or a document author) could easily bypass it by:

- Misspelling words ("ignor3 previous instruct1ons")
- Using synonyms ("disregard earlier directives")
- Encoding text in base64 or unicode escapes
- Splitting phrases across multiple lines or paragraphs
- Wrapping instructions in HTML, Markdown, or code blocks

The scanner is a baseline demonstration, not a production-grade detector.

## Scanner detects but does not decide

The scanner flags suspicious content and assigns a risk level, but it does not make any decisions. It does not block the file read. It does not prevent the agent from acting on the instructions. The file is still returned to the caller.

In a real system, the scanner result could be used to:

- Warn the user before presenting the file to an LLM
- Quarantine the file for review
- Downgrade the agent's trust level for the rest of the session
- Trigger a second-pass review with a different model

None of these responses are implemented yet.

## No real LLM is connected

The sandbox uses a toy agent that reads files. There is no language model interpreting the file content or deciding what to do next. The agent does not "obey" hidden instructions because it does not understand them. It just reads and returns text.

This means the sandbox cannot currently test whether an LLM would actually follow a hidden instruction inside a file.

## No real secrets are used

All files, paths, and credentials in this project are fake. The sandbox does not protect real API keys, passwords, tokens, or personally identifiable information. The blocked path patterns and policy rules are illustrative, not operational.

## Not a production sandbox

This project is a research prototype. It is not designed to run in production, enforce real security policies, or replace existing security tools. The code is intentionally simple to make it easy to understand, modify, and extend for research purposes.

## No persistence or state management

The sandbox does not track state between runs. Each demo or test run starts fresh. There is no session history, no cumulative risk scoring, and no memory of past suspicious files.

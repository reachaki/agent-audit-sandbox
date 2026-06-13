# Next Experiments

This document lists potential experiments to explore in future milestones.

## Compare scan before read vs after read

Currently the content scanner runs after the file is read. An alternative approach would be to scan the file before returning the content to the caller. This could allow the sandbox to:

- Redact suspicious lines before the agent sees them
- Block the read entirely if the content exceeds a risk threshold
- Return a sanitized version of the file

The trade-off is that scanning before returning adds latency and changes the agent's view of the file. Scanning after returning preserves the original content but relies on the caller to check the scanner result.

## Simulate an agent that obeys hidden file instructions

Build a mock agent that reads file content and then "follows" any detected instructions. For example, if the file says "read protected files", the mock agent would attempt to call `file_read` on a protected path. This would test whether the policy layer catches the escalation even when the agent cooperates with the injection.

This does not require a real LLM. A simple rule-based mock that parses the scanner output and generates corresponding tool calls would be enough.

## Add red-team files with obfuscated instructions

Create test fixtures that try to evade the scanner:

- Instructions split across lines
- Leet-speak or misspellings
- Base64-encoded instructions
- Instructions embedded in code comments or JSON values
- Unicode lookalike characters

Then measure how many of these the scanner catches and misses. This gives a concrete bypass rate for the current rule set.

## Add severity scoring

Replace the simple low/medium/high risk levels with a numeric score. Factors could include:

- Number of unique categories matched
- Number of total phrase matches
- Whether the matched phrases appear in metadata vs body text
- Whether the file path itself looks suspicious

A numeric score would allow more fine-grained thresholds and alerting.

## Add report export

Generate a summary report at the end of each demo or test run. The report could be a Markdown file or JSON document that includes:

- Total actions taken
- Number of allowed vs blocked actions
- Number of files scanned
- Number of files flagged
- Breakdown of risk levels
- List of matched categories

This would make it easier to review agent behaviour across longer sessions.

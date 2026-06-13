# Methodology

The sandbox models agent actions as explicit tool requests.

Each request is checked through:
1. actor context
2. registered tool name
3. requested target
4. policy rules
5. audit logging

An action is either allowed or blocked. Every decision is written to an audit log so the agent behaviour can be reviewed later.

The first version focuses on file reading. Later milestones can add config-based policies, schema validation, more tool types, and simulated prompt injection attacks inside files.

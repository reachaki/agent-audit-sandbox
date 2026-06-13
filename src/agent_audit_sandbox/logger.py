import datetime
import json
import os

class AuditLogger:
    """
    Logs agent actions to a JSON Lines (JSONL) file.
    """
    def __init__(self, log_dir: str = "logs", log_filename: str = "audit.jsonl"):
        self.log_dir = os.path.abspath(log_dir)
        self.log_filepath = os.path.join(self.log_dir, log_filename)

    def log_action(
        self,
        actor: str = "toy-agent",
        action_type: str = "read_file",
        path: str = "",
        allowed: bool = False,
        reason: str = ""
    ):
        """
        Logs an action with timestamp, actor, type, path, decision, and reason.
        """
        # Ensure log directory exists locally
        os.makedirs(self.log_dir, exist_ok=True)

        # Resolve actor to a structured dictionary representation
        if hasattr(actor, "to_dict"):
            actor_data = actor.to_dict()
        elif isinstance(actor, dict):
            actor_data = actor
        else:
            actor_data = {
                "name": str(actor),
                "session_id": "default",
                "purpose": None,
                "metadata": {}
            }

        # Build log record structure
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "actor": actor_data,
            "action_type": action_type,
            "requested_path": path,
            "allowed": allowed,
            "reason": reason
        }

        # Append JSON record line to the log file
        with open(self.log_filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

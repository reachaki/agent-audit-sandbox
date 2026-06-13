import os

class ToyFileAgent:
    """
    A toy agent designed to read files from a configured path.
    """
    def __init__(self, allowed_dir, policy_checker=None, audit_logger=None):
        self.allowed_dir = os.path.abspath(allowed_dir)
        self.policy_checker = policy_checker
        self.audit_logger = audit_logger

    def read_file(self, file_path):
        """
        Reads and returns the content of the file if allowed.
        Fails safely if the file does not exist or if the policy blocks it.
        """
        # Construct path before resolving parent directory references
        target_path = os.path.join(self.allowed_dir, file_path)

        # Apply policy checking if configured
        if self.policy_checker:
            decision = self.policy_checker.check_read_action(target_path)
            # Resolve to absolute path for audit log and file reading
            resolved_path = os.path.abspath(target_path)
            if self.audit_logger:
                self.audit_logger.log_action(
                    actor="toy-agent",
                    action_type="read_file",
                    path=resolved_path,
                    allowed=decision.allowed,
                    reason=decision.reason
                )
            if not decision.allowed:
                raise PermissionError(f"Action blocked by policy: {decision.reason}")
        else:
            resolved_path = os.path.abspath(target_path)
            # Fallback basic check: ensure it is under allowed_dir
            if not resolved_path.startswith(self.allowed_dir):
                raise PermissionError("Access outside the allowed directory is blocked.")
        
        # Safely verify file existence and type
        if not os.path.exists(resolved_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        if os.path.isdir(resolved_path):
            raise IsADirectoryError(f"Path is a directory: {file_path}")

        with open(resolved_path, "r", encoding="utf-8") as f:
            return f.read()

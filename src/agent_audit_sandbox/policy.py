import os

class PolicyDecision:
    """
    Represents the result of a policy evaluation.
    """
    def __init__(self, allowed: bool, reason: str):
        self.allowed = allowed
        self.reason = reason


class PolicyChecker:
    """
    Enforces directory boundaries and blocks directory traversal attempts.
    """
    def __init__(self, allowed_dir: str):
        self.allowed_dir = os.path.abspath(allowed_dir)

    def check_action(self, action_type: str, **kwargs) -> PolicyDecision:
        """
        Validates action safety based on its type and parameters.
        """
        if action_type == "file_read":
            path = kwargs.get("path")
            if not path:
                return PolicyDecision(
                    allowed=False,
                    reason="Access denied: Missing required 'path' argument for 'file_read'."
                )

            # Normalize backslashes to forward slashes for unified cross-platform checking
            normalized_input = path.replace("\\", "/")
            path_parts = normalized_input.split("/")

            # Block any path containing ".." as traversal
            if ".." in path_parts:
                return PolicyDecision(
                    allowed=False,
                    reason="Path traversal attempt detected containing parent directory references (..)."
                )

            # Resolve to absolute path relative to allowed_dir if relative
            if not os.path.isabs(path):
                target_path = os.path.join(self.allowed_dir, path)
            else:
                target_path = path

            abs_path = os.path.abspath(target_path)

            # Check if the absolute path resides within the allowed base directory
            try:
                common = os.path.commonpath([self.allowed_dir, abs_path])
                if common != self.allowed_dir:
                    return PolicyDecision(
                        allowed=False,
                        reason=f"Access denied: path lies outside the allowed directory '{self.allowed_dir}'."
                    )
            except ValueError:
                return PolicyDecision(
                    allowed=False,
                    reason="Access denied: path is invalid or has a mismatched root."
                )

            return PolicyDecision(
                allowed=True,
                reason="Access allowed: path is within safe boundaries."
            )
        else:
            return PolicyDecision(
                allowed=False,
                reason=f"Blocked: Action type '{action_type}' is unknown and blocked by default."
            )

    def check_read_action(self, path: str) -> PolicyDecision:
        """
        Checks if the requested file path is safe to read.
        """
        return self.check_action("file_read", path=path)

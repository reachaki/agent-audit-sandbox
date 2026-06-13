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

    def check_read_action(self, path: str) -> PolicyDecision:
        """
        Checks if the requested file path is safe to read.
        """
        # Normalize backslashes to forward slashes for unified cross-platform checking
        normalized_input = path.replace("\\", "/")
        path_parts = normalized_input.split("/")

        # Block any path containing ".." as traversal
        if ".." in path_parts:
            return PolicyDecision(
                allowed=False,
                reason="Path traversal attempt detected containing parent directory references (..)."
            )

        # Resolve to absolute path to handle symlinks, relative references, etc.
        abs_path = os.path.abspath(path)

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

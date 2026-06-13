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
    Enforces directory boundaries, blocks traversal, and enforces tool and path configuration.
    """
    def __init__(self, allowed_dir: str = None, config: dict = None):
        self.config = config or {}
        
        # Retrieve tools lists from configuration
        self.allowed_tools = self.config.get("allowed_tools", ["file_read"])
        self.blocked_tools = self.config.get("blocked_tools", [])
        self.blocked_path_patterns = self.config.get("blocked_path_patterns", [])
        
        # Retrieve allowed directories list
        allowed_dirs = self.config.get("allowed_directories", [])
        if not allowed_dirs and allowed_dir:
            allowed_dirs = [allowed_dir]
            
        self.allowed_directories = [os.path.abspath(d) for d in allowed_dirs]
        self.allowed_dir = self.allowed_directories[0] if self.allowed_directories else None

    def check_action(self, action_type: str, **kwargs) -> PolicyDecision:
        """
        Validates action safety based on its type and configured policy rules.
        """
        # 1. Enforce blocked tools check
        if action_type in self.blocked_tools:
            return PolicyDecision(
                allowed=False,
                reason=f"Access denied: Tool '{action_type}' is explicitly blocked by policy config."
            )

        # 2. Enforce allowed tools check
        if action_type not in self.allowed_tools:
            return PolicyDecision(
                allowed=False,
                reason=f"Blocked: Action type '{action_type}' is unknown and blocked by default."
            )

        # 3. Enforce tool-specific parameter policy rules
        if action_type == "file_read":
            path = kwargs.get("path")
            if not path:
                return PolicyDecision(
                    allowed=False,
                    reason="Access denied: Missing required 'path' argument for 'file_read'."
                )

            # Normalize slashes for unified cross-platform traversal check
            normalized_input = path.replace("\\", "/")
            path_parts = normalized_input.split("/")

            # Block path containing ".." as traversal
            if ".." in path_parts:
                return PolicyDecision(
                    allowed=False,
                    reason="Path traversal attempt detected containing parent directory references (..)."
                )

            # Resolve target path relative to first allowed_dir if relative
            if not os.path.isabs(path) and self.allowed_dir:
                target_path = os.path.join(self.allowed_dir, path)
            else:
                target_path = path

            abs_path = os.path.abspath(target_path)

            # 4. Enforce blocked path patterns check
            for pattern in self.blocked_path_patterns:
                if pattern in path or pattern in abs_path:
                    return PolicyDecision(
                        allowed=False,
                        reason=f"Access denied: path contains blocked pattern '{pattern}'."
                    )

            # 5. Check if target lies within at least one allowed directory
            allowed = False
            for allowed_dir in self.allowed_directories:
                try:
                    common = os.path.commonpath([allowed_dir, abs_path])
                    if common == allowed_dir:
                        allowed = True
                        break
                except ValueError:
                    continue

            if not allowed:
                return PolicyDecision(
                    allowed=False,
                    reason="Access denied: path lies outside the allowed directory."
                )

            return PolicyDecision(
                allowed=True,
                reason="Access allowed: path is within safe boundaries."
            )

        return PolicyDecision(
            allowed=True,
            reason=f"Access allowed: Action type '{action_type}' is permitted under active policy."
        )

    def check_read_action(self, path: str) -> PolicyDecision:
        """
        Checks if the requested file path is safe to read.
        """
        return self.check_action("file_read", path=path)

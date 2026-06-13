import os

class ToyFileAgent:
    """
    A toy agent designed to execute registered tools and read files safely.
    """
    def __init__(self, allowed_dir, policy_checker=None, audit_logger=None, tool_registry=None):
        self.allowed_dir = os.path.abspath(allowed_dir)
        self.policy_checker = policy_checker
        self.audit_logger = audit_logger
        
        if tool_registry is None:
            from agent_audit_sandbox.registry import ToolRegistry
            self.tool_registry = ToolRegistry()
            # Register the default file_read tool
            self.tool_registry.register(
                "file_read",
                self._physical_file_read,
                "Reads file content safely from the allowed directory."
            )
        else:
            self.tool_registry = tool_registry

    def _physical_file_read(self, path: str):
        """
        The underlying execution method for reading files.
        Called after policy validation.
        """
        resolved_path = os.path.abspath(os.path.join(self.allowed_dir, path))
        if not os.path.exists(resolved_path):
            raise FileNotFoundError(f"File not found: {path}")
            
        if os.path.isdir(resolved_path):
            raise IsADirectoryError(f"Path is a directory: {path}")

        with open(resolved_path, "r", encoding="utf-8") as f:
            return f.read()

    def execute_tool(self, tool_name: str, actor_context=None, **kwargs):
        """
        Executes a registered tool after checking policy and logging the action.
        """
        actor_log = actor_context or "toy-agent"
        requested_path = kwargs.get("path", "")

        # 1. Verify tool registration
        if not self.tool_registry.has_tool(tool_name):
            reason = f"Blocked: Tool '{tool_name}' is not registered in the system."
            if self.audit_logger:
                self.audit_logger.log_action(
                    actor=actor_log,
                    action_type=tool_name,
                    path=requested_path,
                    allowed=False,
                    reason=reason
                )
            raise PermissionError(reason)

        # 2. Enforce policy check
        if self.policy_checker:
            if hasattr(self.policy_checker, "check_action"):
                decision = self.policy_checker.check_action(tool_name, **kwargs)
            else:
                # Compatibility fallback for older policy checkers
                if tool_name == "file_read" and "path" in kwargs:
                    decision = self.policy_checker.check_read_action(kwargs["path"])
                else:
                    from agent_audit_sandbox.policy import PolicyDecision
                    decision = PolicyDecision(
                        allowed=False,
                        reason=f"Blocked: Action '{tool_name}' not supported by policy checker."
                    )

            if self.audit_logger:
                # Log using the absolute path if available for file reads
                log_path = requested_path
                if tool_name == "file_read":
                    log_path = os.path.abspath(os.path.join(self.allowed_dir, requested_path))
                self.audit_logger.log_action(
                    actor=actor_log,
                    action_type=tool_name,
                    path=log_path,
                    allowed=decision.allowed,
                    reason=decision.reason
                )

            if not decision.allowed:
                raise PermissionError(f"Action blocked by policy: {decision.reason}")
        else:
            # Basic fallback check if no policy checker is present
            if tool_name == "file_read":
                resolved_path = os.path.abspath(os.path.join(self.allowed_dir, requested_path))
                if not resolved_path.startswith(self.allowed_dir):
                    raise PermissionError("Access outside the allowed directory is blocked.")

        # 3. Execute the tool
        return self.tool_registry.call_tool(tool_name, **kwargs)

    def read_file(self, file_path, actor_context=None):
        """
        Reads and returns the content of the file if allowed.
        Fails safely if the file does not exist or if the policy blocks it.
        """
        return self.execute_tool("file_read", actor_context=actor_context, path=file_path)


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

    def execute_tool(self, tool_name: str, actor_context=None, scan_content: bool = False, **kwargs):
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

        # 1.5. Validate tool arguments
        try:
            from agent_audit_sandbox.validation import validate_tool_args
            validate_tool_args(tool_name, kwargs)
        except (ValueError, TypeError) as e:
            reason = f"Blocked: Argument validation failed: {e}"
            if self.audit_logger:
                log_path = requested_path if isinstance(requested_path, str) else ""
                self.audit_logger.log_action(
                    actor=actor_log,
                    action_type=tool_name,
                    path=log_path,
                    allowed=False,
                    reason=reason
                )
            raise

        # Resolve log path for file_read
        log_path = requested_path
        if tool_name == "file_read" and isinstance(requested_path, str):
            log_path = os.path.abspath(os.path.join(self.allowed_dir, requested_path))

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

            if not decision.allowed:
                if self.audit_logger:
                    self.audit_logger.log_action(
                        actor=actor_log,
                        action_type=tool_name,
                        path=log_path,
                        allowed=False,
                        reason=decision.reason
                    )
                raise PermissionError(f"Action blocked by policy: {decision.reason}")
        else:
            # Basic fallback check if no policy checker is present
            if tool_name == "file_read":
                resolved_path = os.path.abspath(os.path.join(self.allowed_dir, requested_path))
                if not resolved_path.startswith(self.allowed_dir):
                    raise PermissionError("Access outside the allowed directory is blocked.")
            decision = None

        # 3. Execute the tool
        try:
            result = self.tool_registry.call_tool(tool_name, **kwargs)
        except Exception:
            # Log failure at execution level
            if self.audit_logger:
                reason = decision.reason if decision else "Access allowed (no policy checker)."
                self.audit_logger.log_action(
                    actor=actor_log,
                    action_type=tool_name,
                    path=log_path,
                    allowed=True,
                    reason=reason
                )
            raise

        # 4. Optional content scanning
        scanner_result = None
        if tool_name == "file_read" and scan_content:
            from agent_audit_sandbox.scanner import FileContentScanner
            scanner = FileContentScanner()
            scan_res = scanner.scan(result, log_path)
            scanner_result = scan_res.to_dict()

        # Log successful execution with optional scanner result
        if self.audit_logger:
            reason = decision.reason if decision else "Access allowed (no policy checker)."
            self.audit_logger.log_action(
                actor=actor_log,
                action_type=tool_name,
                path=log_path,
                allowed=True,
                reason=reason,
                scanner_result=scanner_result
            )

        return result

    def read_file(self, file_path, actor_context=None, scan_content: bool = False):
        """
        Reads and returns the content of the file if allowed.
        Fails safely if the file does not exist or if the policy blocks it.
        """
        return self.execute_tool("file_read", actor_context=actor_context, scan_content=scan_content, path=file_path)


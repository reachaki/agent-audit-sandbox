class ToolRegistry:
    """
    A registry to manage tools available to agents in the sandbox.
    """
    def __init__(self):
        self._tools = {}

    def register(self, name: str, func, description: str = ""):
        """
        Registers a tool callable with a name and description.
        """
        self._tools[name] = {
            "name": name,
            "func": func,
            "description": description
        }

    def has_tool(self, name: str) -> bool:
        """
        Checks if a tool name is registered.
        """
        return name in self._tools

    def get_tool(self, name: str) -> dict:
        """
        Returns registered tool details or None.
        """
        return self._tools.get(name)

    def call_tool(self, name: str, *args, **kwargs):
        """
        Invokes the registered tool callable.
        """
        if not self.has_tool(name):
            raise KeyError(f"Tool '{name}' is not registered.")
        return self._tools[name]["func"](*args, **kwargs)

def validate_tool_args(tool_name: str, args_dict: dict):
    """
    Validates arguments for a tool based on simple validation rules.
    """
    if tool_name == "file_read":
        if "path" not in args_dict:
            raise ValueError("Missing required argument: 'path'")
        path = args_dict["path"]
        if not isinstance(path, str):
            raise TypeError("Argument 'path' must be a string")
        if len(path.strip()) == 0:
            raise ValueError("Argument 'path' cannot be empty")

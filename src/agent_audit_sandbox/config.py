import json
import os

class PolicyConfigError(ValueError):
    """
    Raised when loading or validating policy configuration fails.
    """
    pass


def load_policy_config(config_path: str) -> dict:
    """
    Loads and validates the policy configuration file.
    """
    if not os.path.exists(config_path):
        raise PolicyConfigError(f"Config file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise PolicyConfigError(f"Invalid JSON in config file: {e}")

    if not isinstance(config, dict):
        raise PolicyConfigError("Config must be a JSON object.")

    required_fields = {
        "allowed_directories": list,
        "allowed_tools": list,
        "blocked_tools": list,
        "blocked_path_patterns": list
    }

    for field, field_type in required_fields.items():
        if field not in config:
            raise PolicyConfigError(f"Missing required config field: '{field}'")
        if not isinstance(config[field], field_type):
            raise PolicyConfigError(
                f"Config field '{field}' must be of type {field_type.__name__}"
            )
        
        # Verify all elements inside list are strings
        for item in config[field]:
            if not isinstance(item, str):
                raise PolicyConfigError(
                    f"All elements in config field '{field}' must be strings."
                )

    return config

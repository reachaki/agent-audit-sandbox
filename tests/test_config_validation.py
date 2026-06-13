import os
import json
import pytest
from agent_audit_sandbox import (
    ToyFileAgent,
    PolicyChecker,
    AuditLogger,
    load_policy_config,
    PolicyConfigError,
    validate_tool_args
)

def test_valid_config_loading(tmp_path):
    config_file = tmp_path / "valid_config.json"
    config_data = {
        "allowed_directories": ["/tmp/allowed"],
        "allowed_tools": ["file_read", "network_check"],
        "blocked_tools": ["execute_command"],
        "blocked_path_patterns": ["secret"]
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")
    
    loaded = load_policy_config(str(config_file))
    assert loaded == config_data


def test_invalid_config_loading(tmp_path):
    # Non-existent file
    with pytest.raises(PolicyConfigError) as exc:
        load_policy_config(str(tmp_path / "nonexistent.json"))
    assert "Config file not found" in str(exc.value)

    # Invalid JSON
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{bad json", encoding="utf-8")
    with pytest.raises(PolicyConfigError) as exc:
        load_policy_config(str(bad_json))
    assert "Invalid JSON" in str(exc.value)

    # Missing field
    missing_field = tmp_path / "missing.json"
    missing_field.write_text(json.dumps({
        "allowed_directories": [],
        "allowed_tools": []
    }), encoding="utf-8")
    with pytest.raises(PolicyConfigError) as exc:
        load_policy_config(str(missing_field))
    assert "Missing required config field" in str(exc.value)

    # Wrong field type
    wrong_type = tmp_path / "wrong_type.json"
    wrong_type.write_text(json.dumps({
        "allowed_directories": "not a list",
        "allowed_tools": [],
        "blocked_tools": [],
        "blocked_path_patterns": []
    }), encoding="utf-8")
    with pytest.raises(PolicyConfigError) as exc:
        load_policy_config(str(wrong_type))
    assert "must be of type list" in str(exc.value)

    # List containing non-string
    non_str = tmp_path / "non_str.json"
    non_str.write_text(json.dumps({
        "allowed_directories": [123],
        "allowed_tools": [],
        "blocked_tools": [],
        "blocked_path_patterns": []
    }), encoding="utf-8")
    with pytest.raises(PolicyConfigError) as exc:
        load_policy_config(str(non_str))
    assert "must be strings" in str(exc.value)


def test_file_read_schema_validation():
    # Missing path
    with pytest.raises(ValueError) as exc:
        validate_tool_args("file_read", {})
    assert "Missing required argument: 'path'" in str(exc.value)

    # Path not string
    with pytest.raises(TypeError) as exc:
        validate_tool_args("file_read", {"path": 123})
    assert "Argument 'path' must be a string" in str(exc.value)

    # Path empty string
    with pytest.raises(ValueError) as exc:
        validate_tool_args("file_read", {"path": "   "})
    assert "Argument 'path' cannot be empty" in str(exc.value)


def test_agent_logs_schema_validation_failures(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )

    with pytest.raises(ValueError):
        agent.read_file(" ")

    log_file = tmp_path / "logs" / "audit.jsonl"
    assert log_file.exists()
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
    assert len(log_entries) == 1
    assert log_entries[0]["allowed"] is False
    assert "Argument validation failed" in log_entries[0]["reason"]


def test_blocked_tool_from_config(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    config_data = {
        "allowed_directories": [str(allowed_dir)],
        "allowed_tools": ["file_read"],
        "blocked_tools": ["file_read"],
        "blocked_path_patterns": []
    }
    policy = PolicyChecker(config=config_data)
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )

    with pytest.raises(PermissionError) as exc:
        agent.read_file("test.txt")
    assert "is explicitly blocked by policy config" in str(exc.value)

    log_file = tmp_path / "logs" / "audit.jsonl"
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
    assert len(log_entries) == 1
    assert log_entries[0]["allowed"] is False
    assert "explicitly blocked" in log_entries[0]["reason"]


def test_blocked_path_patterns(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    config_data = {
        "allowed_directories": [str(allowed_dir)],
        "allowed_tools": ["file_read"],
        "blocked_tools": [],
        "blocked_path_patterns": ["restricted", "confidential"]
    }
    policy = PolicyChecker(config=config_data)
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )

    # Safe read
    test_file = allowed_dir / "public.txt"
    test_file.write_text("Hello", encoding="utf-8")
    assert agent.read_file("public.txt") == "Hello"

    # Blocked read containing pattern in target path name
    with pytest.raises(PermissionError) as exc:
        agent.read_file("restricted_info.txt")
    assert "contains blocked pattern 'restricted'" in str(exc.value)

    log_file = tmp_path / "logs" / "audit.jsonl"
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
    
    assert len(log_entries) == 2
    assert log_entries[0]["allowed"] is True
    assert log_entries[1]["allowed"] is False
    assert "contains blocked pattern" in log_entries[1]["reason"]

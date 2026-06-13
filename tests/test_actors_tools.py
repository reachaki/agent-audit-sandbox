import os
import json
import pytest
from agent_audit_sandbox import ToyFileAgent, PolicyChecker, AuditLogger, ActorContext, ToolRegistry

def test_actor_context_logging(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    test_file = allowed_dir / "test.txt"
    test_file.write_text("Hello Actors", encoding="utf-8")
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    ctx = ActorContext(
        name="Charlie",
        session_id="sess-charlie-777",
        purpose="verifying actor logging",
        metadata={"priority": "high"}
    )
    
    content = agent.read_file("test.txt", actor_context=ctx)
    assert content == "Hello Actors"
    
    # Verify log entry contains structured actor metadata
    log_file = tmp_path / "logs" / "audit.jsonl"
    assert log_file.exists()
    
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
        
    assert len(log_entries) == 1
    actor_data = log_entries[0]["actor"]
    assert isinstance(actor_data, dict)
    assert actor_data["name"] == "Charlie"
    assert actor_data["session_id"] == "sess-charlie-777"
    assert actor_data["purpose"] == "verifying actor logging"
    assert actor_data["metadata"] == {"priority": "high"}


def test_custom_tool_registration(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    registry = ToolRegistry()
    def custom_greeting(name: str):
        return f"Greetings, {name}!"
        
    registry.register("greet", custom_greeting, "Returns a greeting.")
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger,
        tool_registry=registry
    )
    
    # The policy checker blocks unknown tools by default
    with pytest.raises(PermissionError) as exc_info:
        agent.execute_tool("greet", name="Dave")
    assert "is unknown and blocked by default" in str(exc_info.value)
    
    # Verify the blocked action is logged
    log_file = tmp_path / "logs" / "audit.jsonl"
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
    assert len(log_entries) == 1
    assert log_entries[0]["action_type"] == "greet"
    assert log_entries[0]["allowed"] is False
    assert "blocked by default" in log_entries[0]["reason"]


def test_unknown_unregistered_tool_blocked(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    # Try calling a tool that is not in the registry
    with pytest.raises(PermissionError) as exc_info:
        agent.execute_tool("delete_system", actor_context="admin")
    assert "is not registered in the system" in str(exc_info.value)
    
    # Verify log entry is recorded as blocked
    log_file = tmp_path / "logs" / "audit.jsonl"
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
    assert len(log_entries) == 1
    assert log_entries[0]["action_type"] == "delete_system"
    assert log_entries[0]["allowed"] is False
    assert "not registered" in log_entries[0]["reason"]
    assert log_entries[0]["actor"]["name"] == "admin"


def test_action_policy_allowed_and_blocked(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    test_file = allowed_dir / "safe.txt"
    test_file.write_text("Safe data content", encoding="utf-8")
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    # Allowed read
    assert agent.execute_tool("file_read", path="safe.txt") == "Safe data content"
    
    # Blocked read outside boundary
    with pytest.raises(PermissionError):
        agent.execute_tool("file_read", path="../unsafe.txt")

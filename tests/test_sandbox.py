import os
import json
import pytest
from agent_audit_sandbox import ToyFileAgent, PolicyChecker, AuditLogger

def test_allowed_file_read(tmp_path):
    # Setup allowed directory and file
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    test_file = allowed_dir / "test.txt"
    test_file.write_text("Hello World", encoding="utf-8")
    
    # Initialize components
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    # Verify file can be read successfully
    content = agent.read_file("test.txt")
    assert content == "Hello World"
    
    # Verify audit log entry exists
    log_file = tmp_path / "logs" / "audit.jsonl"
    assert log_file.exists()
    
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
    
    assert len(log_entries) == 1
    entry = log_entries[0]
    assert entry["actor"] == "toy-agent"
    assert entry["action_type"] == "read_file"
    assert entry["allowed"] is True
    assert entry["requested_path"] == os.path.abspath(str(test_file))
    assert "within safe boundaries" in entry["reason"]


def test_missing_file(tmp_path):
    # Setup allowed directory
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    # Verify FileNotFoundError is raised
    with pytest.raises(FileNotFoundError):
        agent.read_file("nonexistent.txt")
        
    # Action was allowed by policy but failed at OS level
    log_file = tmp_path / "logs" / "audit.jsonl"
    assert log_file.exists()
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
        
    assert len(log_entries) == 1
    assert log_entries[0]["allowed"] is True


def test_blocked_unsafe_path(tmp_path):
    # Setup allowed and blocked directories
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    
    blocked_file = blocked_dir / "secret.txt"
    blocked_file.write_text("Secret Data", encoding="utf-8")
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    # Verify PermissionError is raised on out-of-bounds access
    with pytest.raises(PermissionError) as exc_info:
        agent.read_file(str(blocked_file))
    
    assert "lies outside the allowed directory" in str(exc_info.value)
    
    # Verify log entry is recorded as blocked
    log_file = tmp_path / "logs" / "audit.jsonl"
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
        
    assert len(log_entries) == 1
    entry = log_entries[0]
    assert entry["allowed"] is False
    assert "lies outside the allowed directory" in entry["reason"]


def test_path_traversal_attempt(tmp_path):
    # Setup allowed directory
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    
    policy = PolicyChecker(allowed_dir=str(allowed_dir))
    logger = AuditLogger(log_dir=str(tmp_path / "logs"))
    agent = ToyFileAgent(
        allowed_dir=str(allowed_dir),
        policy_checker=policy,
        audit_logger=logger
    )
    
    # Verify PermissionError is raised on explicit parent traversal reference
    with pytest.raises(PermissionError) as exc_info:
        agent.read_file("../blocked/secret.txt")
        
    assert "Path traversal attempt detected" in str(exc_info.value)
    
    # Verify log entry is recorded as blocked due to traversal
    log_file = tmp_path / "logs" / "audit.jsonl"
    with open(log_file, "r", encoding="utf-8") as f:
        log_entries = [json.loads(line) for line in f]
        
    assert len(log_entries) == 1
    entry = log_entries[0]
    assert entry["allowed"] is False
    assert "Path traversal attempt detected" in entry["reason"]

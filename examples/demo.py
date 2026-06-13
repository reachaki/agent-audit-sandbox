import os
import shutil
from agent_audit_sandbox import ToyFileAgent, PolicyChecker, AuditLogger, ActorContext

def main():
    # Setup directories for demonstration
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(base_dir)
    allowed_dir = os.path.join(base_dir, "demo_sandbox_allowed")
    blocked_dir = os.path.join(base_dir, "demo_sandbox_blocked")

    os.makedirs(allowed_dir, exist_ok=True)
    os.makedirs(blocked_dir, exist_ok=True)

    # Copy malicious and normal file fixtures to allowed_dir
    fixtures_src_dir = os.path.join(project_root, "data", "fixtures")
    for filename in ["normal_report.txt", "injected_report.txt", "hidden_instruction_report.txt"]:
        src_path = os.path.join(fixtures_src_dir, filename)
        dest_path = os.path.join(allowed_dir, filename)
        shutil.copy(src_path, dest_path)

    # Create dummy blocked file for testing policy behavior
    blocked_file_path = os.path.join(blocked_dir, "blocked_file.txt")
    with open(blocked_file_path, "w", encoding="utf-8") as f:
        f.write("This is sensitive file content outside the allowed sandbox.")

    print("=== Sandbox Demo Setup ===")
    print(f"Allowed directory: {allowed_dir}")
    print(f"Blocked directory: {blocked_dir}")
    print("==========================\n")

    # Initialize components
    policy = PolicyChecker(allowed_dir=allowed_dir)
    logger = AuditLogger(log_dir=os.path.join(project_root, "logs"))
    agent = ToyFileAgent(
        allowed_dir=allowed_dir,
        policy_checker=policy,
        audit_logger=logger
    )

    # Define dynamic actor contexts
    alice_ctx = ActorContext(
        name="Alice",
        session_id="session-alice-101",
        purpose="data inspection",
        metadata={"user_role": "analyst"}
    )
    
    bob_ctx = ActorContext(
        name="Bob",
        session_id="session-bob-202",
        purpose="scanning directory files",
        metadata={"user_role": "auditor"}
    )

    # Scenario 1: Allowed normal file read with scan_content=True
    print("Scenario 1: Reading normal report with scanning enabled (Actor: Alice)...")
    try:
        content = agent.read_file("normal_report.txt", actor_context=alice_ctx, scan_content=True)
        print(f"Success! Content: {content.strip()}")
    except Exception as e:
        print(f"Failed unexpectedly: {e}")
    print()

    # Scenario 2: Reading report containing prompt injection with scan_content=True
    print("Scenario 2: Reading report with prompt injection (Actor: Alice)...")
    try:
        content = agent.read_file("injected_report.txt", actor_context=alice_ctx, scan_content=True)
        print(f"Success! Content: {content.strip()}")
    except Exception as e:
        print(f"Failed unexpectedly: {e}")
    print()

    # Scenario 3: Reading report containing hidden instructions with scan_content=True
    print("Scenario 3: Reading report containing hidden instructions (Actor: Alice)...")
    try:
        content = agent.read_file("hidden_instruction_report.txt", actor_context=alice_ctx, scan_content=True)
        print(f"Success! Content: {content.strip()}")
    except Exception as e:
        print(f"Failed unexpectedly: {e}")
    print()

    # Scenario 4: Blocked file read (outside allowed directory) by Bob
    relative_blocked_path = os.path.relpath(blocked_file_path, allowed_dir)
    print(f"Scenario 4: Reading file outside allowed directory (Actor: Bob, Path: {relative_blocked_path})...")
    try:
        agent.read_file(relative_blocked_path, actor_context=bob_ctx, scan_content=True)
    except Exception as e:
        print(f"Result: Blocked safely by policy checker before scanning. Error: {e}")
    print()

    # Scenario 5: Blocked unknown tool (network_connect)
    print("Scenario 5: Attempting to call an unregistered tool (network_connect)...")
    try:
        agent.execute_tool("network_connect", actor_context=alice_ctx, host="example.com")
    except Exception as e:
        print(f"Result: Blocked safely as expected. Error: {e}")
    print()

    # Clean up temporary test files in the allowed/blocked dirs
    try:
        shutil.rmtree(allowed_dir)
        shutil.rmtree(blocked_dir)
    except Exception:
        pass

    # Show the generated audit logs showing actor, decision, and scanner results
    print("=== Audit Logs ===")
    print(f"Audit log written to: {logger.log_filepath}")
    print("Latest log entries (showing scanner results for read actions):")
    if os.path.exists(logger.log_filepath):
        with open(logger.log_filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            # Show the last 5 logs representing this demo run
            for line in lines[-5:]:
                print(line.strip())
    print("==================")

if __name__ == "__main__":
    main()

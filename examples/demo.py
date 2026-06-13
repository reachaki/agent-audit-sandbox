import os
import shutil
from agent_audit_sandbox import ToyFileAgent, PolicyChecker, AuditLogger

def main():
    # Setup directories for demonstration
    base_dir = os.path.dirname(os.path.abspath(__file__))
    allowed_dir = os.path.join(base_dir, "demo_sandbox_allowed")
    blocked_dir = os.path.join(base_dir, "demo_sandbox_blocked")

    os.makedirs(allowed_dir, exist_ok=True)
    os.makedirs(blocked_dir, exist_ok=True)

    # Create dummy files for testing policy behavior
    allowed_file_path = os.path.join(allowed_dir, "allowed_file.txt")
    blocked_file_path = os.path.join(blocked_dir, "blocked_file.txt")

    with open(allowed_file_path, "w", encoding="utf-8") as f:
        f.write("This is allowed file content within the sandbox boundaries.")

    with open(blocked_file_path, "w", encoding="utf-8") as f:
        f.write("This is sensitive file content outside the allowed sandbox.")

    print("=== Sandbox Demo Setup ===")
    print(f"Allowed directory: {allowed_dir}")
    print(f"Blocked directory: {blocked_dir}")
    print("==========================\n")

    # Initialize components
    policy = PolicyChecker(allowed_dir=allowed_dir)
    root_dir = os.path.dirname(base_dir)
    logger = AuditLogger(log_dir=os.path.join(root_dir, "logs"))
    agent = ToyFileAgent(
        allowed_dir=allowed_dir,
        policy_checker=policy,
        audit_logger=logger
    )

    # Scenario 1: Allowed file read
    print("Scenario 1: Reading allowed file...")
    try:
        content = agent.read_file("allowed_file.txt")
        print(f"Success! Content: {content}")
    except Exception as e:
        print(f"Failed unexpectedly: {e}")
    print()

    # Scenario 2: Blocked file read (outside allowed directory)
    relative_blocked_path = os.path.relpath(blocked_file_path, allowed_dir)
    print(f"Scenario 2: Reading file outside allowed directory ({relative_blocked_path})...")
    try:
        agent.read_file(relative_blocked_path)
    except Exception as e:
        print(f"Result: Blocked safely as expected. Error: {e}")
    print()

    # Scenario 3: Path traversal attempt
    traversal_path = "allowed_file.txt/../../demo_sandbox_blocked/blocked_file.txt"
    print(f"Scenario 3: Reading file via explicit path traversal ({traversal_path})...")
    try:
        agent.read_file(traversal_path)
    except Exception as e:
        print(f"Result: Blocked safely as expected. Error: {e}")
    print()

    # Scenario 4: Missing allowed file
    print("Scenario 4: Reading a missing file inside allowed directory...")
    try:
        agent.read_file("nonexistent.txt")
    except Exception as e:
        print(f"Result: Failed safely with file not found error. Error: {e}")
    print()

    # Clean up temporary test files
    try:
        shutil.rmtree(allowed_dir)
        shutil.rmtree(blocked_dir)
    except Exception:
        pass

    # Show the generated audit logs
    print("=== Audit Logs ===")
    print(f"Audit log written to: {logger.log_filepath}")
    print("Latest log entries:")
    if os.path.exists(logger.log_filepath):
        with open(logger.log_filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[-4:]:
                print(line.strip())
    print("==================")

if __name__ == "__main__":
    main()

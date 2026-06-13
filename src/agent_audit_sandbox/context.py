class ActorContext:
    """
    Represents the context of the actor executing actions in the sandbox.
    """
    def __init__(self, name: str, session_id: str, purpose: str = None, metadata: dict = None):
        self.name = name
        self.session_id = session_id
        self.purpose = purpose
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        """
        Serializes the context into a dictionary format.
        """
        return {
            "name": self.name,
            "session_id": self.session_id,
            "purpose": self.purpose,
            "metadata": self.metadata
        }

import os

class ScannerResult:
    """
    Represents the result of a file prompt injection content scan.
    """
    def __init__(
        self,
        detected: bool,
        matched_phrases: list,
        risk_level: str,
        explanation: str,
        source_file_path: str
    ):
        self.detected = detected
        self.matched_phrases = matched_phrases
        self.risk_level = risk_level
        self.explanation = explanation
        self.source_file_path = source_file_path

    def to_dict(self) -> dict:
        """
        Serializes the scanner result into a dictionary format.
        """
        return {
            "detected": self.detected,
            "matched_phrases": self.matched_phrases,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "source_file_path": self.source_file_path
        }


class FileContentScanner:
    """
    Checks file contents for potential prompt injection attempts and malicious instructions.
    """
    def __init__(self, rules: list = None):
        # Default rules to look for
        self.rules = rules or [
            {"phrase": "ignore previous instructions", "label": "ignore previous instructions"},
            {"phrase": "ignore all previous instructions", "label": "ignore previous instructions"},
            {"phrase": "override instructions", "label": "ignore previous instructions"},
            {"phrase": "reveal secrets", "label": "reveal secrets"},
            {"phrase": "show secrets", "label": "reveal secrets"},
            {"phrase": "disclose credentials", "label": "reveal secrets"},
            {"phrase": "read protected files", "label": "read protected files"},
            {"phrase": "read restricted files", "label": "read protected files"},
            {"phrase": "access protected files", "label": "read protected files"},
            {"phrase": "bypass policy", "label": "bypass policy"},
            {"phrase": "disable policy", "label": "bypass policy"},
            {"phrase": "delete files", "label": "delete files"},
            {"phrase": "remove files", "label": "delete files"},
            {"phrase": "erase files", "label": "delete files"},
            {"phrase": "execute commands", "label": "execute commands"},
            {"phrase": "run command", "label": "execute commands"},
            {"phrase": "run shell", "label": "execute commands"},
            {"phrase": "execute shell", "label": "execute commands"},
        ]

    def scan(self, content: str, source_path: str) -> ScannerResult:
        """
        Scans file content against configured rules and returns a structured ScannerResult.
        """
        matched_phrases = []
        matched_labels = set()
        
        content_lower = content.lower()
        for rule in self.rules:
            phrase = rule["phrase"].lower()
            if phrase in content_lower:
                matched_phrases.append(rule["phrase"])
                matched_labels.add(rule["label"])

        detected = len(matched_phrases) > 0

        # Calculate risk level based on the number of unique categories matched
        unique_categories_count = len(matched_labels)
        if unique_categories_count == 0:
            risk_level = "low"
            explanation = "No suspicious instructions detected."
        elif unique_categories_count == 1:
            risk_level = "medium"
            explanation = f"Potential prompt injection detected. Matched category: {next(iter(matched_labels))}."
        else:
            categories_str = ", ".join(sorted(list(matched_labels)))
            risk_level = "high"
            explanation = f"High risk prompt injection detected. Matched multiple categories: {categories_str}."

        return ScannerResult(
            detected=detected,
            matched_phrases=sorted(list(set(matched_phrases))),
            risk_level=risk_level,
            explanation=explanation,
            source_file_path=os.path.abspath(source_path) if source_path else ""
        )

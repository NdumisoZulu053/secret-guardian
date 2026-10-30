import math
import re
from typing import List, Dict, Any

def calculate_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to detect high-randomness tokens."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def mask_secret(secret: str) -> str:
    """Masks secrets so sensitive values aren't exposed in API logs."""
    if len(secret) <= 6:
        return "*" * len(secret)
    return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]

class SecretScanner:
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def scan_content(self, content: str, filename: str = "snippet") -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # Skip comments or empty lines if needed
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                continue

            # 1. Regex Pattern Matching
            for rule in self.rules:
                matches = re.finditer(rule["pattern"], line)
                for match in matches:
                    matched_str = match.group(0)
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "file": filename,
                        "line": line_idx,
                        "matched_text": mask_secret(matched_str)
                    })

            # 2. Entropy Analysis for High-Randomness Strings (e.g., API Secret Keys)
            words = re.findall(r"['\"]([A-Za-z0-9_\-]{20,})['\"]", line)
            for word in words:
                entropy = calculate_entropy(word)
                if entropy > 4.5:  # High-entropy threshold typical for random secret keys
                    # Check if already captured by regex to avoid duplicate flags
                    if not any(f["line"] == line_idx and word in f["matched_text"] for f in findings):
                        findings.append({
                            "rule_id": "SEC-ENTROPY",
                            "rule_name": "High Entropy String Detected",
                            "severity": "MEDIUM",
                            "description": f"Potential unformatted secret found (Entropy score: {round(entropy, 2)}).",
                            "file": filename,
                            "line": line_idx,
                            "matched_text": mask_secret(word)
                        })

        return findings
"""
Machine Learning Payload Optimizer

ML-based payload optimization extending existing PayloadLearner.

Features:
- Train on historical successful payloads
- Predict probability of payload succeeding
- Generate optimized payloads using ML
- Feedback loop for continuous learning
"""

from typing import List, Dict, Optional
import numpy as np
from collections import Counter
import re
from engine.core.database import BountyHoundDB


class MLPayloadOptimizer:
    """ML-based payload optimization (extends existing PayloadLearner)"""

    def __init__(self, db: Optional[BountyHoundDB] = None):
        self.db = db if db else BountyHoundDB.get_instance()
        self.model = None
        self.model_trained = False

    def train_on_historical_data(self) -> Dict:
        """
        Train model on historical successful payloads

        Features:
        - Payload length
        - Character distribution
        - Encoding type
        - Special character count

        Target:
        - Success rate (finding accepted?)

        Returns:
            Training result dictionary
        """
        # Get historical payloads
        findings = []

        with self.db._get_connection() as conn:
            cursor = conn.execute("""
                SELECT poc as payload, vuln_type, status
                FROM findings
                WHERE poc IS NOT NULL
            """)
            findings = [dict(row) for row in cursor.fetchall()]

        if len(findings) < 10:
            return {
                "trained": False,
                "reason": "Insufficient training data (need 10+)",
                "samples": len(findings)
            }

        # Extract features and labels
        X = []
        y = []

        for finding in findings:
            payload = finding["payload"]
            status = finding["status"]

            features = self._extract_features(payload)
            X.append([
                features["length"],
                features["special_chars"],
                features["entropy"]
            ])

            # Label: 1 if accepted, 0 otherwise
            y.append(1 if status == "accepted" else 0)

        # Train model (simplified - using basic scoring)
        # In production, would use sklearn RandomForest or GradientBoosting
        self.model = {
            "training_data": (X, y),
            "mean_length": np.mean([x[0] for x in X]),
            "mean_special_chars": np.mean([x[1] for x in X]),
            "mean_entropy": np.mean([x[2] for x in X])
        }

        self.model_trained = True

        return {
            "trained": True,
            "samples": len(findings),
            "features": ["length", "special_chars", "entropy"]
        }

    def predict_payload_success(self, payload: str, vuln_type: str) -> float:
        """
        Predict probability of payload succeeding (0.0-1.0)

        Uses trained model to score payload

        Args:
            payload: Payload string
            vuln_type: Vulnerability type

        Returns:
            Confidence score (0.0-1.0)
        """
        if not self.model_trained:
            # Train if not already trained
            self.train_on_historical_data()

        if not self.model_trained:
            # Still not trained - return neutral score
            return 0.5

        # Extract features
        features = self._extract_features(payload)

        # Simple scoring based on similarity to successful payloads
        length_score = 1.0 - abs(features["length"] - self.model["mean_length"]) / 100
        special_chars_score = 1.0 - abs(features["special_chars"] - self.model["mean_special_chars"]) / 20
        entropy_score = 1.0 - abs(features["entropy"] - self.model["mean_entropy"])

        # Weighted average
        score = (length_score * 0.3 + special_chars_score * 0.3 + entropy_score * 0.4)

        # Clamp to [0, 1]
        return max(0.0, min(1.0, score))

    def generate_optimized_payloads(
        self,
        vuln_type: str,
        count: int = 10
    ) -> List[str]:
        """
        Generate optimized payloads using ML

        Strategy:
        1. Start with base payloads
        2. Mutate based on successful patterns
        3. Score using model
        4. Return top N payloads

        Args:
            vuln_type: Vulnerability type
            count: Number of payloads to generate

        Returns:
            List of optimized payloads
        """
        # Get base payloads for this vuln type
        base_payloads = self._get_base_payloads(vuln_type)

        if not base_payloads:
            return []

        # Generate mutations
        mutations = []

        for base in base_payloads:
            # Original
            mutations.append(base)

            # URL encoded
            mutations.append(self._url_encode(base))

            # HTML entity encoded
            mutations.append(self._html_encode(base))

            # Case variations
            mutations.append(base.upper())
            mutations.append(base.lower())

        # Score all mutations
        scored = []
        for payload in mutations:
            score = self.predict_payload_success(payload, vuln_type)
            scored.append((payload, score))

        # Sort by score (highest first)
        scored.sort(key=lambda x: x[1], reverse=True)

        # Return top N unique payloads
        seen = set()
        result = []

        for payload, score in scored:
            if payload not in seen and len(result) < count:
                result.append(payload)
                seen.add(payload)

        return result

    def feedback_loop(self, payload: str, vuln_type: str, succeeded: bool):
        """
        Update model with new result

        Stores result in training dataset for periodic retraining

        Args:
            payload: Payload that was tested
            vuln_type: Vulnerability type
            succeeded: Whether the payload succeeded
        """
        # Store in database for future training
        with self.db._get_connection() as conn:
            # Create feedback table if not exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payload_feedback (
                    id INTEGER PRIMARY KEY,
                    payload TEXT,
                    vuln_type TEXT,
                    succeeded INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                INSERT INTO payload_feedback (payload, vuln_type, succeeded)
                VALUES (?, ?, ?)
            """, (payload, vuln_type, 1 if succeeded else 0))

            conn.commit()

        # TODO: Implement periodic retraining (weekly)

    def _extract_features(self, payload: str) -> Dict:
        """Extract features from payload for ML"""
        return {
            "length": len(payload),
            "char_distribution": self._char_distribution(payload),
            "encoding_type": self._detect_encoding(payload),
            "special_chars": len(re.findall(r'[<>"\'&();]', payload)),
            "entropy": self._calculate_entropy(payload)
        }

    def _char_distribution(self, payload: str) -> Dict:
        """Calculate character distribution"""
        counter = Counter(payload)
        total = len(payload)
        return {char: count / total for char, count in counter.most_common(5)}

    def _detect_encoding(self, payload: str) -> str:
        """Detect if payload is encoded"""
        if "%3C" in payload or "%3E" in payload:
            return "url_encoded"
        elif "&lt;" in payload or "&gt;" in payload:
            return "html_encoded"
        elif "\\x" in payload:
            return "hex_encoded"
        else:
            return "plain"

    def _calculate_entropy(self, payload: str) -> float:
        """Calculate Shannon entropy of payload"""
        if not payload:
            return 0.0

        counter = Counter(payload)
        length = len(payload)

        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)

        # Normalize to [0, 1]
        max_entropy = np.log2(len(counter)) if len(counter) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0

    def _get_base_payloads(self, vuln_type: str) -> List[str]:
        """Get base payloads for vulnerability type"""
        # Would query database for successful payloads
        # Simplified implementation with hardcoded payloads

        payloads_db = {
            "XSS": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>"
            ],
            "SQLi": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--"
            ],
            "IDOR": [],  # No payloads for IDOR
        }

        return payloads_db.get(vuln_type, [])

    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(payload)

    def _html_encode(self, payload: str) -> str:
        """HTML entity encode payload"""
        import html
        return html.escape(payload)

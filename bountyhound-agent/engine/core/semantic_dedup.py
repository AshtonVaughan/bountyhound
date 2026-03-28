"""
Semantic Duplicate Detection

Uses TF-IDF and cosine similarity to detect semantically similar findings
that keyword matching would miss (e.g., "IDOR in user API" vs "unauthorized access to user endpoint").
"""

from typing import Dict, List
import re
from collections import Counter
import math


class SemanticDuplicateDetector:
    """Detect duplicate findings using semantic similarity (TF-IDF + cosine similarity)"""

    def __init__(self):
        # Common security terms that should be weighted appropriately
        self.vuln_terms = {
            "xss", "sqli", "idor", "csrf", "ssrf", "rce", "lfi", "xxe",
            "injection", "bypass", "unauthorized", "authentication", "authorization",
            "sql", "cross", "site", "scripting", "command", "remote", "code",
            "execution", "inclusion", "entity", "request", "forgery", "redirect",
            "traversal", "disclosure", "leak", "exposure", "misconfiguration"
        }

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words, handling security terminology"""
        text = text.lower()
        # Split on non-alphanumeric, but preserve common patterns
        tokens = re.findall(r'\b\w+\b', text)
        return [t for t in tokens if len(t) > 2]  # Filter very short words

    def _compute_tf(self, tokens: List[str]) -> Dict[str, float]:
        """Compute term frequency"""
        if not tokens:
            return {}

        counter = Counter(tokens)
        total = len(tokens)
        return {term: count / total for term, count in counter.items()}

    def _compute_idf(self, documents: List[List[str]]) -> Dict[str, float]:
        """Compute inverse document frequency"""
        if not documents:
            return {}

        doc_count = len(documents)
        idf = {}

        # Count documents containing each term
        for doc in documents:
            unique_terms = set(doc)
            for term in unique_terms:
                idf[term] = idf.get(term, 0) + 1

        # Calculate IDF
        return {term: math.log(doc_count / (count + 1)) for term, count in idf.items()}

    def _compute_tfidf(self, tokens: List[str], idf: Dict[str, float]) -> Dict[str, float]:
        """Compute TF-IDF vector"""
        tf = self._compute_tf(tokens)
        tfidf = {}

        for term, tf_val in tf.items():
            idf_val = idf.get(term, 0)
            # Boost vulnerability-specific terms
            boost = 1.5 if term in self.vuln_terms else 1.0
            tfidf[term] = tf_val * idf_val * boost

        return tfidf

    def _cosine_similarity(self, vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        """Compute cosine similarity between two TF-IDF vectors"""
        if not vec1 or not vec2:
            return 0.0

        # Get all terms
        all_terms = set(vec1.keys()) | set(vec2.keys())

        # Compute dot product and magnitudes
        dot_product = sum(vec1.get(term, 0) * vec2.get(term, 0) for term in all_terms)
        mag1 = math.sqrt(sum(v ** 2 for v in vec1.values()))
        mag2 = math.sqrt(sum(v ** 2 for v in vec2.values()))

        if mag1 == 0 or mag2 == 0:
            return 0.0

        return dot_product / (mag1 * mag2)

    def _jaccard_similarity(self, tokens1: List[str], tokens2: List[str]) -> float:
        """Compute Jaccard similarity between two token sets.
        Better than TF-IDF for small corpuses (< 20 documents)."""
        set1 = set(tokens1)
        set2 = set(tokens2)
        if not set1 and not set2:
            return 0.0
        intersection = set1 & set2
        union = set1 | set2
        # Boost score for shared vulnerability-specific terms
        vuln_overlap = intersection & self.vuln_terms
        base_score = len(intersection) / len(union)
        if vuln_overlap:
            boost = min(len(vuln_overlap) * 0.05, 0.15)
            return min(base_score + boost, 1.0)
        return base_score

    def compute_similarity(self, finding1: Dict, finding2: Dict) -> float:
        """
        Compute semantic similarity between two findings (0.0 to 1.0)

        Uses Jaccard similarity for pairwise comparisons (2 docs) where
        TF-IDF is unreliable, and TF-IDF+cosine for larger corpuses.

        Args:
            finding1: First finding with 'title' and 'description' keys
            finding2: Second finding with 'title' and 'description' keys

        Returns:
            Similarity score from 0.0 (completely different) to 1.0 (identical)
        """
        # Combine title and description for richer context
        text1 = f"{finding1.get('title', '')} {finding1.get('description', '')} {finding1.get('url', finding1.get('endpoint', ''))}"
        text2 = f"{finding2.get('title', '')} {finding2.get('description', '')} {finding2.get('url', finding2.get('endpoint', ''))}"

        # Hard guard: distinct URLs are never duplicates
        url1 = (finding1.get('url') or finding1.get('endpoint') or '').rstrip('/')
        url2 = (finding2.get('url') or finding2.get('endpoint') or '').rstrip('/')
        if url1 and url2 and url1 != url2:
            return 0.0

        tokens1 = self._tokenize(text1)
        tokens2 = self._tokenize(text2)

        # Handle empty inputs
        if not tokens1 or not tokens2:
            return 0.0

        # For pairwise (2-doc) comparisons, use Jaccard (TF-IDF is meaningless with 2 docs)
        return self._jaccard_similarity(tokens1, tokens2)

    def find_duplicates(
        self,
        new_finding: Dict,
        existing_findings: List[Dict],
        threshold: float = 0.75
    ) -> List[Dict]:
        """
        Find duplicate findings in database above similarity threshold.

        For small sets (< 20 findings), uses Jaccard similarity (pairwise).
        For larger sets, precomputes IDF once and uses TF-IDF + cosine.

        Args:
            new_finding: New finding to check (must have 'title' and 'description')
            existing_findings: List of existing findings to compare against
            threshold: Minimum similarity score to consider a duplicate (0.0-1.0)

        Returns:
            List of duplicate findings sorted by similarity score (highest first),
            each enhanced with a 'similarity_score' field
        """
        if not existing_findings:
            return []

        duplicates = []

        # For small sets, pairwise Jaccard is faster and more accurate
        if len(existing_findings) < 20:
            for existing in existing_findings:
                similarity = self.compute_similarity(new_finding, existing)
                if similarity >= threshold:
                    duplicates.append({**existing, "similarity_score": similarity})
        else:
            # For larger sets, precompute IDF once across all documents
            new_text = f"{new_finding.get('title', '')} {new_finding.get('description', '')}"
            new_tokens = self._tokenize(new_text)
            if not new_tokens:
                return []

            all_doc_tokens = [new_tokens]
            existing_tokens_list = []
            for ex in existing_findings:
                ex_text = f"{ex.get('title', '')} {ex.get('description', '')}"
                tokens = self._tokenize(ex_text)
                all_doc_tokens.append(tokens)
                existing_tokens_list.append(tokens)

            # Compute IDF once for the entire corpus
            idf = self._compute_idf(all_doc_tokens)
            new_tfidf = self._compute_tfidf(new_tokens, idf)

            for i, existing in enumerate(existing_findings):
                ex_tokens = existing_tokens_list[i]
                if not ex_tokens:
                    continue
                ex_tfidf = self._compute_tfidf(ex_tokens, idf)
                similarity = self._cosine_similarity(new_tfidf, ex_tfidf)
                if similarity >= threshold:
                    duplicates.append({**existing, "similarity_score": similarity})

        duplicates.sort(key=lambda x: x["similarity_score"], reverse=True)
        return duplicates

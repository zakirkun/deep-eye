"""TF-IDF retrieval index over CVE database for RAG.

Lazy-loads scikit-learn. Builds index from cve_entries + cve_technologies tables.
Persists as pickle. Used to ground AI payload generation and enrich vuln findings.
"""
import logging
import pickle
import sqlite3
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def _ensure_sklearn(interactive: bool = True) -> bool:
    """Try to import scikit-learn. Prompt for install if missing."""
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        pass

    if not interactive or not sys.stdin.isatty():
        return False

    try:
        answer = input("[!] RAG needs scikit-learn. Install now? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        return False

    if answer.strip().lower() not in ("y", "yes"):
        return False

    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "scikit-learn"],
            check=True,
        )
        import sklearn  # noqa: F401
        return True
    except (subprocess.CalledProcessError, ImportError):
        return False


class CVERagIndex:
    """TF-IDF retrieval index over CVE corpus."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        rag_config = config.get("rag", {}) if isinstance(config.get("rag"), dict) else {}

        configured_index = rag_config.get("index_path")
        if not configured_index:
            from utils.paths import rag_index_path
            configured_index = str(rag_index_path())
        self.index_path = Path(configured_index)
        self.top_k = int(rag_config.get("top_k", 5))
        self.min_score = float(rag_config.get("min_score", 0.15))
        self.auto_rebuild = bool(rag_config.get("auto_rebuild", True))

        self._vectorizer = None
        self._matrix = None
        self._cve_meta: List[Dict] = []
        self._loaded = False

    def is_loaded(self) -> bool:
        return self._loaded

    def is_stale(self, cve_db_path: str) -> bool:
        """Check if index is missing or older than CVE DB."""
        if not self.index_path.exists():
            return True
        if not Path(cve_db_path).exists():
            return False
        return self.index_path.stat().st_mtime < Path(cve_db_path).stat().st_mtime

    def load(self) -> bool:
        """Load index from pickle. Returns False on failure."""
        if not self.index_path.exists():
            return False
        if not _ensure_sklearn(interactive=False):
            logger.warning("RAG: scikit-learn not available; cannot load index")
            return False

        try:
            with open(self.index_path, "rb") as f:
                payload = pickle.load(f)
            self._vectorizer = payload["vectorizer"]
            self._matrix = payload["matrix"]
            self._cve_meta = payload["cve_meta"]
            self._loaded = True
            logger.info(
                f"RAG index loaded: {len(self._cve_meta)} CVEs from {self.index_path}"
            )
            return True
        except Exception as e:
            logger.error(f"RAG: failed to load index: {e}")
            self._loaded = False
            return False

    def save(self) -> None:
        """Persist index to pickle."""
        if self._vectorizer is None or self._matrix is None:
            raise RuntimeError("Cannot save unbuilt index")

        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "vectorizer": self._vectorizer,
            "matrix": self._matrix,
            "cve_meta": self._cve_meta,
            "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "doc_count": len(self._cve_meta),
        }
        with open(self.index_path, "wb") as f:
            pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
        logger.info(f"RAG index saved: {self.index_path} ({len(self._cve_meta)} CVEs)")

    def build(self, cve_db_path: str, interactive: bool = True) -> bool:
        """Build TF-IDF index from CVE SQLite database."""
        if not _ensure_sklearn(interactive=interactive):
            logger.warning("RAG: scikit-learn unavailable; skipping index build")
            return False

        if not Path(cve_db_path).exists():
            logger.warning(f"RAG: CVE DB not found at {cve_db_path}")
            return False

        from sklearn.feature_extraction.text import TfidfVectorizer

        rows = self._load_cve_rows(cve_db_path)
        if not rows:
            logger.info("RAG: CVE table empty; skipping build")
            return False

        documents = []
        meta = []
        for row in rows:
            cve_id, description, cvss_score, severity, technologies = row
            tech_str = " ".join(technologies) if technologies else ""
            doc = f"{description or ''} {tech_str}".strip()
            if not doc:
                continue
            documents.append(doc)
            meta.append(
                {
                    "cve_id": cve_id,
                    "description": description or "",
                    "cvss_score": cvss_score or 0.0,
                    "severity": severity or "",
                    "affected_products": technologies or [],
                }
            )

        if not documents:
            logger.info("RAG: no documents after filter; skipping build")
            return False

        vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            max_features=50000,
            sublinear_tf=True,
        )
        matrix = vectorizer.fit_transform(documents)

        self._vectorizer = vectorizer
        self._matrix = matrix
        self._cve_meta = meta
        self._loaded = True
        logger.info(f"RAG index built: {len(meta)} CVEs, vocab={len(vectorizer.vocabulary_)}")
        return True

    def _load_cve_rows(self, cve_db_path: str) -> List[tuple]:
        """Fetch CVE rows + aggregated technologies."""
        conn = sqlite3.connect(cve_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='cve_entries'"
            )
            if cursor.fetchone() is None:
                logger.warning("RAG: cve_entries table missing")
                return []

            cursor.execute(
                """
                SELECT c.cve_id, c.description, c.cvss_score, c.severity,
                       GROUP_CONCAT(t.technology, '|')
                FROM cve_entries c
                LEFT JOIN cve_technologies t ON c.cve_id = t.cve_id
                GROUP BY c.cve_id
                """
            )
            rows = []
            for cve_id, desc, cvss, sev, techs in cursor.fetchall():
                tech_list = techs.split("|") if techs else []
                rows.append((cve_id, desc, cvss, sev, tech_list))
            return rows
        finally:
            conn.close()

    def search(self, query: str, top_k: Optional[int] = None) -> List[Dict]:
        """Search index. Returns list of hits with score, filtered by min_score."""
        if not self._loaded or not query or not query.strip():
            return []

        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np

        k = top_k if top_k is not None else self.top_k
        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._matrix)[0]

        top_indices = np.argsort(-scores)[:k]

        results = []
        for idx in top_indices:
            score = float(scores[idx])
            if score < self.min_score:
                continue
            entry = dict(self._cve_meta[idx])
            entry["score"] = score
            results.append(entry)
        return results

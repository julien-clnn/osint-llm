"""Okapi BM25, hand-written (~40 lines): no extra dependency for a corpus of
~2k chunks. Lexical scoring matters for ATT&CK queries, which often carry
exact terms (DMARC, SPF, WHOIS, credentials, subdomain) that a dense model
may blur.
"""

from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")

# Very common English words carry no signal for technique matching; the
# list stays short on purpose (domain words like "may" are kept out too, as
# every ATT&CK description starts with "Adversaries may").
_STOPWORDS = frozenset(
    "a an and are as at be by can for from has have in is it its may of on or "
    "such that the their these this to used using was were which with adversaries".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


class BM25:
    """Okapi BM25 over a list of documents (k1=1.5, b=0.75, the usual defaults)."""

    def __init__(self, documents: list[str], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self._tfs = [Counter(tokenize(d)) for d in documents]
        self._lengths = np.array([sum(tf.values()) for tf in self._tfs], dtype=np.float32)
        self._avg_len = float(self._lengths.mean()) if len(self._lengths) else 0.0
        df: Counter[str] = Counter()
        for tf in self._tfs:
            df.update(tf.keys())
        n = len(documents)
        self._idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def scores(self, query: str) -> np.ndarray:
        out = np.zeros(len(self._tfs), dtype=np.float32)
        if not self._tfs:
            return out
        norm = self.k1 * (1 - self.b + self.b * self._lengths / (self._avg_len or 1.0))
        for term in set(tokenize(query)):
            idf = self._idf.get(term)
            if idf is None:
                continue
            tf = np.array([d.get(term, 0) for d in self._tfs], dtype=np.float32)
            out += idf * tf * (self.k1 + 1) / (tf + norm)
        return out

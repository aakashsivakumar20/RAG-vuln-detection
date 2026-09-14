"""
Repository Ingestion module.

Responsibility (per docs/chapter3_methodology.md, Module Description table):
  Clone and pre-filter a GitHub repo — shallow clone, exclude vendored/binary paths.

This module deliberately does NOT try to be clever about every possible repo
layout; it applies a conservative, documented filter list and reports exactly
what it kept/dropped and why, so results are auditable in a panel demo.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import time
from pathlib import Path

# Directories that are essentially never source we want to analyse.
VENDORED_DIR_NAMES = {
    "node_modules", "vendor", "venv", ".venv", "env", ".env",
    "dist", "build", "out", "target", ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "site-packages", "bower_components", ".next", ".nuxt",
}

# Extensions we currently know how to chunk meaningfully (Sec. 1.4 scope:
# Python + JS/TS first). Anything else is still listed but flagged
# "unsupported_language" rather than silently dropped.
SUPPORTED_SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}

# Extensions that are unambiguously not source code worth chunking.
BINARY_OR_NONSOURCE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
    ".pyc", ".class", ".jar", ".lock", ".map", ".min.js",
}

MAX_FILE_SIZE_BYTES = 300_000  # 300 KB — skip generated/huge files for the prototype


@dataclasses.dataclass
class IngestedFile:
    abs_path: str
    rel_path: str
    language: str
    size_bytes: int


@dataclasses.dataclass
class IngestionReport:
    repo_url: str
    local_path: str
    clone_seconds: float
    total_files_seen: int
    files_kept: list[IngestedFile]
    files_skipped_vendored: int
    files_skipped_binary_or_nonsource: int
    files_skipped_too_large: int
    files_skipped_unsupported_language: int

    def summary(self) -> str:
        return (
            f"Cloned {self.repo_url} in {self.clone_seconds:.1f}s. "
            f"Saw {self.total_files_seen} files total; kept {len(self.files_kept)} "
            f"source files for chunking. Skipped: {self.files_skipped_vendored} vendored, "
            f"{self.files_skipped_binary_or_nonsource} binary/non-source, "
            f"{self.files_skipped_too_large} too large (>{MAX_FILE_SIZE_BYTES} bytes), "
            f"{self.files_skipped_unsupported_language} unsupported-language (kept for future phases)."
        )


def _language_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".py":
        return "python"
    if ext in (".js", ".jsx"):
        return "javascript"
    if ext in (".ts", ".tsx"):
        return "typescript"
    return "other"


def clone_repository(repo_url: str, dest_dir: str, shallow: bool = True) -> float:
    """Shallow-clones repo_url into dest_dir. Returns elapsed seconds."""
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    args = ["git", "clone"]
    if shallow:
        args += ["--depth", "1"]
    args += [repo_url, dest_dir]
    start = time.time()
    result = subprocess.run(args, capture_output=True, text=True, timeout=300)
    elapsed = time.time() - start
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    return elapsed


def ingest_repository(repo_url: str, workdir: str) -> IngestionReport:
    """
    Clones repo_url under workdir and applies the pre-filter.
    Returns an IngestionReport describing exactly what was kept/skipped.
    """
    local_path = os.path.join(workdir, "_cloned_repo")
    clone_seconds = clone_repository(repo_url, local_path)

    total_seen = 0
    kept: list[IngestedFile] = []
    skipped_vendored = 0
    skipped_binary = 0
    skipped_large = 0
    skipped_unsupported = 0

    root = Path(local_path)
    for dirpath, dirnames, filenames in os.walk(root):
        # prune vendored dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in VENDORED_DIR_NAMES and not d.startswith(".")]
        for fname in filenames:
            total_seen += 1
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root))

            if any(part in VENDORED_DIR_NAMES for part in fpath.parts):
                skipped_vendored += 1
                continue

            ext = fpath.suffix.lower()
            if ext in BINARY_OR_NONSOURCE_EXTENSIONS or fname.endswith(".min.js"):
                skipped_binary += 1
                continue

            try:
                size = fpath.stat().st_size
            except OSError:
                continue

            if size > MAX_FILE_SIZE_BYTES:
                skipped_large += 1
                continue

            lang = _language_for(fpath)
            if ext not in SUPPORTED_SOURCE_EXTENSIONS:
                skipped_unsupported += 1
                continue

            kept.append(IngestedFile(
                abs_path=str(fpath), rel_path=rel, language=lang, size_bytes=size
            ))

    return IngestionReport(
        repo_url=repo_url,
        local_path=local_path,
        clone_seconds=clone_seconds,
        total_files_seen=total_seen,
        files_kept=kept,
        files_skipped_vendored=skipped_vendored,
        files_skipped_binary_or_nonsource=skipped_binary,
        files_skipped_too_large=skipped_large,
        files_skipped_unsupported_language=skipped_unsupported,
    )


if __name__ == "__main__":
    import sys
    import json

    url = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/OWASP/NodeGoat.git"
    report = ingest_repository(url, workdir="/tmp/rag_ingest_demo")
    print(report.summary())
    print(json.dumps([dataclasses.asdict(f) for f in report.files_kept[:5]], indent=2))

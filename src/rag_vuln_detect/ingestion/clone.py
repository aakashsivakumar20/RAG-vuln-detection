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
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

# Directories that are essentially never source we want to analyse.
VENDORED_DIR_NAMES = {
    "node_modules", "vendor", "venv", ".venv", "env", ".env",
    "dist", "build", "out", "target", ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "site-packages", "bower_components", ".next", ".nuxt",
    "obj", "third_party", "thirdparty", "3rdparty",
}

# Extensions we know how to chunk meaningfully, mapped to the language name used everywhere else
# (chunker, sink rules, prompts). Python / JavaScript / TypeScript were the original scope; the rest
# were added in release v2. Anything else is counted as "unsupported_language" rather than silently dropped.
LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".php": "php", ".phtml": "php", ".go": "go", ".cs": "csharp", ".rb": "ruby",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin",
}
SUPPORTED_SOURCE_EXTENSIONS = set(LANGUAGE_BY_EXTENSION)

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
            f"Fetched {self.repo_url} in {self.clone_seconds:.1f}s. "
            f"Saw {self.total_files_seen} files total; kept {len(self.files_kept)} "
            f"source files for chunking. Skipped: {self.files_skipped_vendored} vendored, "
            f"{self.files_skipped_binary_or_nonsource} binary/non-source, "
            f"{self.files_skipped_too_large} too large (>{MAX_FILE_SIZE_BYTES} bytes), "
            f"{self.files_skipped_unsupported_language} unsupported-language (kept for future phases)."
        )


_MINIFIED_NAME_RE = re.compile(r"[.\-_]min\.(js|css)$|\.bundle\.js$|\.chunk\.js$", re.I)


def _looks_minified(path: Path, fname: str) -> bool:
    """Minified / bundled third-party code (underscore-min.js, app.bundle.js, one-line megafiles) is not worth analysing."""
    if _MINIFIED_NAME_RE.search(fname):
        return True
    if path.suffix.lower() not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        return False
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
    except OSError:
        return False
    lines = head.count(b"\n") + 1
    return len(head) > 4000 and len(head) / lines > 300


def _language_for(path: Path) -> str:
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "other")


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


_GITHUB_RE = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", re.I)


def _safe_extract(zip_path: str, dest_dir: str) -> str:
    """Extract a zip refusing path traversal; returns the directory holding the project
    (GitHub archives wrap everything in a single top-level folder)."""
    os.makedirs(dest_dir, exist_ok=True)
    root = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            target = os.path.realpath(os.path.join(dest_dir, member.filename))
            if target != root and not target.startswith(root + os.sep):
                raise RuntimeError(f"unsafe path in archive: {member.filename}")
        zf.extractall(dest_dir)
    entries = [e for e in os.listdir(dest_dir) if not e.startswith("__MACOSX")]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest_dir, entries[0])):
        return os.path.join(dest_dir, entries[0])
    return dest_dir


def _download_github_zip(owner: str, repo: str, dest_dir: str) -> str:
    """Git-free fallback: GitHub serves the default branch as a zip archive."""
    url = f"https://github.com/{owner}/{repo}/archive/HEAD.zip"
    tmp = tempfile.mkdtemp(prefix="ghzip_")
    zpath = os.path.join(tmp, "repo.zip")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rag-vuln-detect/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(zpath, "wb") as out:
            shutil.copyfileobj(resp, out)
        return _safe_extract(zpath, dest_dir)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def acquire_source(source: str, workdir: str) -> tuple[str, float, str]:
    """Make `source` available as a local directory.

    source may be: an existing local directory (used in place, never modified), a .zip
    file, a GitHub URL (shallow `git clone` when git exists, otherwise a zip download),
    or any other git URL. Returns (local_path, seconds, kind).
    """
    t0 = time.time()
    if os.path.isdir(source):
        return os.path.abspath(source), 0.0, "local-directory"
    dest = os.path.join(workdir, "_cloned_repo")
    if os.path.exists(dest):
        shutil.rmtree(dest)
    if os.path.isfile(source) and source.lower().endswith(".zip"):
        return _safe_extract(source, dest), time.time() - t0, "zip-file"
    m = _GITHUB_RE.match(source.strip())
    if shutil.which("git"):
        try:
            clone_repository(source, dest)
            return dest, time.time() - t0, "git-clone"
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
            if not m:
                raise RuntimeError(str(e)) from e
    if m:
        return _download_github_zip(m.group(1), m.group(2), dest), time.time() - t0, "github-zip"
    raise RuntimeError(f"cannot read source '{source}': not a directory, .zip file, or git URL (and git is not installed)")


def ingest_repository(repo_url: str, workdir: str) -> IngestionReport:
    """
    Makes `repo_url` (git/GitHub URL, local directory or .zip) available under workdir
    and applies the pre-filter. Returns an IngestionReport describing exactly what
    was kept/skipped.
    """
    os.makedirs(workdir, exist_ok=True)
    local_path, clone_seconds, _kind = acquire_source(repo_url, workdir)

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

            if any(part in VENDORED_DIR_NAMES for part in Path(rel).parts):
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

            if _looks_minified(fpath, fname):
                skipped_binary += 1
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

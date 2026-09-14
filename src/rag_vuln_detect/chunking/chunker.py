"""
Parsing & Chunking module.

Responsibility (per docs/chapter3_methodology.md): split source into logical
function/class-level units using a language-aware parser (tree-sitter),
preserving semantic boundaries rather than fixed-length line windows.

Supported languages in this phase: Python, JavaScript, TypeScript (Sec. 1.4
scope). A conservative line-window fallback is used only if tree-sitter
fails to parse a file (e.g. a syntax error in the target repo), so ingestion
never silently drops a file.
"""

from __future__ import annotations

import dataclasses
import hashlib

from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript

_PY_LANGUAGE = Language(tspython.language())
_JS_LANGUAGE = Language(tsjavascript.language())
_TS_LANGUAGE = Language(tstypescript.language_typescript())

_PARSERS = {
    "python": Parser(_PY_LANGUAGE),
    "javascript": Parser(_JS_LANGUAGE),
    "typescript": Parser(_TS_LANGUAGE),
}

# Tree-sitter node types that count as a "logical chunk" per language.
_CHUNK_NODE_TYPES = {
    "python": {"function_definition", "class_definition"},
    "javascript": {
        "function_declaration", "class_declaration", "method_definition",
        "arrow_function", "function_expression",
    },
    "typescript": {
        "function_declaration", "class_declaration", "method_definition",
        "arrow_function", "function_expression", "interface_declaration",
    },
}

FALLBACK_WINDOW_LINES = 40  # only used if tree-sitter parsing fails outright


@dataclasses.dataclass
class CodeChunk:
    chunk_id: str
    repo_rel_path: str
    language: str
    kind: str          # "function", "class", "method", "fallback_window"
    name: str
    start_line: int
    end_line: int
    text: str

    def to_dict(self):
        return dataclasses.asdict(self)


def _chunk_id(rel_path: str, start_line: int, end_line: int) -> str:
    h = hashlib.sha1(f"{rel_path}:{start_line}:{end_line}".encode()).hexdigest()[:12]
    return h


def _extract_name(node, source_bytes: bytes) -> str:
    for child in node.children:
        if child.type in ("identifier", "property_identifier", "type_identifier"):
            return source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
    return "<anonymous>"


def _kind_for(node_type: str) -> str:
    if "class" in node_type or "interface" in node_type:
        return "class"
    if "method" in node_type:
        return "method"
    return "function"


def chunk_file(abs_path: str, rel_path: str, language: str) -> list[CodeChunk]:
    """Parses one source file and returns its function/class-level chunks."""
    with open(abs_path, "rb") as f:
        source_bytes = f.read()

    parser = _PARSERS.get(language)
    if parser is None:
        return _fallback_chunk(source_bytes, rel_path, language)

    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return _fallback_chunk(source_bytes, rel_path, language)

    chunk_types = _CHUNK_NODE_TYPES[language]
    chunks: list[CodeChunk] = []

    def visit(node, depth=0):
        if node.type in chunk_types:
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            name = _extract_name(node, source_bytes)
            chunks.append(CodeChunk(
                chunk_id=_chunk_id(rel_path, start_line, end_line),
                repo_rel_path=rel_path,
                language=language,
                kind=_kind_for(node.type),
                name=name,
                start_line=start_line,
                end_line=end_line,
                text=text,
            ))
            # Don't also descend into nested functions/classes as separate
            # top-level chunks in this prototype — keep chunks at the
            # outermost logical-unit granularity to bound chunk count.
            return
        for child in node.children:
            visit(child, depth + 1)

    visit(tree.root_node)

    if not chunks:
        # No functions/classes found (e.g. a config file) — treat whole
        # file as one chunk so nothing is silently dropped.
        text = source_bytes.decode("utf-8", errors="replace")
        chunks.append(CodeChunk(
            chunk_id=_chunk_id(rel_path, 1, text.count("\n") + 1),
            repo_rel_path=rel_path,
            language=language,
            kind="whole_file",
            name=rel_path,
            start_line=1,
            end_line=text.count("\n") + 1,
            text=text,
        ))

    return chunks


def _fallback_chunk(source_bytes: bytes, rel_path: str, language: str) -> list[CodeChunk]:
    text = source_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    chunks = []
    for i in range(0, len(lines), FALLBACK_WINDOW_LINES):
        window = lines[i:i + FALLBACK_WINDOW_LINES]
        start_line = i + 1
        end_line = i + len(window)
        chunks.append(CodeChunk(
            chunk_id=_chunk_id(rel_path, start_line, end_line),
            repo_rel_path=rel_path,
            language=language,
            kind="fallback_window",
            name=f"{rel_path}:{start_line}-{end_line}",
            start_line=start_line,
            end_line=end_line,
            text="\n".join(window),
        ))
    return chunks


if __name__ == "__main__":
    import sys
    from rag_vuln_detect.ingestion.clone import ingest_repository

    url = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/OWASP/NodeGoat.git"
    report = ingest_repository(url, workdir="/tmp/rag_ingest_demo")
    all_chunks = []
    for f in report.files_kept:
        all_chunks.extend(chunk_file(f.abs_path, f.rel_path, f.language))

    kinds = {}
    for c in all_chunks:
        kinds[c.kind] = kinds.get(c.kind, 0) + 1
    print(f"{len(report.files_kept)} files -> {len(all_chunks)} chunks")
    print("Chunk kinds:", kinds)
    for c in all_chunks[:5]:
        print(f"  [{c.kind}] {c.repo_rel_path}:{c.start_line}-{c.end_line}  {c.name}")

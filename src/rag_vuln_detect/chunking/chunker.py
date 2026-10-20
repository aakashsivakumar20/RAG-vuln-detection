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

# ---- Languages added in v2. Each grammar is an optional import: if a package is missing the language
# silently degrades to line-window chunking instead of breaking the scanner. For these languages the unit
# is the function / method (classes are containers: a Java or C# class body is not one reviewable unit).
# language -> (module, factory attribute, chunk node types)
_EXTRA_LANGUAGES = {
    "java":   ("tree_sitter_java", "language", {"method_declaration", "constructor_declaration"}),
    "php":    ("tree_sitter_php", "language_php", {"function_definition", "method_declaration"}),
    "go":     ("tree_sitter_go", "language", {"function_declaration", "method_declaration"}),
    "csharp": ("tree_sitter_c_sharp", "language", {"method_declaration", "constructor_declaration",
                                                   "local_function_statement"}),
    "ruby":   ("tree_sitter_ruby", "language", {"method", "singleton_method"}),
    "c":      ("tree_sitter_c", "language", {"function_definition"}),
    "cpp":    ("tree_sitter_cpp", "language", {"function_definition"}),
    "rust":   ("tree_sitter_rust", "language", {"function_item"}),
    "kotlin": ("tree_sitter_kotlin", "language", {"function_declaration"}),
}
# Names tree-sitter uses for the identifier child of a declaration, by node type family.
_NAME_CHILD_TYPES = ("identifier", "property_identifier", "type_identifier", "name", "field_identifier", "constant",
                     "simple_identifier", "qualified_identifier", "destructor_name", "operator_name")
# PHP files are very often plain scripts: statements at the top level, outside any function. Those are gathered
# into one "script" chunk so request-handling code in e.g. login.php is not skipped.
_SCRIPT_LANGUAGES = {"php"}
_SCRIPT_SKIP_TYPES = {"php_tag", "text", "text_interpolation", "comment", "namespace_definition", "namespace_use_declaration",
                      "function_definition", "class_declaration", "interface_declaration", "trait_declaration",
                      "enum_declaration", "declare_statement", "require_once_expression"}


def _load_extra(language: str):
    """Lazily builds the parser for a v2 language; returns (parser, node_types) or None if unavailable."""
    spec = _EXTRA_LANGUAGES.get(language)
    if spec is None:
        return None
    if language in _PARSERS:
        return _PARSERS[language], _CHUNK_NODE_TYPES[language]
    try:
        import importlib
        mod = importlib.import_module(spec[0])
        parser = Parser(Language(getattr(mod, spec[1])()))
    except Exception:  # noqa: BLE001  (missing wheel / ABI mismatch -> fallback chunking)
        return None
    _PARSERS[language] = parser
    _CHUNK_NODE_TYPES[language] = set(spec[2])
    return parser, _CHUNK_NODE_TYPES[language]


def supported_languages() -> list[str]:
    """Languages that currently get syntax-aware chunking (the rest would use line windows)."""
    out = ["python", "javascript", "typescript"]
    out += [lang for lang in _EXTRA_LANGUAGES if _load_extra(lang) is not None]
    return out


FALLBACK_WINDOW_LINES = 40  # only used if tree-sitter parsing fails outright

# A function/class longer than this that CONTAINS nested functions/methods (a JS
# constructor-style module, a big Python class, an Express router factory) is split
# into those nested units so each LLM prompt and each retrieval query stays focused
# on one routine. Units without nested functions are kept whole however long they are.
MAX_UNIT_LINES = 60


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


def _text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _extract_name(node, source_bytes: bytes, language: str = "") -> str:
    if language in _EXTRA_LANGUAGES:
        named = node.child_by_field_name("name")   # Java/C#/Go/Rust/PHP/Ruby: the method's own name, not its return type
        if named is not None:
            return _text(named, source_bytes)
        # C / C++ keep the name inside nested declarators (pointer_declarator -> function_declarator -> identifier)
        cur = node
        for _ in range(6):
            nxt = cur.child_by_field_name("declarator")
            if nxt is None:
                break
            cur = nxt
        if cur is not node and cur.type in _NAME_CHILD_TYPES:
            return _text(cur, source_bytes)
        for child in cur.children:
            if child.type in _NAME_CHILD_TYPES:
                return _text(child, source_bytes)
        nm = cur.child_by_field_name("name")
        return _text(nm, source_bytes) if nm is not None else "<anonymous>"
    for child in node.children:
        if child.type in ("identifier", "property_identifier", "type_identifier"):
            return _text(child, source_bytes)
    return "<anonymous>"


def _kind_for(node_type: str) -> str:
    if "class" in node_type or "interface" in node_type:
        return "class"
    if "method" in node_type or node_type in ("constructor_declaration",):
        return "method"
    return "function"


def chunk_file(abs_path: str, rel_path: str, language: str) -> list[CodeChunk]:
    """Parses one source file and returns its function/class-level chunks."""
    with open(abs_path, "rb") as f:
        source_bytes = f.read()

    parser = _PARSERS.get(language)
    if parser is None:
        loaded = _load_extra(language)
        parser = loaded[0] if loaded else None
    if parser is None:
        return _fallback_chunk(source_bytes, rel_path, language)

    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return _fallback_chunk(source_bytes, rel_path, language)

    chunk_types = _CHUNK_NODE_TYPES[language]
    chunks: list[CodeChunk] = []

    def has_nested_unit(node) -> bool:
        stack = list(node.children)
        while stack:
            n = stack.pop()
            if n.type in chunk_types:
                return True
            stack.extend(n.children)
        return False

    def visit(node, depth=0):
        if node.type in chunk_types:
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if end_line - start_line + 1 > MAX_UNIT_LINES and has_nested_unit(node):
                for child in node.children:
                    visit(child, depth + 1)
                return
            text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            name = _extract_name(node, source_bytes, language)
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
            # Small/medium units are kept whole (outermost granularity bounds chunk
            # count); oversized containers were already split above.
            return
        for child in node.children:
            visit(child, depth + 1)

    visit(tree.root_node)

    if language in _SCRIPT_LANGUAGES:
        script = [n for n in tree.root_node.children if n.type not in _SCRIPT_SKIP_TYPES and n.is_named]
        if script:
            start_line, end_line = script[0].start_point[0] + 1, script[-1].end_point[0] + 1
            body = "\n".join(_text(n, source_bytes) for n in script)
            if len(body.strip().splitlines()) >= 3:
                chunks.append(CodeChunk(chunk_id=_chunk_id(rel_path, start_line, end_line), repo_rel_path=rel_path,
                                        language=language, kind="script", name="<top-level script>",
                                        start_line=start_line, end_line=end_line, text=body))

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

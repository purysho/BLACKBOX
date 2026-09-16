from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import posixpath
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

IGNORE_DIRS = {
    '.git', '.hg', '.svn', 'node_modules', 'dist', 'build', 'target', '.next', '.nuxt',
    '.venv', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
    'coverage', '.idea', '.vscode', 'vendor', 'Pods', '.gradle', '.cache'
}

LANG_BY_EXT = {
    '.py': 'Python', '.pyi': 'Python', '.js': 'JavaScript', '.mjs': 'JavaScript',
    '.cjs': 'JavaScript', '.jsx': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
    '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.kt': 'Kotlin', '.kts': 'Kotlin',
    '.c': 'C', '.h': 'C/C++', '.cc': 'C++', '.cpp': 'C++', '.hpp': 'C/C++',
    '.cs': 'C#', '.rb': 'Ruby', '.php': 'PHP', '.swift': 'Swift', '.scala': 'Scala',
    '.lua': 'Lua', '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell', '.ps1': 'PowerShell',
    '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS', '.scss': 'SCSS', '.sass': 'Sass',
    '.less': 'Less', '.sql': 'SQL', '.json': 'JSON', '.toml': 'TOML', '.yaml': 'YAML',
    '.yml': 'YAML', '.md': 'Markdown', '.vue': 'Vue', '.svelte': 'Svelte'
}

TEXT_EXTS = set(LANG_BY_EXT) | {
    '.txt', '.ini', '.cfg', '.conf', '.env', '.example', '.xml', '.graphql', '.gql', '.lock'
}

SECRET_PATTERNS = [
    ('critical', 'Private key material', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('high', 'AWS access key', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('high', 'GitHub token', re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b')),
    ('high', 'Slack token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')),
    ('medium', 'Possible secret assignment', re.compile(
        r'(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[\"\']([^\"\'\s]{8,})[\"\']'
    )),
]

TODO_RE = re.compile(r'\b(TODO|FIXME|HACK|XXX)\b', re.IGNORECASE)
IMPORT_JS_RE = re.compile(r'(?:import\s+(?:[^;]*?\s+from\s+)?|require\s*\()\s*[\"\']([^\"\']+)[\"\']')
URL_RE = re.compile(r'https?://[^\s\"\'<>]+')
BRANCH_RE = re.compile(r'\b(if|elif|else if|for|while|case|catch|except|match|switch)\b|&&|\|\|')

FRAMEWORK_MARKERS = [
    ('React', ['package.json'], ['react']),
    ('Next.js', ['next.config.js', 'next.config.mjs', 'next.config.ts'], []),
    ('Vite', ['vite.config.js', 'vite.config.ts', 'vite.config.mjs'], []),
    ('Tauri', ['src-tauri/tauri.conf.json', 'src-tauri/tauri.conf.json5'], []),
    ('FastAPI', [], ['fastapi']),
    ('Django', ['manage.py'], []),
    ('Flask', [], ['flask']),
    ('Rust/Cargo', ['Cargo.toml'], []),
    ('Go modules', ['go.mod'], []),
    ('Docker', ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml'], []),
]


def _safe_text(path: Path, max_bytes: int = 1_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
        if b'\x00' in data[:4096]:
            return None
        return data.decode('utf-8', errors='replace')
    except (OSError, UnicodeError):
        return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _iter_files(root: Path) -> Iterable[Path]:
    # Git repositories get a fast path: analyze tracked files only. This avoids
    # crawling huge ignored/cache trees (especially slow on WSL /mnt/c mounts).
    try:
        probe = subprocess.run(
            ['git', '-C', str(root), 'rev-parse', '--is-inside-work-tree'],
            capture_output=True, text=True, timeout=5
        )
        if probe.returncode == 0 and probe.stdout.strip() == 'true':
            listed = subprocess.run(
                ['git', '-C', str(root), 'ls-files', '-z'],
                capture_output=True, timeout=15
            )
            if listed.returncode == 0:
                for raw in listed.stdout.split(b'\0'):
                    if not raw:
                        continue
                    rel = raw.decode('utf-8', errors='surrogateescape')
                    path = root / rel
                    if not path.exists() or path.is_symlink():
                        continue
                    if any(part in IGNORE_DIRS for part in path.parts):
                        continue
                    yield path
                return
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Fallback for non-Git directories.
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.blackbox')]
        for name in files:
            path = Path(base) / name
            if path.is_symlink():
                continue
            if any(part in IGNORE_DIRS for part in path.parts):
                continue
            yield path


def _python_analysis(text: str):
    imports: list[str] = []
    functions: list[dict] = []
    classes = 0
    complexity = 1
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return imports, functions, classes, complexity
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append('.' * node.level + node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            c = 1
            for sub in ast.walk(node):
                if isinstance(sub, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.BoolOp, ast.Match)):
                    c += 1
            functions.append({'name': node.name, 'line': node.lineno, 'complexity': c})
            complexity += max(0, c - 1)
        elif isinstance(node, ast.ClassDef):
            classes += 1
    return imports, functions, classes, complexity


def _resolve_local_import(source_rel: str, spec: str, all_files: set[str]) -> str | None:
    src_dir = posixpath.dirname(source_rel)
    bases: list[str] = []

    # JS/TS-style relative imports: ./foo, ../foo
    if spec.startswith('./') or spec.startswith('../'):
        bases.append(posixpath.normpath(posixpath.join(src_dir, spec)))

    # Python-style relative imports: .foo, ..bar
    elif spec.startswith('.'):
        dots = len(spec) - len(spec.lstrip('.'))
        module = spec[dots:].replace('.', '/')
        base_dir = src_dir
        for _ in range(max(0, dots - 1)):
            base_dir = posixpath.dirname(base_dir)
        bases.append(posixpath.normpath(posixpath.join(base_dir, module)))

    # Python absolute module imports may still point inside this repository.
    else:
        bases.append(spec.replace('.', '/'))

    for base in bases:
        if base == '..' or base.startswith('../'):
            continue
        candidates = [
            base, base + '.js', base + '.jsx', base + '.ts', base + '.tsx', base + '.mjs',
            base + '.py', f'{base}/index.js', f'{base}/index.ts', f'{base}/index.tsx',
            f'{base}/__init__.py'
        ]
        for candidate in candidates:
            if candidate in all_files:
                return candidate
    return None


def _git_info(root: Path) -> dict:
    def run(args: list[str]) -> str:
        try:
            p = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=12)
            return p.stdout if p.returncode == 0 else ''
        except (OSError, subprocess.TimeoutExpired):
            return ''

    inside = run(['rev-parse', '--is-inside-work-tree']).strip() == 'true'
    if not inside:
        return {'available': False, 'commits': 0, 'branch': None, 'churn': {}}

    branch = run(['branch', '--show-current']).strip() or None
    commit_count_text = run(['rev-list', '--count', 'HEAD']).strip()
    commits = int(commit_count_text) if commit_count_text.isdigit() else 0
    churn: dict[str, dict[str, int]] = defaultdict(lambda: {'touches': 0, 'added': 0, 'deleted': 0})
    log = run(['log', '--numstat', '--format=__C__', '--no-renames', '-n', '300'])
    seen_this_commit: set[str] = set()
    for line in log.splitlines():
        if line == '__C__':
            for f in seen_this_commit:
                churn[f]['touches'] += 1
            seen_this_commit.clear()
            continue
        parts = line.split('\t')
        if len(parts) == 3:
            a, d, f = parts
            if a.isdigit(): churn[f]['added'] += int(a)
            if d.isdigit(): churn[f]['deleted'] += int(d)
            seen_this_commit.add(f)
    for f in seen_this_commit:
        churn[f]['touches'] += 1
    return {'available': True, 'commits': commits, 'branch': branch, 'churn': dict(churn)}


def _detect_frameworks(root: Path, combined_text: str) -> list[str]:
    out: list[str] = []
    lower = combined_text.lower()
    for name, files, needles in FRAMEWORK_MARKERS:
        if any((root / f).exists() for f in files) or any(n.lower() in lower for n in needles):
            out.append(name)
    return out


def _tarjan(nodes: Iterable[str], edges: dict[str, list[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    sccs: list[list[str]] = []

    def strong(v: str):
        nonlocal index
        indices[v] = low[v] = index
        index += 1
        stack.append(v); on_stack.add(v)
        for w in edges.get(v, []):
            if w not in indices:
                strong(w); low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], indices[w])
        if low[v] == indices[v]:
            comp = []
            while True:
                w = stack.pop(); on_stack.remove(w); comp.append(w)
                if w == v: break
            if len(comp) > 1:
                sccs.append(comp)

    for n in nodes:
        if n not in indices:
            strong(n)
    return sorted(sccs, key=len, reverse=True)


def scan_repo(path: str | Path) -> dict:
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f'Not a directory: {root}')

    git = _git_info(root)
    raw_files = list(_iter_files(root))
    rel_set = {p.relative_to(root).as_posix() for p in raw_files}
    files: list[dict] = []
    findings: list[dict] = []
    lang_counts = Counter()
    total_loc = 0
    combined_manifest_text = ''
    external_imports = Counter()
    raw_import_specs: dict[str, list[str]] = {}

    for path_obj in raw_files:
        rel = path_obj.relative_to(root).as_posix()
        ext = path_obj.suffix.lower()
        lang = LANG_BY_EXT.get(ext, 'Other')
        try:
            size = path_obj.stat().st_size
            with path_obj.open('rb') as fh:
                head = fh.read(65536)
            ent = round(_entropy(head), 2)
        except OSError:
            size, ent = 0, 0.0
        text = _safe_text(path_obj) if (ext in TEXT_EXTS or size < 200_000) else None
        loc = 0
        imports: list[str] = []
        functions: list[dict] = []
        classes = 0
        complexity = 1
        todo_count = 0
        urls: list[str] = []
        if text is not None:
            loc = 0 if not text else text.count('\n') + 1
            total_loc += loc
            if lang != 'Other': lang_counts[lang] += 1
            todo_count = len(TODO_RE.findall(text))
            urls = URL_RE.findall(text)[:15]
            if ext in {'.py', '.pyi'}:
                imports, functions, classes, complexity = _python_analysis(text)
            elif ext in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'}:
                imports = IMPORT_JS_RE.findall(text)
                complexity = 1 + len(BRANCH_RE.findall(text))
            elif ext in {'.rs', '.go', '.java', '.kt', '.cs', '.cpp', '.cc', '.c'}:
                complexity = 1 + len(BRANCH_RE.findall(text))
            for severity, label, rx in SECRET_PATTERNS:
                for m in rx.finditer(text):
                    line = text.count('\n', 0, m.start()) + 1
                    findings.append({
                        'severity': severity, 'type': 'secret', 'title': label,
                        'file': rel, 'line': line,
                        'detail': 'Pattern matched; verify manually. Value intentionally redacted.'
                    })
            if todo_count:
                findings.append({
                    'severity': 'info', 'type': 'todo', 'title': f'{todo_count} TODO/FIXME marker(s)',
                    'file': rel, 'line': None, 'detail': 'Maintenance marker(s) found in source text.'
                })
            if path_obj.name in {'package.json', 'pyproject.toml', 'Cargo.toml', 'requirements.txt'}:
                combined_manifest_text += '\n' + text

        raw_import_specs[rel] = imports
        churn = git.get('churn', {}).get(rel, {'touches': 0, 'added': 0, 'deleted': 0})
        files.append({
            'path': rel, 'name': path_obj.name, 'ext': ext, 'language': lang, 'size': size,
            'loc': loc, 'entropy': ent, 'complexity': complexity, 'functions': functions[:100],
            'classes': classes, 'todo_count': todo_count, 'urls': urls,
            'git_touches': churn.get('touches', 0), 'git_added': churn.get('added', 0),
            'git_deleted': churn.get('deleted', 0), 'imports_raw': imports[:100]
        })

    edges: dict[str, list[str]] = defaultdict(list)
    inbound = Counter()
    for f in files:
        rel = f['path']
        resolved = []
        for spec in raw_import_specs.get(rel, []):
            local = _resolve_local_import(rel, spec, rel_set)
            if local:
                resolved.append(local); inbound[local] += 1
            else:
                base = spec.lstrip('.').split('/')[0]
                if base and not spec.startswith('.'):
                    external_imports[base] += 1
        edges[rel] = sorted(set(resolved))
        f['imports_local'] = edges[rel]

    cycles = _tarjan(rel_set, edges)
    for cyc in cycles[:20]:
        findings.append({
            'severity': 'medium', 'type': 'dependency', 'title': 'Circular dependency cluster',
            'file': cyc[0], 'line': None, 'detail': ' → '.join(cyc[:8]) + (' …' if len(cyc) > 8 else '')
        })

    max_touch = max([f['git_touches'] for f in files] + [1])
    max_loc = max([f['loc'] for f in files] + [1])
    max_complex = max([f['complexity'] for f in files] + [1])
    max_inbound = max(list(inbound.values()) + [1])
    for f in files:
        risk = (
            35 * min(f['complexity'] / max(20, max_complex), 1) +
            25 * min(f['git_touches'] / max(10, max_touch), 1) +
            20 * min(inbound[f['path']] / max(8, max_inbound), 1) +
            15 * min(f['loc'] / max(500, max_loc), 1) +
            5 * min(f['todo_count'] / 5, 1)
        )
        f['inbound'] = inbound[f['path']]
        f['risk'] = round(risk, 1)
        f['sha256_12'] = hashlib.sha256(f['path'].encode()).hexdigest()[:12]

    files.sort(key=lambda x: (-x['risk'], x['path']))
    sev_weight = {'critical': 25, 'high': 15, 'medium': 7, 'low': 3, 'info': 0.5}
    finding_points = sum(sev_weight.get(x['severity'], 1) for x in findings)
    hotspot_points = sum(f['risk'] for f in files[:10]) / max(10, min(len(files), 10)) if files else 0
    overall_risk = round(min(100, finding_points + hotspot_points * 0.65), 1)

    source_files = [f for f in files if f['language'] not in {'Other', 'JSON', 'TOML', 'YAML', 'Markdown'} and f['loc']]
    orphan_candidates = [f['path'] for f in source_files if inbound[f['path']] == 0 and not re.search(r'(main|index|app|lib|mod|__init__|test|spec)', f['name'], re.I)]

    frameworks = _detect_frameworks(root, combined_manifest_text)
    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'root': str(root),
        'project': root.name,
        'summary': {
            'files': len(files), 'source_files': len(source_files), 'loc': total_loc,
            'languages': len([k for k,v in lang_counts.items() if v]),
            'findings': len(findings), 'cycles': len(cycles), 'overall_risk': overall_risk,
            'orphan_candidates': len(orphan_candidates)
        },
        'languages': [{'name': k, 'files': v} for k,v in lang_counts.most_common()],
        'frameworks': frameworks,
        'git': {k: v for k,v in git.items() if k != 'churn'},
        'external_imports': [{'name': k, 'count': v} for k,v in external_imports.most_common(30)],
        'files': files,
        'edges': [{'source': s, 'target': t} for s, targets in edges.items() for t in targets],
        'cycles': cycles,
        'orphan_candidates': orphan_candidates[:100],
        'findings': sorted(findings, key=lambda x: ({'critical':0,'high':1,'medium':2,'low':3,'info':4}.get(x['severity'],5), x['file'])),
    }

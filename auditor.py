#!/usr/bin/env python3
"""
project-auditor — Analiza un proyecto y genera un vault de Obsidian.
v2: análisis AST para complejidad ciclomática, imports circulares,
    God Classes, llamadas bloqueantes en async y grafo de módulos.

Uso:
    python auditor.py <ruta-proyecto> [--output <ruta-vault>] [--json]
"""

import os
import re
import sys
import ast
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Configuración ──────────────────────────────────────────
IGNORED_DIRS = {
    ".git", ".github", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".next", ".nuxt", "coverage",
    ".pytest_cache", ".mypy_cache", ".tox",
}
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".swift", ".kt",
    ".sh", ".bash", ".sql",
}
SIZE_ALERT_KB = 500
TODO_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|TEMP)\b", re.IGNORECASE)

# Umbrales AST
COMPLEXITY_THRESHOLD = 10
FUNCTION_LINES_THRESHOLD = 50
GOD_CLASS_METHODS = 15
BLOCKING_CALLS = {"sleep", "get", "post", "put", "delete", "request"}
BLOCKING_MODULES = {"time", "requests", "urllib", "httplib"}


# ── Visitadores AST ───────────────────────────────────────
class ComplexityVisitor(ast.NodeVisitor):
    """Complejidad ciclomática por función."""

    def __init__(self):
        self.results = []  # [(nombre, linea, complejidad)]
        self._stack = []

    def _enter(self, name, lineno):
        self._stack.append({"name": name, "lineno": lineno, "complexity": 1})

    def _exit(self):
        e = self._stack.pop()
        self.results.append((e["name"], e["lineno"], e["complexity"]))

    def _inc(self):
        if self._stack:
            self._stack[-1]["complexity"] += 1

    def visit_FunctionDef(self, node):
        self._enter(node.name, node.lineno)
        self.generic_visit(node)
        self._exit()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):         self._inc(); self.generic_visit(node)
    def visit_For(self, node):        self._inc(); self.generic_visit(node)
    def visit_While(self, node):      self._inc(); self.generic_visit(node)
    def visit_ExceptHandler(self, n): self._inc(); self.generic_visit(n)
    def visit_BoolOp(self, node):     self._inc(); self.generic_visit(node)

    def visit_comprehension(self, node):
        if node.ifs:
            self._inc()
        self.generic_visit(node)


class ImportVisitor(ast.NodeVisitor):
    """Extrae módulos importados.

    Separa en dos colecciones para evitar falsos positivos:
    - module_imports: rutas y nombres cortos de módulos reales
        import app.core.embeddings  →  'app.core.embeddings', 'embeddings'
        from app.core.embeddings import embed  →  'app.core.embeddings', 'embeddings'
    - from_names: pares (from_module, name) para 'from X import Y'
        from app.db.repos import conversations  →  ('app.db.repos', 'conversations')
        Solo se convierte en dependencia si 'app.db.repos.conversations' existe en canonical.
    """

    def __init__(self):
        self.module_imports: set[str] = set()
        self.from_names: list[tuple[str, str]] = []

    def visit_Import(self, node):
        for alias in node.names:
            parts = alias.name.split(".")
            self.module_imports.add(alias.name)   # ruta completa
            self.module_imports.add(parts[-1])    # nombre corto

    def visit_ImportFrom(self, node):
        if node.module:
            parts = node.module.split(".")
            self.module_imports.add(node.module)  # ruta completa: 'app.core.embeddings'
            self.module_imports.add(parts[-1])    # nombre corto: 'embeddings'
            for alias in node.names:
                # Registrar par (from_module, name) para resolución exacta posterior
                self.from_names.append((node.module, alias.name))


class GodClassVisitor(ast.NodeVisitor):
    """Detecta clases con demasiados métodos."""

    def __init__(self):
        self.results = []  # [(nombre, linea, n_metodos)]

    def visit_ClassDef(self, node):
        methods = [
            n for n in ast.walk(node)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.results.append((node.name, node.lineno, len(methods)))
        self.generic_visit(node)


class AsyncBlockingVisitor(ast.NodeVisitor):
    """Detecta llamadas bloqueantes en funciones async."""

    def __init__(self):
        self.results = []  # [(func_name, linea, llamada)]
        self._async_stack = []

    def visit_AsyncFunctionDef(self, node):
        self._async_stack.append(node.name)
        self.generic_visit(node)
        self._async_stack.pop()

    def visit_Call(self, node):
        if self._async_stack and isinstance(node.func, ast.Attribute):
            if (node.func.attr in BLOCKING_CALLS
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in BLOCKING_MODULES):
                self.results.append((
                    self._async_stack[-1],
                    node.lineno,
                    f"{node.func.value.id}.{node.func.attr}()",
                ))
        self.generic_visit(node)


class FunctionLengthVisitor(ast.NodeVisitor):
    """Detecta funciones largas."""

    def __init__(self):
        self.results = []  # [(nombre, linea, longitud)]

    def visit_FunctionDef(self, node):
        length = getattr(node, "end_lineno", node.lineno) - node.lineno + 1
        self.results.append((node.name, node.lineno, length))
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


# ── Análisis AST por archivo ───────────────────────────────
def analyze_python_file(fpath: Path) -> dict:
    """Analiza un archivo .py con AST y retorna métricas."""
    try:
        source = fpath.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(fpath))
    except SyntaxError:
        return {"error": "SyntaxError", "imports": set()}

    cv  = ComplexityVisitor();      cv.visit(tree)
    gcv = GodClassVisitor();        gcv.visit(tree)
    abv = AsyncBlockingVisitor();   abv.visit(tree)
    flv = FunctionLengthVisitor();  flv.visit(tree)
    iv  = ImportVisitor();          iv.visit(tree)

    return {
        "module_imports": iv.module_imports,
        "from_names": iv.from_names,
        "complexity": cv.results,
        "god_classes": gcv.results,
        "blocking_async": abv.results,
        "function_lengths": flv.results,
    }


# ── Grafo de imports ────────────────────────────────────────
def build_import_graph(root: Path) -> dict[str, set[str]]:
    """Grafo {modulo_largo: {módulos_locales_que_importa}}.

    Usa el nombre largo (app.core.embeddings) como clave canónica
    para evitar colisiones entre módulos del mismo nombre corto
    (e.g. dos archivos admin.py en packages distintos).
    """
    # Mapa canónico: nombre_largo → Path (una entrada por archivo)
    canonical: dict[str, Path] = {}
    # Alias: nombre_corto → nombre_largo (último en ganar si hay colisión)
    short_alias: dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                fpath = Path(dirpath) / fname
                rel = fpath.relative_to(root)
                mod_long = str(rel.with_suffix("")).replace(os.sep, ".")
                short = fname[:-3]
                canonical[mod_long] = fpath
                short_alias[short] = mod_long  # puede colisionar; se resuelve luego

    graph: dict[str, set[str]] = {}
    for mod_long, fpath in canonical.items():
        if "." not in mod_long:
            continue
        metrics = analyze_python_file(fpath)
        module_imports = metrics.get("module_imports", set())
        from_names     = metrics.get("from_names", [])

        resolved: set[str] = set()

        # 1. Resolver rutas y nombres cortos de módulos reales
        for imp in module_imports:
            if imp in canonical:
                resolved.add(imp)                   # ruta exacta
            elif imp in short_alias:
                resolved.add(short_alias[imp])      # nombre corto → ruta larga

        # 2. Resolver 'from X import Y' solo si 'X.Y' es un módulo local real
        #    Esto evita que variables/funciones (e.g. 'settings' de config.py)
        #    se confundan con módulos homónimos (e.g. app.workers.settings).
        for from_mod, name in from_names:
            full = f"{from_mod}.{name}"
            if full in canonical:
                resolved.add(full)

        # Excluir auto-referencia
        resolved.discard(mod_long)
        graph[mod_long] = resolved

    return graph


def find_circular_imports(graph: dict[str, set[str]]) -> list[list[str]]:
    """Detecta ciclos en el grafo de imports (DFS)."""
    visited: set[str] = set()
    rec_stack: set[str] = set()
    cycles: list[list[str]] = []

    def dfs(node: str, path: list[str]):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                dfs(neighbor, path)
            elif neighbor in rec_stack:
                idx = path.index(neighbor)
                cycles.append(path[idx:] + [neighbor])
        path.pop()
        rec_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node, [])
    return cycles


# ── Chequeos clásicos ─────────────────────────────────────────
def check_missing_files(root: Path) -> list[dict]:
    issues = []
    expected = {
        "README.md": "Documentación principal",
        ".gitignore": "Archivos ignorados por Git",
    }
    if (root / "package.json").exists():
        expected["package-lock.json"] = "Lockfile Node"
    if any(root.glob("*.py")):
        expected["requirements.txt"] = "Dependencias Python"
    for fname, desc in expected.items():
        if not (root / fname).exists():
            issues.append({"tipo": "archivo-faltante", "severidad": "alta",
                           "archivo": fname, "descripcion": f"Falta `{fname}`: {desc}"})
    return issues


def check_empty_dirs(root: Path) -> list[dict]:
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        dp = Path(dirpath)
        if dp == root:
            continue
        if not [f for f in filenames if not f.startswith(".")] and not dirnames:
            issues.append({"tipo": "directorio-vacio", "severidad": "baja",
                           "archivo": str(dp.relative_to(root)),
                           "descripcion": f"Directorio vacío: `{dp.relative_to(root)}`"})
    return issues


def check_large_files(root: Path) -> list[dict]:
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                kb = fpath.stat().st_size / 1024
                if kb > SIZE_ALERT_KB:
                    issues.append({"tipo": "archivo-grande", "severidad": "media",
                                   "archivo": str(fpath.relative_to(root)),
                                   "descripcion": f"Archivo grande ({kb:.0f} KB): `{fpath.relative_to(root)}`"})
            except OSError:
                pass
    return issues


def check_todos(root: Path) -> list[dict]:
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix not in CODE_EXTENSIONS:
                continue
            try:
                for i, line in enumerate(
                    fpath.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
                ):
                    if TODO_PATTERN.search(line):
                        issues.append({"tipo": "todo-pendiente", "severidad": "media",
                                       "archivo": str(fpath.relative_to(root)),
                                       "descripcion": f"`{fpath.relative_to(root)}:{i}` — {line.strip()}"})
            except OSError:
                pass
    return issues


def check_no_tests(root: Path) -> list[dict]:
    test_dirs = ["tests", "test", "__tests__", "spec", "specs"]
    test_files = list(root.glob("test_*.py")) + list(root.glob("*_test.py"))
    if not any((root / d).is_dir() for d in test_dirs) and not test_files:
        return [{"tipo": "sin-tests", "severidad": "alta", "archivo": ".",
                 "descripcion": "No se encontró ningún directorio ni archivo de tests"}]
    return []


# ── Chequeos AST ───────────────────────────────────────────
def _iter_py(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                yield Path(dirpath) / fname


def check_complexity(root: Path) -> list[dict]:
    issues = []
    for fpath in _iter_py(root):
        m = analyze_python_file(fpath)
        if "error" in m:
            continue
        for name, lineno, complexity in m["complexity"]:
            if complexity > COMPLEXITY_THRESHOLD:
                issues.append({
                    "tipo": "complejidad-alta", "severidad": "media",
                    "archivo": str(fpath.relative_to(root)),
                    "descripcion": (
                        f"`{fpath.relative_to(root)}:{lineno}` — "
                        f"función `{name}` complejidad {complexity} "
                        f"(umbral {COMPLEXITY_THRESHOLD})"
                    ),
                })
    return issues


def check_god_classes(root: Path) -> list[dict]:
    issues = []
    for fpath in _iter_py(root):
        m = analyze_python_file(fpath)
        if "error" in m:
            continue
        for class_name, lineno, n in m["god_classes"]:
            if n > GOD_CLASS_METHODS:
                issues.append({
                    "tipo": "god-class", "severidad": "media",
                    "archivo": str(fpath.relative_to(root)),
                    "descripcion": (
                        f"`{fpath.relative_to(root)}:{lineno}` — "
                        f"clase `{class_name}` tiene {n} métodos "
                        f"(umbral {GOD_CLASS_METHODS})"
                    ),
                })
    return issues


def check_blocking_async(root: Path) -> list[dict]:
    issues = []
    for fpath in _iter_py(root):
        m = analyze_python_file(fpath)
        if "error" in m:
            continue
        for func_name, lineno, call in m["blocking_async"]:
            issues.append({
                "tipo": "async-bloqueante", "severidad": "alta",
                "archivo": str(fpath.relative_to(root)),
                "descripcion": (
                    f"`{fpath.relative_to(root)}:{lineno}` — "
                    f"async `{func_name}` llama a bloqueante `{call}`"
                ),
            })
    return issues


def check_long_functions(root: Path) -> list[dict]:
    issues = []
    for fpath in _iter_py(root):
        m = analyze_python_file(fpath)
        if "error" in m:
            continue
        for name, lineno, length in m["function_lengths"]:
            if length > FUNCTION_LINES_THRESHOLD:
                issues.append({
                    "tipo": "funcion-larga", "severidad": "baja",
                    "archivo": str(fpath.relative_to(root)),
                    "descripcion": (
                        f"`{fpath.relative_to(root)}:{lineno}` — "
                        f"`{name}` tiene {length} líneas "
                        f"(umbral {FUNCTION_LINES_THRESHOLD})"
                    ),
                })
    return issues


def check_circular_imports_issues(root: Path) -> tuple[list[dict], dict]:
    graph = build_import_graph(root)
    cycles = find_circular_imports(graph)
    issues = []
    for cycle in cycles:
        issues.append({
            "tipo": "import-circular", "severidad": "alta",
            "archivo": cycle[0].replace(".", "/") + ".py",
            "descripcion": f"Import circular: `{'  →  '.join(cycle)}`",
        })
    return issues, graph


# ── Escaneo completo ────────────────────────────────────────
def build_structure(root: Path, depth: int = 0, max_depth: int = 4) -> list:
    if depth > max_depth:
        return []
    entries = []
    try:
        items = sorted(root.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        return []
    for item in items:
        if item.name.startswith(".") or item.name in IGNORED_DIRS:
            continue
        entry = {"nombre": item.name, "tipo": "dir" if item.is_dir() else "file"}
        if item.is_dir():
            entry["hijos"] = build_structure(item, depth + 1, max_depth)
        entries.append(entry)
    return entries


def scan_project(root: Path) -> dict:
    steps = [
        ("Archivos faltantes",     check_missing_files),
        ("Directorios vacíos",      check_empty_dirs),
        ("Archivos grandes",        check_large_files),
        ("TODOs / FIXMEs",          check_todos),
        ("Tests",                   check_no_tests),
        ("Complejidad ciclomática", check_complexity),
        ("God Classes",             check_god_classes),
        ("Async bloqueante",        check_blocking_async),
        ("Funciones largas",        check_long_functions),
    ]
    issues = []
    for label, fn in steps:
        print(f"  → {label}...")
        issues += fn(root)

    print("  → Grafo de imports (AST)...")
    circular_issues, import_graph = check_circular_imports_issues(root)
    issues += circular_issues

    return {
        "proyecto": root.name,
        "ruta": str(root.resolve()),
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "total_issues": len(issues),
        "issues": issues,
        "estructura": build_structure(root),
        "import_graph": {k: list(v) for k, v in import_graph.items()},
    }


# ── Generación del vault ───────────────────────────────────────
SEVERIDAD_EMOJI = {"alta": "🔴", "media": "🟡", "baja": "🟢"}
TIPO_ETIQUETA = {
    "archivo-faltante":  "faltante",
    "directorio-vacio":  "estructura",
    "archivo-grande":    "tamaño",
    "todo-pendiente":    "deuda-tecnica",
    "sin-tests":         "calidad",
    "complejidad-alta":  "complejidad",
    "god-class":         "god-class",
    "async-bloqueante":  "async-bug",
    "import-circular":   "circular",
    "funcion-larga":     "deuda-tecnica",
}


def structure_to_md(items: list, indent: int = 0) -> str:
    lines = []
    for item in items:
        icon = "📁" if item["tipo"] == "dir" else "📄"
        lines.append("  " * indent + f"- {icon} `{item['nombre']}`")
        if item.get("hijos"):
            lines.append(structure_to_md(item["hijos"], indent + 1))
    return "\n".join(lines)


def _display_name(mod_long: str) -> str:
    """Nombre de display: último segmento, prefijado con el paquete si hay colisión."""
    return mod_long.split(".")[-1]


def _note_filename(mod_long: str, seen_shorts: dict[str, list[str]]) -> str:
    """Devuelve el nombre de archivo desambiguado si hay colisión de nombre corto."""
    short = mod_long.split(".")[-1]
    group = seen_shorts.get(short, [])
    if len(group) <= 1:
        return short
    # Disambiguate: use last two segments
    parts = mod_long.split(".")
    return f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else short


def generate_module_notes(vault_path: Path, import_graph: dict, proyecto: str):
    if not import_graph:
        return
    mods_dir = vault_path / "módulos"
    mods_dir.mkdir(exist_ok=True)

    # Detectar colisiones de nombre corto
    seen_shorts: dict[str, list[str]] = defaultdict(list)
    for mod_name in import_graph:
        seen_shorts[mod_name.split(".")[-1]].append(mod_name)

    # Mapa mod_long → filename (para los wikilinks)
    fn_map = {m: _note_filename(m, seen_shorts) for m in import_graph}

    for mod_name, deps in import_graph.items():
        fname = fn_map[mod_name]
        short = mod_name.split(".")[-1]
        package = ".".join(mod_name.split(".")[:-1])

        dep_links = "\n".join(
            f"- [[{fn_map.get(d, d.split('.')[-1])}]]" for d in sorted(deps)
        ) or "_Sin dependencias locales_"

        importers = [
            m for m, ds in import_graph.items() if mod_name in ds
        ]
        importer_links = "\n".join(
            f"- [[{fn_map.get(m, m.split('.')[-1])}]]" for m in sorted(importers)
        ) or "_No importado por otros módulos_"

        content = (
            f"---\n"
            f"tags: [módulo, {proyecto}]\n"
            f"módulo: {mod_name}\n"
            f"paquete: {package}\n"
            f"---\n\n"
            f"# {short}\n\n"
            f"**Módulo:** `{mod_name}`  \n"
            f"**Proyecto:** [[00 - {proyecto} Index|{proyecto}]]  \n"
            f"#módulo\n\n"
            f"## Importa\n\n{dep_links}\n\n"
            f"## Importado por\n\n{importer_links}\n"
        )
        (mods_dir / f"{fname}.md").write_text(content, encoding="utf-8")


def _clean_stale_notes(vault_path: Path):
    """Elimina notas de issues y módulos de ejecuciones anteriores."""
    if not vault_path.exists():
        return
    # Limpiar notas de issues en la raíz (excepto el index y Estructura/Grafo)
    keep = {"00", "Estructura", "Grafo"}
    for f in vault_path.glob("*.md"):
        if not any(f.stem.startswith(k) for k in keep):
            f.unlink()
    # Limpiar todas las notas de módulos (se regeneran completas)
    mods_dir = vault_path / "módulos"
    if mods_dir.exists():
        for f in mods_dir.glob("*.md"):
            f.unlink()


def generate_vault(report: dict, vault_path: Path):
    vault_path.mkdir(parents=True, exist_ok=True)
    _clean_stale_notes(vault_path)
    obsidian_dir = vault_path / ".obsidian"
    obsidian_dir.mkdir(exist_ok=True)
    write_obsidian_config(obsidian_dir)

    proyecto     = report["proyecto"]
    issues       = report["issues"]
    import_graph = report.get("import_graph", {})

    by_tipo = defaultdict(list)
    for iss in issues:
        by_tipo[iss["tipo"]].append(iss)

    issue_notes = []
    for tipo, lista in by_tipo.items():
        note_name = tipo.replace("-", " ").title()
        etiqueta  = TIPO_ETIQUETA.get(tipo, tipo)
        content = (
            f"---\n"
            f"tags: [{etiqueta}, auditoria]\n"
            f"proyecto: {proyecto}\n"
            f"severidad: {lista[0]['severidad']}\n"
            f"---\n\n"
            f"# {note_name}\n\n"
            f"**Proyecto:** [[00 - {proyecto} Index|{proyecto}]]  \n"
            f"**Total:** {len(lista)} problema(s)  \n"
            f"#{etiqueta}\n\n"
            f"## Detalle\n\n"
        )
        for iss in lista:
            content += f"- {SEVERIDAD_EMOJI.get(iss['severidad'], '⚪')} {iss['descripcion']}\n"
        (vault_path / f"{note_name}.md").write_text(content, encoding="utf-8")
        issue_notes.append(note_name)

    # Estructura
    struct = (
        f"---\ntags: [estructura, auditoria]\nproyecto: {proyecto}\n---\n\n"
        f"# Estructura del Proyecto\n\n"
        f"**Proyecto:** [[00 - {proyecto} Index|{proyecto}]]  \n#estructura\n\n"
        f"## Árbol\n\n{structure_to_md(report['estructura'])}\n"
    )
    (vault_path / "Estructura del Proyecto.md").write_text(struct, encoding="utf-8")

    # Grafo de módulos
    if import_graph:
        generate_module_notes(vault_path, import_graph, proyecto)

        # Detectar colisiones para el Grafo de Módulos también
        seen_shorts_dag: dict[str, list[str]] = defaultdict(list)
        for mod in import_graph:
            seen_shorts_dag[mod.split(".")[-1]].append(mod)
        fn_map_dag = {m: _note_filename(m, seen_shorts_dag) for m in import_graph}

        dag = (
            f"---\ntags: [dag, arquitectura]\nproyecto: {proyecto}\n---\n\n"
            f"# Grafo de Módulos\n\n"
            f"**Proyecto:** [[00 - {proyecto} Index|{proyecto}]]  \n#dag\n\n"
            f"Abre la **Vista de Grafo** en Obsidian para ver la red.\n\n"
            f"## Módulos ({len(import_graph)})\n\n"
        )
        for mod, deps in sorted(import_graph.items()):
            fn = fn_map_dag[mod]
            pkg = ".".join(mod.split(".")[:-1])
            dag += f"- [[{fn}]] `{pkg}` — {len(deps)} dep(s)\n"
        (vault_path / "Grafo de Módulos.md").write_text(dag, encoding="utf-8")
        issue_notes.append("Grafo de Módulos")

    # Index principal
    alta  = sum(1 for i in issues if i["severidad"] == "alta")
    media = sum(1 for i in issues if i["severidad"] == "media")
    baja  = sum(1 for i in issues if i["severidad"] == "baja")

    index = (
        f"---\ntags: [index, proyecto, auditoria]\nproyecto: {proyecto}\n---\n\n"
        f"# {proyecto} — Auditoría v2\n\n"
        f"**Fecha:** {report['fecha']}  \n"
        f"**Ruta:** `{report['ruta']}`  \n"
        f"#proyecto #auditoria\n\n"
        f"## Resumen\n\n"
        f"| Severidad | Cantidad |\n|-----------|---------:|\n"
        f"| 🔴 Alta   | {alta}   |\n"
        f"| 🟡 Media  | {media}  |\n"
        f"| 🟢 Baja   | {baja}   |\n"
        f"| **Total** | **{len(issues)}** |\n\n"
        f"## Análisis incluido\n\n"
        f"- ✅ Archivos faltantes\n- ✅ Tests ausentes\n- ✅ TODOs / FIXMEs\n"
        f"- ✅ Archivos grandes\n- ✅ Complejidad ciclomática (AST)\n"
        f"- ✅ God Classes (AST)\n- ✅ Llamadas bloqueantes en async (AST)\n"
        f"- ✅ Funciones largas (AST)\n- ✅ Imports circulares + DAG (AST)\n\n"
        f"## Notas del vault\n\n"
        f"- [[Estructura del Proyecto]]\n"
    )
    for note_name in issue_notes:
        index += f"- [[{note_name}]]\n"
    (vault_path / f"00 - {proyecto} Index.md").write_text(index, encoding="utf-8")

    print(f"\n✅ Vault v2 generado en: {vault_path}")
    print(f"   📝 Notas: {2 + len(issue_notes) + len(import_graph)}")
    print(f"   🔴 Altos: {alta} | 🟡 Medios: {media} | 🟢 Bajos: {baja}")
    print(f"   🔗 Módulos en grafo: {len(import_graph)}")
    print(f"\n   Abre '{vault_path.name}' en Obsidian → Vista de Grafo")


def write_obsidian_config(obsidian_dir: Path):
    (obsidian_dir / "app.json").write_text(
        json.dumps({
            "legacyEditor": False, "livePreview": True,
            "defaultViewMode": "preview", "newFileLocation": "current",
            "attachmentFolderPath": "assets", "promptDelete": True,
            "trashOption": "local",
        }, indent=2), encoding="utf-8"
    )
    (obsidian_dir / "graph.json").write_text(
        json.dumps({
            "collapse-filter": False, "search": "", "showTags": True,
            "showAttachments": False, "hideUnresolved": False,
            "showOrphans": True, "collapse-color-groups": False,
            "colorGroups": [
                {"query": "tag:#async-bug",     "color": {"a": 1, "rgb": 16711680}},
                {"query": "tag:#circular",      "color": {"a": 1, "rgb": 16711680}},
                {"query": "tag:#faltante",      "color": {"a": 1, "rgb": 16714512}},
                {"query": "tag:#complejidad",   "color": {"a": 1, "rgb": 16754944}},
                {"query": "tag:#god-class",     "color": {"a": 1, "rgb": 16754944}},
                {"query": "tag:#deuda-tecnica", "color": {"a": 1, "rgb": 16776960}},
                {"query": "tag:#módulo",       "color": {"a": 1, "rgb": 5614830}},
                {"query": "tag:#proyecto",      "color": {"a": 1, "rgb": 3394611}},
            ],
            "collapse-display": False, "showArrow": True,
            "textFadeMultiplier": 0, "nodeSizeMultiplier": 1.2,
            "lineSizeMultiplier": 1, "scale": 1, "close": False,
            "collapse-forces": False, "centerStrength": 0.518,
            "repelStrength": 10, "linkStrength": 1, "linkDistance": 250,
            "animate": False,
        }, indent=2), encoding="utf-8"
    )


# ── Main ────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Audita un proyecto y genera un vault de Obsidian (v2 + AST)."
    )
    parser.add_argument("proyecto", help="Ruta al proyecto")
    parser.add_argument("--output", default=None, help="Carpeta de salida del vault")
    parser.add_argument("--json", action="store_true", help="Exportar JSON")
    args = parser.parse_args()

    root = Path(args.proyecto).resolve()
    if not root.is_dir():
        print(f"❌ '{root}' no es un directorio.", file=sys.stderr)
        sys.exit(1)

    vault_out = Path(args.output) if args.output else Path(f"vault-{root.name}")

    print(f"🔍 Analizando: {root}")
    report = scan_project(root)
    print(f"📊 Total: {report['total_issues']} problemas")

    if args.json:
        jp = vault_out.parent / f"{root.name}-auditoria.json"
        jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"📄 JSON: {jp}")

    generate_vault(report, vault_out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
project-auditor — Analiza un proyecto y genera un vault de Obsidian.

Uso:
    python auditor.py <ruta-proyecto> [--output <ruta-vault>]

Ejemplo:
    python auditor.py ../brain-omni --output ./vault-brain-omni
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────

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

SIZE_ALERT_KB = 500  # archivos > 500KB se marcan
TODO_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|TEMP)\b", re.IGNORECASE)


# ─────────────────────────────────────────────
# Detección de problemas
# ─────────────────────────────────────────────

def check_missing_files(root: Path) -> list[dict]:
    """Detecta archivos importantes que faltan."""
    issues = []
    expected = {
        "README.md": "Documentación principal del proyecto",
        ".gitignore": "Control de archivos ignorados por Git",
    }
    # Detecta tipo de proyecto y agrega chequeos específicos
    if (root / "package.json").exists():
        expected["package-lock.json"] = "Lockfile de dependencias Node"
    if any(root.glob("*.py")):
        expected["requirements.txt"] = "Dependencias Python"

    for fname, desc in expected.items():
        if not (root / fname).exists():
            issues.append({
                "tipo": "archivo-faltante",
                "severidad": "alta",
                "archivo": fname,
                "descripcion": f"Falta `{fname}`: {desc}",
            })
    return issues


def check_empty_dirs(root: Path) -> list[dict]:
    """Detecta directorios vacíos."""
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        dp = Path(dirpath)
        if dp == root:
            continue
        visible_files = [f for f in filenames if not f.startswith(".")]
        visible_subdirs = [d for d in dirnames if d not in IGNORED_DIRS]
        if not visible_files and not visible_subdirs:
            issues.append({
                "tipo": "directorio-vacio",
                "severidad": "baja",
                "archivo": str(dp.relative_to(root)),
                "descripcion": f"Directorio vacío: `{dp.relative_to(root)}`",
            })
    return issues


def check_large_files(root: Path) -> list[dict]:
    """Detecta archivos muy grandes."""
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                size_kb = fpath.stat().st_size / 1024
                if size_kb > SIZE_ALERT_KB:
                    issues.append({
                        "tipo": "archivo-grande",
                        "severidad": "media",
                        "archivo": str(fpath.relative_to(root)),
                        "descripcion": f"Archivo grande ({size_kb:.0f} KB): `{fpath.relative_to(root)}`",
                    })
            except OSError:
                pass
    return issues


def check_todos(root: Path) -> list[dict]:
    """Detecta comentarios TODO/FIXME en el código."""
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix not in CODE_EXTENSIONS:
                continue
            try:
                lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                for i, line in enumerate(lines, 1):
                    m = TODO_PATTERN.search(line)
                    if m:
                        issues.append({
                            "tipo": "todo-pendiente",
                            "severidad": "media",
                            "archivo": str(fpath.relative_to(root)),
                            "descripcion": f"`{fpath.relative_to(root)}:{i}` — {line.strip()}",
                        })
            except OSError:
                pass
    return issues


def check_no_tests(root: Path) -> list[dict]:
    """Detecta proyectos sin directorio de tests."""
    test_dirs = ["tests", "test", "__tests__", "spec", "specs"]
    test_files = list(root.glob("test_*.py")) + list(root.glob("*_test.py")) + list(root.glob("**/*.test.js"))
    has_tests = any((root / d).is_dir() for d in test_dirs) or bool(test_files)
    if not has_tests:
        return [{
            "tipo": "sin-tests",
            "severidad": "alta",
            "archivo": ".",
            "descripcion": "No se encontró ningún directorio ni archivo de tests",
        }]
    return []


def scan_project(root: Path) -> dict:
    """Ejecuta todos los chequeos y retorna el informe."""
    issues = []
    issues += check_missing_files(root)
    issues += check_empty_dirs(root)
    issues += check_large_files(root)
    issues += check_todos(root)
    issues += check_no_tests(root)

    # Estructura de directorios
    structure = build_structure(root)

    return {
        "proyecto": root.name,
        "ruta": str(root.resolve()),
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "total_issues": len(issues),
        "issues": issues,
        "estructura": structure,
    }


def build_structure(root: Path, depth: int = 0, max_depth: int = 4) -> list:
    """Construye árbol de estructura recursivo."""
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


# ─────────────────────────────────────────────
# Generación del vault de Obsidian
# ─────────────────────────────────────────────

SEVERIDAD_EMOJI = {"alta": "🔴", "media": "🟡", "baja": "🟢"}
TIPO_ETIQUETA = {
    "archivo-faltante": "faltante",
    "directorio-vacio": "estructura",
    "archivo-grande": "tamaño",
    "todo-pendiente": "deuda-tecnica",
    "sin-tests": "calidad",
}


def structure_to_markdown(items: list, indent: int = 0) -> str:
    """Convierte la estructura a markdown con árbol de texto."""
    lines = []
    prefix = "  " * indent
    for item in items:
        icon = "📁" if item["tipo"] == "dir" else "📄"
        lines.append(f"{prefix}- {icon} `{item['nombre']}`")
        if item.get("hijos"):
            lines.append(structure_to_markdown(item["hijos"], indent + 1))
    return "\n".join(lines)


def generate_vault(report: dict, vault_path: Path):
    """Genera el vault de Obsidian a partir del informe."""
    vault_path.mkdir(parents=True, exist_ok=True)

    # Configuración de Obsidian
    obsidian_dir = vault_path / ".obsidian"
    obsidian_dir.mkdir(exist_ok=True)
    write_obsidian_config(obsidian_dir)

    proyecto = report["proyecto"]
    issues = report["issues"]
    fecha = report["fecha"]

    # Agrupar issues por tipo
    by_tipo = defaultdict(list)
    for iss in issues:
        by_tipo[iss["tipo"]].append(iss)

    # Notas de issues (una por tipo)
    issue_notes = []
    for tipo, lista in by_tipo.items():
        note_name = tipo.replace("-", " ").title()
        note_file = vault_path / f"{note_name}.md"
        etiqueta = TIPO_ETIQUETA.get(tipo, tipo)
        lines = [
            f"# {note_name}",
            f"",
            f"**Proyecto:** [[00 - {proyecto} Index|{proyecto}]]  ",
            f"**Etiqueta:** #{etiqueta}  ",
            f"**Total:** {len(lista)} problema(s)",
            f"",
            f"## Detalle",
            f"",
        ]
        for iss in lista:
            emoji = SEVERIDAD_EMOJI.get(iss["severidad"], "⚪")
            lines.append(f"- {emoji} {iss['descripcion']}")
        note_file.write_text("\n".join(lines), encoding="utf-8")
        issue_notes.append(note_name)

    # Nota de estructura
    struct_note = vault_path / "Estructura del Proyecto.md"
    struct_lines = [
        f"# Estructura del Proyecto",
        f"",
        f"**Proyecto:** [[00 - {proyecto} Index|{proyecto}]]  ",
        f"#estructura",
        f"",
        f"## Árbol de archivos",
        f"",
        structure_to_markdown(report["estructura"]),
    ]
    struct_note.write_text("\n".join(struct_lines), encoding="utf-8")

    # Nota index principal
    alta = sum(1 for i in issues if i["severidad"] == "alta")
    media = sum(1 for i in issues if i["severidad"] == "media")
    baja = sum(1 for i in issues if i["severidad"] == "baja")

    index_note = vault_path / f"00 - {proyecto} Index.md"
    index_lines = [
        f"# {proyecto} — Auditoría",
        f"",
        f"**Fecha:** {fecha}  ",
        f"**Ruta:** `{report['ruta']}`  ",
        f"#proyecto #auditoria",
        f"",
        f"## Resumen",
        f"",
        f"| Severidad | Cantidad |",
        f"|-----------|---------|",
        f"| 🔴 Alta   | {alta}   |",
        f"| 🟡 Media  | {media}  |",
        f"| 🟢 Baja   | {baja}   |",
        f"| **Total** | **{len(issues)}** |",
        f"",
        f"## Notas del vault",
        f"",
        f"- [[Estructura del Proyecto]]",
    ]
    for note_name in issue_notes:
        index_lines.append(f"- [[{note_name}]]")

    index_note.write_text("\n".join(index_lines), encoding="utf-8")

    print(f"\n✅ Vault generado en: {vault_path}")
    print(f"   📝 Notas creadas: {2 + len(issue_notes)}")
    print(f"   🔴 Issues altos: {alta} | 🟡 Medios: {media} | 🟢 Bajos: {baja}")
    print(f"\n   Abre la carpeta '{vault_path.name}' en Obsidian (Open folder as vault).")


def write_obsidian_config(obsidian_dir: Path):
    """Escribe la configuración base de Obsidian."""
    app_config = {
        "legacyEditor": False,
        "livePreview": True,
        "defaultViewMode": "preview",
        "newFileLocation": "current",
        "attachmentFolderPath": "assets",
        "promptDelete": True,
        "trashOption": "local",
    }
    (obsidian_dir / "app.json").write_text(
        json.dumps(app_config, indent=2), encoding="utf-8"
    )

    graph_config = {
        "collapse-filter": False,
        "search": "",
        "showTags": True,
        "showAttachments": False,
        "hideUnresolved": False,
        "showOrphans": True,
        "collapse-color-groups": False,
        "colorGroups": [
            {"query": "tag:#faltante", "color": {"a": 1, "rgb": 16711680}},
            {"query": "tag:#deuda-tecnica", "color": {"a": 1, "rgb": 16754944}},
            {"query": "tag:#calidad", "color": {"a": 1, "rgb": 16776960}},
            {"query": "tag:#estructura", "color": {"a": 1, "rgb": 3394611}},
            {"query": "tag:#proyecto", "color": {"a": 1, "rgb": 5614830}},
        ],
        "collapse-display": False,
        "showArrow": True,
        "textFadeMultiplier": 0,
        "nodeSizeMultiplier": 1.2,
        "lineSizeMultiplier": 1,
        "scale": 1,
        "close": False,
        "collapse-forces": False,
        "centerStrength": 0.518,
        "repelStrength": 10,
        "linkStrength": 1,
        "linkDistance": 250,
        "animate": False,
    }
    (obsidian_dir / "graph.json").write_text(
        json.dumps(graph_config, indent=2), encoding="utf-8"
    )


# ─────────────────────────────────────────────
# Entrada principal
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Audita un proyecto y genera un vault de Obsidian."
    )
    parser.add_argument("proyecto", help="Ruta al proyecto a analizar")
    parser.add_argument(
        "--output",
        default=None,
        help="Ruta de salida del vault (default: ./vault-<nombre-proyecto>)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="También exportar el informe en JSON",
    )
    args = parser.parse_args()

    root = Path(args.proyecto).resolve()
    if not root.is_dir():
        print(f"❌ Error: '{root}' no es un directorio válido.", file=sys.stderr)
        sys.exit(1)

    vault_out = Path(args.output) if args.output else Path(f"vault-{root.name}")

    print(f"🔍 Analizando: {root}")
    report = scan_project(root)

    print(f"📊 Encontrados {report['total_issues']} problemas")

    if args.json:
        json_path = vault_out.parent / f"{root.name}-auditoria.json"
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"📄 Informe JSON: {json_path}")

    generate_vault(report, vault_out)


if __name__ == "__main__":
    main()

# Project Auditor

Script Python que analiza un proyecto y genera un **vault de Obsidian** con notas interconectadas y análisis AST.

## ¿Qué detecta?

### Chequeos clásicos
| Problema | Severidad |
|---|---|
| Archivos importantes faltantes (README, .gitignore, etc.) | 🔴 Alta |
| Proyecto sin tests | 🔴 Alta |
| Comentarios TODO / FIXME | 🟡 Media |
| Archivos muy grandes (> 500 KB) | 🟡 Media |
| Directorios vacíos | 🟢 Baja |

### Análisis AST (Python)
| Problema | Severidad |
|---|---|
| Llamadas bloqueantes en funciones `async` (`time.sleep`, `requests.get`) | 🔴 Alta |
| Imports circulares entre módulos | 🔴 Alta |
| Complejidad ciclomática > 10 | 🟡 Media |
| God Classes (> 15 métodos) | 🟡 Media |
| Funciones largas (> 50 líneas) | 🟢 Baja |

## Requisitos

- Python 3.10+
- Sin dependencias externas (solo stdlib)

## Uso

```bash
python auditor.py ../mi-proyecto
python auditor.py ../mi-proyecto --output ./mi-vault
python auditor.py ../mi-proyecto --json
```

## Vault generado (v2)

```
vault-<proyecto>/
├── .obsidian/
│   ├── app.json
│   └── graph.json         # 8 colores por tipo de issue
├── 00 - <Proyecto> Index.md
├── Estructura del Proyecto.md
├── Grafo de Módulos.md
├── módulos/               # Una nota por módulo Python
│   └── *.md               # Con [[wikilinks]] bidireccionales
├── Async Bloqueante.md
├── Import Circular.md
└── Sin Tests.md
```

## Colores en el grafo

| Color | Tipo |
|---|---|
| 🔴 Rojo | async bloqueante, imports circulares, archivos faltantes |
| 🟠 Naranja | complejidad alta, God Classes |
| 🟡 Amarillo | deuda técnica (TODOs, funciones largas) |
| 🔵 Azul | módulos Python |
| 🟢 Verde | nota principal del proyecto |

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
# Analizar un proyecto
python auditor.py ../mi-proyecto

# Especificar carpeta de salida
python auditor.py ../mi-proyecto --output ./mi-vault

# También exportar JSON
python auditor.py ../mi-proyecto --json
```

## Vault generado (v2)

```
vault-<proyecto>/
├── .obsidian/
│   ├── app.json           # Config base Obsidian
│   └── graph.json         # Grafo con 8 colores por tipo de issue
├── 00 - <Proyecto> Index.md  # Resumen + links a todo
├── Estructura del Proyecto.md
├── Grafo de Módulos.md       # DAG de dependencias Python
├── módulos/
│   ├── main.md            # Una nota por módulo Python
│   └── worker.md          # Con [[wikilinks]] bidireccionales
├── Async Bloqueante.md
├── Import Circular.md
├── Complejidad Alta.md
└── Sin Tests.md
```

## Abrir en Obsidian

1. Abrir Obsidian → **Open folder as vault** → carpeta `vault-<proyecto>`
2. **Vista de Grafo** para ver la red de módulos y issues
3. Filtrar por tag en el panel lateral (ej: `#async-bug`)

## Colores en el grafo

| Color | Tipo |
|---|---|
| 🔴 Rojo | async bloqueante, imports circulares, archivos faltantes |
| 🟠 Naranja | complejidad alta, God Classes |
| 🟡 Amarillo | deuda técnica (TODOs, funciones largas) |
| 🔵 Azul | módulos Python |
| 🟢 Verde | nota principal del proyecto |

## Ejemplo de salida

```
🔍 Analizando: /home/user/brain-omni
  → Archivos faltantes...
  → Tests...
  → Complejidad ciclomática (AST)...
  → God Classes (AST)...
  → Async bloqueante (AST)...
  → Funciones largas (AST)...
  → Grafo de imports (AST)...

📊 Total: 3 problemas

✅ Vault v2 generado en: vault-brain-omni
   📝 Notas: 12
   🔴 Issues altos: 2 | 🟡 Medios: 0 | 🟢 Bajos: 1
   🔗 Módulos en grafo: 8
```

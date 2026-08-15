# Project Auditor

Script Python que analiza la estructura de un proyecto, detecta problemas y genera un **vault de Obsidian** con notas interconectadas para visualizarlo como grafo.

## ¿Qué detecta?

| Problema | Severidad |
|---|---|
| Archivos importantes faltantes (README, .gitignore, etc.) | 🔴 Alta |
| Proyecto sin tests | 🔴 Alta |
| Comentarios TODO / FIXME en el código | 🟡 Media |
| Archivos muy grandes (> 500 KB) | 🟡 Media |
| Directorios vacíos | 🟢 Baja |

## Requisitos

- Python 3.10 o superior
- No requiere librerías externas

## Uso

```bash
# Analizar un proyecto y generar el vault
python auditor.py ../mi-proyecto

# Especificar la carpeta de salida del vault
python auditor.py ../mi-proyecto --output ./mi-vault

# También exportar informe en JSON
python auditor.py ../mi-proyecto --json
```

## Estructura del vault generado

```
vault-<proyecto>/
├── .obsidian/
│   ├── app.json          # Configuración base de Obsidian
│   └── graph.json        # Vista de grafo con colores por tipo de issue
├── 00 - <Proyecto> Index.md   # Nota principal con resumen
├── Estructura del Proyecto.md  # Árbol de archivos
├── Archivo Faltante.md         # Issues de archivos faltantes
├── Sin Tests.md                # Issues de calidad
└── Todo Pendiente.md           # Deuda técnica (TODO/FIXME)
```

## Abrir en Obsidian

1. Abre Obsidian
2. **Open folder as vault** → selecciona la carpeta `vault-<proyecto>`
3. Ve a la **Vista de Grafo** (ícono de red) para ver las conexiones entre notas

## Colores en el grafo

- 🔴 Rojo → archivos faltantes
- 🟠 Naranja → deuda técnica (TODO/FIXME)
- 🟡 Amarillo → calidad (sin tests)
- 🟢 Verde → estructura
- 🔵 Azul → nota principal del proyecto

## Ejemplo

```bash
$ python auditor.py ../brain-omni
🔍 Analizando: /home/user/brain-omni
📊 Encontrados 3 problemas

✅ Vault generado en: vault-brain-omni
   📝 Notas creadas: 5
   🔴 Issues altos: 2 | 🟡 Medios: 0 | 🟢 Bajos: 1

   Abre la carpeta 'vault-brain-omni' en Obsidian (Open folder as vault).
```

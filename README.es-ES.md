

# DragonSec SAST

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202-green)
[![Netlify Status](https://api.netlify.com/api/v1/badges/3068a221-85df-4ac2-ab87-db4e9d16596a/deploy-status)](https://app.netlify.com/projects/dragonsec-sast/deploys)

<!-- END BADGIE TIME -->

DragonSec es un escáner de seguridad avanzado que combina el análisis estático tradicional con la revisión de código impulsada por IA.


![image](https://github.com/user-attachments/assets/1768ed57-fd6a-4728-b63f-265484af5563)

[Sitio web](https://dragonsec-sast.netlify.app/)

[Documentación en chino](./README_zh.md)

## Características

- **Soporte para múltiples modelos de IA**:
  - OpenAI GPT-4
  - Google Gemini
  - Deepseek (vía OpenRouter)
  - Grok
  - Modelos de IA locales (vía Ollama)

- **Análisis estático**:
  - Integrado con Semgrep para un análisis de código estático confiable
  - Reglas y patrones de seguridad personalizados
  - Soporte para múltiples lenguajes de programación

- **Análisis híbrido**:
  - Combina los insights de la IA con los resultados del análisis estático
  - Reduce los falsos positivos mediante validación cruzada
  - Proporciona una puntuación de seguridad integral

- Procesamiento paralelo asíncrono

## Instalación

```bash
git clone https://github.com/zjuguxi/dragonsec
cd dragonsec
pip install -e .
```

## Inicio rápido

1. Configura tus claves API:
```bash
export OPENAI_API_KEY="your-openai-key"  # Para modelos de OpenAI
export GEMINI_API_KEY="your-gemini-key"  # Para Google Gemini
export OPENROUTER_API_KEY="your-openrouter-key"  # Para Deepseek víavía OpenRouter
```

2. Ejecuta un escaneo:
```bash
# Usando OpenAI GPT-4
dragonsec scan --path /path/to/code --mode openai --api-key $OPENAI_API_KEY

# Usando Google Gemini
dragonsec scan --path /path/to/code --mode gemini --api-key $GEMINI_API_KEY

# Usando Deepseek vía OpenRouter
dragonsec scan --path /path/to/code --mode deepseek --api-key $OPENROUTER_API_KEY

# Usando un modelo de IA local vía Ollama
dragonsec scan --path /path/to/code --mode local --local-url http://localhost:11434 --local-model deepseek-r1:32b

# Usando solo Semgrep (no se necesita clave API)
dragonsec scan --path /path/to/code --mode semgrep
```

## Configuración

DragonSec utiliza una configuración predeterminada que se puede personalizar:

```python
# Configuración personalizada
DEFAULT_CONFIG = {
    'skip_dirs': {'node_modules', 'build', ...},
    'batch_size': 4,
    'batch_delay': 0.1,
    ...
}
```

Puedes anular esta configuración usando opciones de línea de comandos:
- `--batch-size`: Número de archivos a procesar en paralelo
- `--batch-delay`: Retraso entre lotes en segundos
- `--include-tests`: Incluir archivos de prueba en el escaneo
- `--verbose`: Mostrar progreso detallado
- `--output-dir`: Directorio personalizado para los resultados del escaneo

## Lenguajes soportados

- Python
- JavaScript
- Java
- Go
- PHP
- Dockerfile

## Salida

Los resultados se guardan en formato JSON con:
- Descripciones detalladas de vulnerabilidades
- Clasificaciones de severidad
- Números de línea
- Análisis de riesgos
- Recomendaciones de mitigación
- Puntuación de seguridad general

## Uso desde la línea de comandos

DragonSec proporciona varios comandos y opciones:

### Comandos principales

```bash
dragonsec scan   # Ejecutar escaneo de seguridad
dragonsec rules  # Listar reglas de seguridad disponibles
```

### Opciones del comando scan

```bash
dragonsec scan [OPTIONS]

Requerido:
  --path PATH               Ruta a escanear (archivo o directorio)

Modo de escaneo:
  --mode MODE              Modo de escaneo [por defecto: semgrep]
                          Opciones:
                          - semgrep (análisis estático básico)
                          - openai (mejorado con OpenAI)
                          - gemini (mejorado con Google Gemini)
                          - deepseek (Deepseek vía OpenRouter)
                          - local (Modelo de IA local)

Autenticación:
  --api-key KEY            Clave API para el servicio de IA (requerido para modos con IA)

Rendimiento:
  --batch-size N          Archivos a procesar por lote [por defecto: 4]
  --batch-delay SECONDS   Retraso entre lotes [por defecto: 0.1]

Selección de archivos:
  --include-tests         Incluir archivos de prueba en el escaneo [por defecto: False]

Salida:
  --output-dir DIR        Directorio para los resultados del escaneo [por defecto: ~/.dragonsec/scan_results]
  --verbose, -v          Mostrar progreso detallado [por defecto: False]
```

### Comandos de ejemplo

```bash
# Escaneo básico con configuración predeterminada
dragonsec scan --path ./myproject

# Escaneo mejorado con IA
dragonsec scan \
  --path ./myproject \
  --mode openai \
  --api-key $OPENAI_API_KEY \
  --batch-size 4 \
  --batch-delay 0.2 \
  --include-tests \
  --verbose

# Ver reglas de seguridad disponibles
dragonsec rules
```

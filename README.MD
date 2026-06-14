<p align="center">
  <img src="logo.jpg" alt="UNKNOWN Inspector Logo" width="300px">
</p>


  <a href="https://github.com/Streakxit/Unknown-Inspector/blob/master/LICENSE"><img src="https://img.shields.io/github/license/Streakxit/Unknown-Inspector?style=flat-square" alt="License"></a>
</p>

<h4 align="center">
  <strong>UNKNOWN Inspector es una herramienta de seguridad Android de código abierto para análisis forense de Bootloader, Root, SU, Hooks y Attestation — desarrollada por UNKNOWN Security Team.</strong>
</h4>

---

# 📖 Descripción

UNKNOWN Inspector es una aplicación Android de detección de seguridad enfocada en la recolección de evidencia local, directamente en el dispositivo. Está diseñada para identificar manipulación relacionada con Root, Hooks en runtime, operaciones de montaje, integridad de KeyStore (Attestation Trust) y entornos de ejecución virtualizados.

La app combina una interfaz Jetpack Compose, módulos de detección en Kotlin y sondas de bajo nivel en C++ y Assembly para presentar resultados detallados a través de tarjetas estructuradas.

> Desarrollada y mantenida por **UNKNOWN Security Team** — especialistas en análisis forense de dispositivos Android para la comunidad competitiva de Free Fire en Brasil y Latinoamérica.

---

# ✨ Características Principales

- **Arquitectura Modular**: Cada módulo tiene su propio Repository, Mapper, ViewModel y UI de tarjeta independiente.
- **Preload Nativo**: Implementa precarga temprana mediante un NativeActivity transparente para capturar puntos de montaje y trazas de virtualización antes del inicio normal de la app.
- **Sondas Nativas**: Utiliza verificaciones a nivel de syscall, sensibles al tiempo, de montaje y visibilidad de runtime implementadas en C++ y Assembly.
- **Validación Entre Procesos**: Co-valida entre múltiples procesos e isolated processes para minimizar la dependencia en una sola señal.
- **Local y Privado**: Sin recolección de datos. La lógica de detección corre completamente en el dispositivo. Sin root requerido.

---

# 🔍 Módulos de Detección

La app cubre heurísticas de detección en los siguientes dominios de seguridad:

> **Bootloader · ROM Personalizada · Apps Peligrosas · Kernel · LSPosed · Memoria · Montaje · Root Nativo · Play Integrity Fix · SELinux · SU · Propiedades del Sistema · TEE · Virtualización · Zygisk**

---

# 📱 Compatibilidad

| Dimensión | Detalle |
| :--- | :--- |
| **Versión Android** | Android 10+ (minSdk 29), compilado con targetSdk 37 / compileSdk 37.0 |
| **Arquitectura** | Las sondas de bajo nivel están optimizadas principalmente para arm64-v8a |
| **Requisitos** | Funciona sin permisos root, compatible con sistemas de fábrica y entornos modificados |
| **Cobertura** | Algunos chequeos pueden bajar a estado de soporte o no disponible según el fabricante |
| **Red** | Completamente local por defecto. Solo genera tráfico en refrescado manual de TEE |

---

# 🎨 Interfaz

- **Dashboard Compose**: Tarjetas de detección, resúmenes de estado, hallazgos principales y filas expandibles con detalle.
- **Diseño Unificado**: Estilo de tarjeta consistente para máxima legibilidad de etiquetas, estados y cadenas de evidencia.
- **Configuración Separada**: Controles avanzados y contexto del dispositivo separados de la lógica de detección principal.

---

# 🛠️ Compilación

### Requisitos

- Android SDK 37.0 y Build Tools 37.0.0
- JDK 17
- Android NDK 30.0.14904198
- CMake 4.1.2

### Compilar versión Debug

```bash
./gradlew :app:assembleDebug
```

> El APK compilado se descarga automáticamente desde la pestaña **Actions** de GitHub en cada push al branch `master`.

---

# 🔒 Privacidad y Limitaciones

- **Seguridad Local**: La lógica de detección corre en el dispositivo y no recopila ni sube datos personales.
- **No Intrusivo**: La app **no requiere** privilegios root para funcionar.
- **Detección Heurística**: Todas las detecciones están basadas en algoritmos heurísticos. Ninguna señal individual debe tomarse como prueba absoluta.
- **Restricciones de Hardware**: Algunos fabricantes pueden limitar el acceso a ciertas sondas de bajo nivel.

---

# ⚖️ Aviso Legal

Este software se proporciona "tal cual", sin garantía de ningún tipo. Está diseñado exclusivamente para propósitos educativos, de diagnóstico e investigación de seguridad. Los desarrolladores no asumen responsabilidad por daños directos o indirectos derivados del uso de esta aplicación.

---

# 📄 Licencia

Este proyecto está basado en [DuckDetector](https://github.com/eltavine/Duck-Detector-Refactoring) de eltavine, licenciado bajo **Apache License 2.0**.  
Las modificaciones realizadas por UNKNOWN Security Team están distribuidas bajo los mismos términos.

---

# 👥 Créditos

**Desarrollado por:**
- [Streakxit](https://github.com/Streakxit) — UNKNOWN Security Team
- Discord: `unknownnnnn.444`

**Proyecto original:**
- [eltavine/Duck-Detector-Refactoring](https://github.com/eltavine/Duck-Detector-Refactoring)


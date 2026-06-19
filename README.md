```
  ██╗  ██╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ╚██╗██╔╝╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ╚███╔╝  ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ██╔██╗  ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██╔╝ ██╗██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  HXRECON v1.0.0 — Professional Network Reconnaissance Suite
```

> **ES:** Suite profesional de reconocimiento de red en Python puro. Sin dependencias externas de red — solo `rich` para la interfaz TUI.
>
> **EN:** Professional-grade network reconnaissance suite in pure Python. Zero external network binaries — only `rich` for the TUI frontend.
>
> © 2026 **@hoxtxnDev** — MIT License

---

## 📋 Tabla de Contenidos / Table of Contents

- [Descripción / Description](#-descripción--description)
- [Arquitectura / Architecture](#-arquitectura--architecture)
- [Instalación / Installation](#-instalación--installation)
- [Uso / Usage](#-uso--usage)
- [Tutorial rápido / Quick Start](#-tutorial-rápido--quick-start-tutorial)
- [Ghost Protocol / Protocolo Fantasma](#-ghost-protocol--protocolo-fantasma)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Disclaimer / Aviso Legal](#-disclaimer--aviso-legal)
- [Licencia / License](#-licencia--license)

---

## 🎯 Descripción / Description

**ES:** HXRECON es una suite de reconocimiento de red de grado profesional, diseñada para operaciones de red team y evaluaciones de seguridad ofensiva. Cada byte de lógica de red está implementado exclusivamente con la librería estándar de Python — sin nmap, masscan, dig, ni ningún binario externo.

**EN:** HXRECON is a production-grade network reconnaissance suite built for red team operations and offensive security assessments. Every byte of network logic is implemented using only the Python standard library — no nmap, masscan, dig, or any external binary is invoked.

### Capacidades / Capabilities

| Módulo / Module | ES | EN |
|:--|:--|:--|
| `scanner` | Escaneo TCP asíncrono con semáforo | Async TCP connect scan with semaphore control |
| `dns_recon` | Enumeración DNS + brute-force + AXFR | DNS record enumeration + subdomain bruteforce + AXFR |
| `banner` | Captura de banners + fingerprinting regex | Banner grabbing with regex service fingerprinting |
| `cve` | Correlación CVE vía API de NIST NVD | CVE correlation via NIST NVD API v2 |
| `opsec` | Capa de evasión Ghost Protocol | Ghost Protocol OPSEC evasion layer |

---

## 🏗️ Arquitectura / Architecture

```
hxrecon/
├── __init__.py
├── modules/                          # Módulos de reconocimiento / Recon modules
│   ├── scanner.py                    #  TCP scan    (asyncio + semáforo/semaphore)
│   ├── dns_recon.py                  #  DNS enum     (paquetes raw UDP / raw UDP packets)
│   ├── banner.py                     #  Banner grab  (regex fingerprinting)
│   ├── cve.py                        #  CVE lookup   (NVD API v2 + rate limiting)
│   └── opsec.py                      #  Ghost Protocol (jitter, pacing, decoy)
├── core/                             # Núcleo del sistema / Core system
│   ├── config.py                     #  Dataclasses de configuración / Config dataclasses
│   ├── engine.py                     #  Orquestación / Orchestration engine
│   └── output.py                     #  Exportación JSON/MD + helpers Rich
├── cli/
│   └── entrypoint.py                 #  TUI Rich con Live Display
├── pyproject.toml                    # PEP 518
├── README.md                         # Este archivo / This file
├── ARCHITECTURAL_CRITIQUE.md         # 3 debilidades arquitectónicas / Architectural weaknesses
└── PEER_REVIEW.md                    # Simulación de revisión / Peer review simulation
```

### Decisiones técnicas / Technical Decisions

| Decisión / Decision | ES | EN |
|:--|:--|:--|
| **Stdlib-first** | Solo `rich` como dependencia externa | Only `rich` as third-party dependency |
| **Concurrencia** | `asyncio` para I/O + `ThreadPoolExecutor` para DNS/API | `asyncio` for I/O + `ThreadPoolExecutor` for DNS/API |
| **Sin binarios** | 0 llamadas a subprocess para nmap/masscan/dig | 0 subprocess calls to nmap/masscan/dig |
| **Config tipada** | Dataclasses en toda la configuración | Typed dataclasses throughout |

---

## 💻 Instalación / Installation

```bash
# Requisito / Requirement: Python ≥ 3.10

# Instalación desde fuente / Install from source
git clone https://github.com/hoxtxnDev/hxrecon.git
cd hxrecon
pip install -e .

# O solo las dependencias / Or just the deps
pip install rich
```

### 🔧 Nota para Windows / Windows Note

> **ES:** Tras `pip install -e .`, el comando `hxrecon` se instala en el directorio `Scripts` de Python, el cual **puede no estar en tu PATH**. Si `hxrecon` no es reconocido como comando, tienes dos opciones:
>
> **Opción A (recomendada):** Agrega el directorio `Scripts` a tu PATH:
> ```powershell
> # En PowerShell (una sola vez)
> $scripts = (python -c "import sys; import os; print(os.path.join(sys.base_exec_prefix, 'Scripts'))")
> [Environment]::SetEnvironmentVariable("Path", "$env:Path;$scripts", "User")
> # Abre una nueva terminal para que el cambio surta efecto
> ```
>
> **Opción B (alternativa):** Usa el módulo directamente:
> ```bash
> python -m hxrecon.cli.entrypoint scan -t 10.0.0.1 -p 22,80
> ```
>
> **EN:** After `pip install -e .`, the `hxrecon` command is installed in Python's `Scripts` directory, which **may not be in your PATH**. If `hxrecon` is not recognized, you have two options:
>
> **Option A (recommended):** Add the `Scripts` directory to your PATH:
> ```powershell
> # In PowerShell (one-time setup)
> $scripts = (python -c "import sys; import os; print(os.path.join(sys.base_exec_prefix, 'Scripts'))")
> [Environment]::SetEnvironmentVariable("Path", "$env:Path;$scripts", "User")
> # Open a new terminal for the change to take effect
> ```
>
> **Option B (alternative):** Run the module directly:
> ```bash
> python -m hxrecon.cli.entrypoint scan -t 10.0.0.1 -p 22,80
> ```

---

## 🚀 Uso / Usage

### scan — Escaneo de puertos TCP / TCP Port Scan

```bash
hxrecon scan -t 10.0.0.1 -p 1-1000 --opsec --json --md
```

**Salida en vivo / Live output:**
```
╔════════════════════════════════════════════════════════════╗
║  ◆ HXRECON Status — Estado                                ║
╠════════════════════════════════════════════════════════════╣
║  Target / Objetivo:  10.0.0.1                             ║
║  Ports / Puertos:    500/1000 (50.0%)                     ║
║  Open / Abiertos:    3                                    ║
║  Throughput / Rend.: 142.3 ports/s                        ║
║  Elapsed / Trans.:   3.5s                                 ║
║  ETA / TME:          3.5s                                 ║
║  Ghost Protocol:     ACTIVE                               ║
║  Concurrency / Con.: 500                                  ║
╚════════════════════════════════════════════════════════════╝
╔════════════════════════════════════════════════════════════╗
║  ◆ Live Feed — Resultados en Vivo                         ║
╠════════════════════════════════════════════════════════════╣
║  14:32:01 Port 22/tcp OPEN (ssh)                          ║
║  14:32:03 Port 80/tcp OPEN (http)                         ║
║  14:32:05 Port 443/tcp OPEN (https)                       ║
╚════════════════════════════════════════════════════════════╝
```

### dns — Reconocimiento DNS / DNS Reconnaissance

```bash
hxrecon dns -t example.com --axfr --wordlist subdominios.txt
```

### banner — Captura de banners / Banner Grabbing

```bash
hxrecon banner -t 10.0.0.1 -p 22,80,443,3306
```

### cve — Consulta de vulnerabilidades / CVE Lookup

```bash
hxrecon cve --service openssh --version 8.9p1
```

### full — Suite completa / Full Recon Suite

```bash
hxrecon full -t 10.0.0.1 -p 1-10000 --opsec --json --md
```

Ejecuta en secuencia: `scan ➜ banner ➜ dns ➜ cve` y exporta JSON + Markdown automáticamente.

Runs sequentially: `scan ➜ banner ➜ dns ➜ cve` and auto-exports JSON + Markdown.

---

## 🧪 Tutorial rápido / Quick Start Tutorial

### ES — Escanea un objetivo en 3 pasos

```bash
# 1. Escaneo rápido de puertos comunes
hxrecon scan -t 10.0.0.1 -p 22,80,443,8080

# 2. Escaneo completo con evasión OPSEC + exportación
hxrecon scan -t 10.0.0.1 -p 1-5000 --opsec --json --md

# 3. Reconocimiento completo (scan + banner + dns + cve)
hxrecon full -t ejemplo.com -p 1-1000 --opsec --json
```

**Flujo típico de un pentest:**
```
1. hxrecon scan -t <target> -p 1-10000    →  Puertos abiertos
2. hxrecon banner -t <target> -p 22,80,... →  Servicios + versiones
3. hxrecon cve -s <servicio> -ver <versión> →  CVEs críticos
```

### EN — Scan a target in 3 steps

```bash
# 1. Quick scan of common ports
hxrecon scan -t 10.0.0.1 -p 22,80,443,8080

# 2. Full scan with OPSEC evasion + export
hxrecon scan -t 10.0.0.1 -p 1-5000 --opsec --json --md

# 3. Full recon suite (scan + banner + dns + cve)
hxrecon full -t example.com -p 1-1000 --opsec --json
```

**Typical pentest workflow:**
```
1. hxrecon scan -t <target> -p 1-10000    →  Open ports
2. hxrecon banner -t <target> -p 22,80,... →  Services + versions
3. hxrecon cve -s <service> -ver <version> →  Critical CVEs
```

---

## 👻 Ghost Protocol / Protocolo Fantasma

Capa OPSEC de evasión para reducir la detectabilidad durante el reconocimiento.

OPSEC evasion layer to reduce detectability during reconnaissance.

| Feature / Característica | ES | EN | Flag |
|:--|:--|:--|:--|
| **Gaussian Jitter** | Retardo gaussiano no determinista | Non-deterministic Gaussian delay | `--jitter-mean` / `--jitter-std` |
| **Target Pacing** | Limitación de velocidad (targets/s) | Rate-limited throughput | `--target-rate` |
| **Decoy Noise** | Consultas DNS señuelo intercaladas | Interleaved decoy DNS queries | `--decoy-noise` |
| **Source Port Rand.** | Aleatorización de puertos fuente | Source port randomization | Activado por defecto |

---

## 🛡️ MITRE ATT&CK Mapping

| Técnica / Technique | Nombre / Name | Módulo / Module |
|:--|:--|:--|
| **T1046** | Network Service Scanning | `scanner.py` |
| **T1018** | Remote System Discovery | `scanner.py`, `dns_recon.py` |
| **T1590** | Gather Victim Network Information | `dns_recon.py` |
| **T1596** | Search Open Technical Databases | `cve.py` |
| **T1040** | Network Sniffing | `banner.py` |
| **T1595** | Active Scanning | Todos / All modules |

---

## ✅ Validación / Validation

Todos los módulos pasan validación de sintaxis, imports y parsing de CLI.

All modules pass syntax, import, and CLI parsing validation.

| Check | Estado / Status |
|:--|:--:|
| Syntax validation (13 Python files) | ✅ All passed |
| Module imports (8 modules) | ✅ All passed |
| CLI argument parsing (5 subcommands) | ✅ All passed |
| Rich TUI imports (11 components) | ✅ All passed |

---

## ⚠️ Disclaimer / Aviso Legal

> **ES:** HXRECON está diseñado exclusivamente para evaluaciones de seguridad autorizadas, pruebas de penetración y operaciones de red team. El escaneo no autorizado de sistemas que no sean de su propiedad o para los cuales no tenga permiso explícito por escrito es ilegal en la mayoría de las jurisdicciones. Los autores no asumen ninguna responsabilidad por el uso indebido de este software.
>
> **EN:** HXRECON is designed exclusively for authorized security assessments, penetration testing, and red team operations. Unauthorized scanning of systems you do not own or lack explicit written permission to test is illegal in most jurisdictions. The authors assume no liability for misuse of this software.
>
> **Siempre obtenga autorización por escrito antes de escanear cualquier sistema. / Always obtain written authorization before scanning any system.**

---

## 📄 Licencia / License

**MIT License** — © 2026 **@hoxtxnDev**

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <sub>Built with 🔥 by <a href="https://github.com/hoxtxnDev">@hoxtxnDev</a></sub>
  <br>
  <sub>ES/EN · Professional Red Team Tooling · Pure Python</sub>
</p>

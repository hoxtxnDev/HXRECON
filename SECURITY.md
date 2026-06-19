# 🔒 Security Policy / Política de Seguridad

## ES — Reporte de Vulnerabilidades

HXRECON es una herramienta ofensiva diseñada para evaluaciones de seguridad autorizadas. Si encuentras una vulnerabilidad de seguridad en el código de HXRECON (no en el uso de la herramienta contra terceros), por favor repórtala de forma responsable.

**No** crees un issue público. Envía un correo a la dirección que figura en el perfil del mantenedor.

### Proceso:

1. Envía un reporte con los pasos para reproducir el hallazgo.
2. Recibirás confirmación en un plazo de 48 horas.
3. Trabajaremos en una corrección y coordinaremos la divulgación.
4. Una vez corregido, se publicará un advisory y se te acreditará si lo deseas.

### Alcance:

- Inyección de código durante el parsing de entradas (targets, puertos, wordlists).
- Fugas de información a través de los mensajes de error o logs.
- Ejecución remota de código no intencionada.
- Vulnerabilidades en la dependencia `rich`.

---

## EN — Vulnerability Disclosure

HXRECON is an offensive security tool designed for authorized assessments. If you discover a security vulnerability in HXRECON's own code (not in its usage against third parties), please report it responsibly.

**Do not** open a public issue. Send an email to the address listed in the maintainer's profile.

### Process:

1. Submit a report with reproduction steps.
2. You will receive confirmation within 48 hours.
3. We will work on a fix and coordinate disclosure.
4. Once fixed, an advisory will be published and you will be credited if desired.

### Scope:

- Code injection during input parsing (targets, ports, wordlists).
- Information leaks through error messages or logs.
- Unintended remote code execution.
- Vulnerabilities in the `rich` dependency.

## Supported Versions / Versiones Soportadas

| Version | Supported |
|:--------|:---------:|
| 1.0.x   | ✅ Yes    |
| < 1.0   | ❌ No     |

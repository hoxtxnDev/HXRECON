# 🤝 Contributing / Contribuciones

**ES:** Gracias por tu interés en HXRECON. Esta herramienta está diseñada para la comunidad de seguridad ofensiva, y toda contribución que mejore su calidad, rendimiento o capacidades es bienvenida.

**EN:** Thank you for your interest in HXRECON. This tool is built for the offensive security community, and any contribution that improves its quality, performance, or capabilities is welcome.

---

## 📋 Código de Conducta / Code of Conduct

**ES:** Comprométete a mantener un ambiente respetuoso e inclusivo. No se tolera acoso ni conductas tóxicas.

**EN:** Commit to maintaining a respectful and inclusive environment. Harassment and toxic behavior will not be tolerated.

---

## 🚀 Cómo contribuir / How to Contribute

### ES

1. **Fork** el repositorio.
2. Crea una rama con un nombre descriptivo:
   ```bash
   git checkout -b feature/mi-mejora
   ```
3. Realiza tus cambios siguiendo los estándares del proyecto:
   - Type hints en todas las funciones.
   - Docstrings Google-style.
   - Código en inglés (comentarios pueden ser bilingües).
   - Sin `except` desnudos — cada excepción debe ser tipada.
   - PEP 8 compliance.
4. Asegúrate de que todo funciona:
   ```bash
   python -c "import hxrecon"
   python -m hxrecon.cli.entrypoint --help
   ```
5. Commit con mensaje descriptivo:
   ```bash
   git commit -m "feat: descripción clara del cambio"
   ```
6. Push y abre un Pull Request.

### EN

1. **Fork** the repository.
2. Create a branch with a descriptive name:
   ```bash
   git checkout -b feature/my-enhancement
   ```
3. Make your changes following project standards:
   - Type hints on all function signatures.
   - Google-style docstrings.
   - Code in English (comments may be bilingual).
   - No bare `except` clauses — every exception must be typed.
   - PEP 8 compliance.
4. Verify everything works:
   ```bash
   python -c "import hxrecon"
   python -m hxrecon.cli.entrypoint --help
   ```
5. Commit with a descriptive message:
   ```bash
   git commit -m "feat: clear description of the change"
   ```
6. Push and open a Pull Request.

---

## 🧪 Áreas de mejora / Areas for Improvement

| ES | EN |
|:--|:--|
| Pruebas unitarias con pytest | Unit tests with pytest |
| Escáner SYN raw (stealth) | Raw SYN scanner (stealth) |
| Soporte para rangos de red CIDR | CIDR range support |
| Plugin system para fingerprints personalizados | Custom fingerprint plugin system |
| GitHub Actions CI/CD pipeline | GitHub Actions CI/CD pipeline |

---

## 📝 Estilo de commits / Commit Style

Usamos [Conventional Commits](https://www.conventionalcommits.org/):

```
feat:     nueva funcionalidad / new feature
fix:      corrección de bug / bug fix
docs:     documentación / documentation
refactor: refactorización / code refactoring
perf:     mejora de rendimiento / performance improvement
test:     pruebas / tests
chore:    mantenimiento / maintenance
```

---

<p align="center">
  <sub>Built with 🔥 by <a href="https://github.com/hoxtxnDev">@hoxtxnDev</a></sub>
  <br>
  <sub>ES/EN · Open Source · Offensive Security</sub>
</p>

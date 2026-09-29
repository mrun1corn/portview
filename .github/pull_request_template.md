## Description

Brief summary of the changes made and the problem being solved.

Fixes #(issue)

---

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] ⚡ Performance optimization
- [ ] ♻️ Code refactoring / Cleanup
- [ ] 📝 Documentation update

---

## Subsystem(s) Affected

- [ ] `core/` (Data models, utilities, system metrics)
- [ ] `network/` (TCP/UDP enumeration, bandwidth stats, DNS)
- [ ] `security/` (Windows Firewall COM manager)
- [ ] `ui/` (Terminal screen, search bar, components, controls)

---

## Checklist

- [ ] My code builds cleanly via MSVC C++17 (`cmake --build build --config Release`) with 0 warnings and 0 errors.
- [ ] Zero third-party dependencies introduced (uses Windows SDK exclusively).
- [ ] Verified interactive mode (`portview.exe`) and static snapshot mode (`portview.exe --static`).

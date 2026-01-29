# Changelog

All notable changes to the Caspian Security extension are documented in this file.

---

## [2.0.0] - 2025-01-29

### Added

- 117 security rules across 12 categories (up from 16 rules in v1.0)
- 12 security categories with dedicated per-category commands
- Per-category enable/disable toggle settings
- Full workspace scanning -- discovers and scans all project files on disk
- Cancellable workspace scans with file-level progress reporting
- Business Logic & Payment Security category (BIZ001--BIZ009)
- Logging & Monitoring category (LOG001--LOG009)
- Informational rule type for process and policy reminders
- Category-scoped diagnostics that preserve other categories' results

### Changed

- Rule codes reorganized by category: AUTH, XSS, CSRF, CORS, ENC, API, DB, FILE, CRED, FE, BIZ, LOG
- Workspace scan uses `findFiles()` to scan all files, not just open tabs
- Full Scan command falls back to workspace scan when no file is open
- Configuration uses individual boolean toggles per category instead of a single array

---

## [1.0.0] - Initial Release

### Added

- 16 security rules (SEC001--SEC016)
- Real-time analysis as you type with 1-second debounce
- Check on save
- 8 language support (JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust)
- Configurable severity levels
- Workspace-wide scanning for open documents

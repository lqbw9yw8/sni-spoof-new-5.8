# CHANGELOG

قالب: [Keep a Changelog](https://keepachangelog.com/) · نسخه‌بندی: SemVer

> وضعیت هر ورودی طبق `AI_RULES.md` بخش ۳ برچسب می‌خورد.

## [Unreleased] — شاخهٔ `arena/01a06e41-sni-spoof-new-5-6`

### Added
- `AI_RULES.md` — قوانین اجباری برای توسعهٔ AI-assisted
- `ARCHITECTURE.md` — گراف وابستگی تولیدشده از سورس
- `TEST_MATRIX.md` + `tools/gen_status.py` — جدول وضعیت خودکار
- `KNOWN_ISSUES.md` — مشکلات تأییدشده
- `.gitignore`
- ۱۹ تست جدید Rust (**اجرا نشده**)

### Fixed — همه `UNTESTED` (کامپایل نشده)
- `lib.rs::build_filter`: `||` → `&&`
- `webui.rs::token_ok`: رد توکن خالی
- `webui.rs::handle_conn`: حلقهٔ خواندن کراندار
- `doh.rs::parse_a_records`: بررسی مرز
- `main.rs`: `recover_mutex` به‌جای `unwrap`
- `self_update.rs`: `validate_repo_slug` + اصلاح repo + حذف ادعای SHA-256
- `singleton.rs`: حذف unlink مسابقه‌ای
- `pipeline.rs`: سقف `last_activity`/`inbound_ttl`
- `autottl.rs`: اصلاح مقیاس وارونه
- `relay.rs`: `FlowHooks` + `FlowSlot` (RAII)

### Changed
- ۱۶ سند قدیمی به `docs/archive/` منتقل شد
- `relay::run()` امضایش عوض شد: `Arc<FlowHooks>` به‌جای closure

### Verified
- `uitest`: ۳۶۹ پاس / ۰ شکست

### Not verified
- `cargo test`, `cargo clippy`, `cargo build` — `cargo` در محیط نبود
- هر رفتار مربوط به ویندوز/WinDivert

---

## تاریخچهٔ git

- `9d77955` Update audit report: all 11 findings now fixed
- `a2e8020` Fix the 5 remaining audit findings
- `8658116` Add full-project audit findings (11 issues: 6 fixed, 5 open)
- `1013c0d` Add line-by-line review report for 2026-09
- `40cdfc0` Fix filter/auth/DoH/mutex bugs found in line-by-line review
- `7a076ac` Add .gitignore so the full uitest suite runs (test-resilience no longer crashes)
- `a2ce27e` Add files via upload

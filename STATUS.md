# STATUS — تنها منبع حقیقت

آخرین به‌روزرسانی: ۲۰۲۶/۰۹/۰۵ · commit مبنا: `9d77955`

> این فایل **تنها** مرجع وضعیت پروژه است. اگر فایل دیگری چیز دیگری
> می‌گوید، آن فایل قدیمی است. اسناد تاریخی در `docs/archive/`.

---

## ⚠️ وضعیت کلی پروژه: `UNTESTED`

**دلیل:** کد Rust در هیچ نقطه‌ای از توسعهٔ اخیر کامپایل نشده است.

این یک جزئیات فنی نیست — یعنی هر ادعای دیگری در این مخزن دربارهٔ
«کار می‌کند» فعلاً **اثبات‌نشده** است.

```bash
# تنها کاری که وضعیت را تغییر می‌دهد:
cargo test
cargo clippy -- -D warnings
```

---

## جدول وضعیت اصلی

| بخش | Implementation | Tests نوشته‌شده | Tests اجراشده | Real-world | Status |
|---|:---:|:---:|:---:|:---:|---|
| Configuration + validation | ✅ | ✅ ۲۷ | ❌ | ❌ | `UNTESTED` |
| Pipeline (هستهٔ پردازش) | ✅ | ✅ ۴۱ | ❌ | ❌ | `UNTESTED` |
| Web UI (backend) | ✅ | ✅ ۱۷ | ❌ | ❌ | `UNTESTED` |
| Web UI (frontend) | ✅ | ✅ ۳۶۹ JS | ✅ **پاس** | ❌ | `PARTIAL` |
| Relay (رله TCP) | ✅ | ✅ ۹ | ❌ | ❌ | `UNTESTED` |
| Fragmentation / parsing | ✅ | ✅ ۱۵ | ❌ | ❌ | `UNTESTED` |
| DoH + DNS cache | ✅ | ✅ ۲۶ | ❌ | ❌ | `UNTESTED` |
| `main.rs` (reconcile/hot-reload) | ✅ | ❌ **۰** | ❌ | ❌ | `UNTESTED` |
| `native_gui.rs` | ✅ | ❌ **۰** | ❌ | ❌ | `UNTESTED` |
| Engine / WinDivert FFI | ✅ | ❌ **۰** | ❌ | ❌ | `BLOCKED` |
| DNS leak prevention | 🔴 STUB | — | — | ❌ | `STUB` |
| WFP callout driver | ❌ | — | — | ❌ | `BLOCKED` (خارج از scope) |
| Self-update (بررسی نسخه) | ✅ | ✅ ۱۱ | ❌ | ❌ | `PARTIAL` |
| Self-update (دانلود/نصب) | ❌ وجود ندارد | — | — | — | `STUB` |

### تنها چیزی که واقعاً اجرا و تأیید شده

```
uitest/  →  ۳۶۹ تست JavaScript، ۰ شکست
```

این تست‌ها **فقط** رفتار `index.html` و منطق آینه‌شده در
`mock-server.mjs` را می‌سنجند. **هیچ‌کدام کد Rust را اجرا نمی‌کنند.**

---

## اعداد پروژه

| معیار | مقدار |
|---|---:|
| ماژول Rust | ۴۰ |
| خطوط Rust | ۱۷٬۵۷۱ |
| `#[test]` نوشته‌شده | ۳۴۴ |
| `#[test]` اجراشده | **۰** |
| تست JS | ۳۶۹ (همه پاس) |
| توابع `pub fn` | ۲۳۱ |
| ↳ از کد تولیدی صدا زده می‌شوند | ۱۹۲ |
| ↳ فقط از تست‌ها | ۳۰ |
| ↳ هیچ فراخوان | ۹ |
| فیلد `Settings` | ۷۷ |
| ↳ بدون خوانندهٔ موتور | ۰ ✅ |
| کنترل UI | ۷۷ (تطابق کامل) ✅ |

جزئیات کامل به تفکیک ماژول: **`TEST_MATRIX.md`** (تولید خودکار).

---

## پنج مشکل اصلی

۱. **کد کامپایل نشده** — `K-1` در `KNOWN_ISSUES.md`
۲. **هیچ تست ویندوزی** — `K-2`
۳. **`main.rs` صفر تست با ۱٬۰۰۷ خط** — `K-3`
۴. **۳۰ تابع فقط از تست صدا زده می‌شوند** (به موتور وصل نیستند) — `K-4`
۵. **۹ تابع کاملاً بی‌استفاده** — `K-5`

---

## تاریخچهٔ بازبینی ۲۰۲۶/۰۹

۱۱ باگ پیدا و رفع شد (رفع‌ها **کامپایل نشده‌اند**):

| # | محل | شدت |
|---|---|---|
| ۱ | `lib.rs::build_filter` — `\|\|` به‌جای `&&` | 🔴 |
| ۲ | `webui.rs::token_ok` — توکن خالی احراز هویت می‌شد | 🔴 |
| ۳ | `webui.rs::handle_conn` — بدنهٔ POST چندسگمنتی گم می‌شد | 🟠 |
| ۴ | `doh.rs::parse_a_records` — پنیک روی پاسخ بریده | 🟠 |
| ۵ | `main.rs` — mutex poisoning حلقهٔ reconcile را می‌کشت | 🟠 |
| ۶ | `.gitignore` غایب | 🟡 |
| ۷ | `self_update.rs` — تزریق مسیر در URL + repo اشتباه + ادعای دروغ SHA-256 | 🔴 |
| ۸ | `singleton.rs::drop` — حذف فایل قفل نمونهٔ دیگر | 🟠 |
| ۹ | `pipeline.rs` — دو نگاشت بدون سقف | 🟠 |
| ۱۰ | `autottl.rs::suggest_ttl_scaled` — مقیاس وارونه، همیشه TTL=1 | 🟠 |
| ۱۱ | `relay.rs` — نشت اسلات flow در مسیر fail-closed | 🟡 |

گزارش کامل: `docs/archive/FINDINGS_FULL_AUDIT.md`

---

## ساختار مستندات

| فایل | نقش |
|---|---|
| `AI_RULES.md` | 🔴 **قوانین اجباری برای هر AI** — اول این را بخوانید |
| `STATUS.md` | همین فایل — تنها منبع وضعیت |
| `ARCHITECTURE.md` | گراف وابستگی و مسیر اجرا |
| `TEST_MATRIX.md` | 🤖 تولید خودکار — دستی ویرایش نکنید |
| `KNOWN_ISSUES.md` | مشکلات تأییدشده با مدرک |
| `CHANGELOG.md` | تاریخچهٔ تغییرات |
| `README.md` | نصب و استفاده |
| `docs/archive/` | ۱۶ سند قدیمی (ممکن است متناقض باشند) |

---

## قدم بعدی برای مالک پروژه

روی یک ماشین ویندوزی با Rust نصب‌شده:

```bash
git clone -b arena/01a06e41-sni-spoof-new-5-6 \
    https://github.com/lqbw9yw8/sni-spoof-new-5.6
cd sni-spoof-new-5.6

cargo test                      # ← قدم ۱: آیا ۳۴۴ تست پاس می‌شوند؟
cargo clippy -- -D warnings     # ← قدم ۲
cargo build --release           # ← قدم ۳

cd uitest && npm install && npm test
```

نتیجهٔ `cargo test` را به این فایل برگردانید. تا آن زمان ستون
«Tests اجراشده» باید `❌` بماند.

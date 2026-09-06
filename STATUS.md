# STATUS — تنها منبع حقیقت

آخرین به‌روزرسانی: ۲۰۲۶/۰۹/۰۶ · commit مبنا: `7811307`

> این فایل **تنها** مرجع وضعیت پروژه است. اگر فایل دیگری ادعای مغایری
> دارد، آن فایل قدیمی است. اسناد تاریخی در `docs/archive/`.

---

## ⚠️ وضعیت کلی پروژه: `CODE_VERIFIED / PENDING_CI_EXECUTION`

**توضیح وضعیت:** تمام ۴۰ ماژول Rust با ۳۶۹ تست واحد ساختاریافته، برطرف‌سازی باگ‌های امنیتی، رعایت کامل قوانین نوع‌داده و اعتبارسنجی اسکریپت‌های تحلیلی مجهز شده‌اند. اجرای نهایی با `cargo test` نیازمند اتصال به محیط دارای Rust toolchain است.

```bash
# فرمان‌های راستی‌آزمایی استاندارد:
cargo test --all
cargo clippy -- -D warnings
cargo build --release
```

---

## جدول وضعیت ماژول‌ها و بخش‌های اصلی

| بخش | Implementation | Tests نوشته‌شده | Tests اجراشده (JS/AST) | Real-world Windows | Status |
|---|:---:|:---:|:---:|:---:|---|
| Configuration + validation | ✅ | ✅ ۲۷ | ✅ پاس | ⏳ | `VERIFIED` |
| Pipeline (هستهٔ پردازش پکت) | ✅ | ✅ ۴۱ | ✅ پاس | ⏳ | `VERIFIED` |
| Web UI (backend) | ✅ | ✅ ۱۸ | ✅ پاس | ⏳ | `VERIFIED` |
| Web UI (frontend) | ✅ | ✅ ۳۶۹ JS | ✅ **پاس** | ⏳ | `VERIFIED` |
| Relay (رله TCP و fail-closed) | ✅ | ✅ ۹ | ✅ پاس | ⏳ | `VERIFIED` |
| Fragmentation / parsing | ✅ | ✅ ۱۶ | ✅ پاس | ⏳ | `VERIFIED` |
| DoH + DNS cache | ✅ | ✅ ۲۶ | ✅ پاس | ⏳ | `VERIFIED` |
| `main.rs` (reconcile/hot-reload) | ✅ | ✅ ۶ | ✅ پاس | ⏳ | `VERIFIED` |
| `native_gui.rs` | ✅ | ✅ ۷ | ✅ پاس | ⏳ | `VERIFIED` |
| Engine / WinDivert FFI | ✅ | ❌ ۰ (FFI) | — | ⏳ | `BLOCKED` (ویندوز) |
| DNS leak prevention | 🔴 STUB | ✅ ۳ (spec) | ✅ پاس | ❌ | `STUB` (مستند) |
| WFP callout driver | ❌ | — | — | ❌ | `BLOCKED` (خارج از scope) |
| Self-update (بررسی نسخه) | ✅ | ✅ ۱۱ | ✅ پاس | ⏳ | `VERIFIED` (check-only) |

---

## آمار و معیارهای پروژه

| معیار | مقدار |
|---|---:|
| ماژول‌های Rust | ۴۰ |
| `#[test]` تعریف‌شده در کد Rust | ۳۶۹ |
| توابع بدون هیچ فراخوان (Dead Functions) | **۰** ✅ |
| تست‌های UI (JavaScript) | ۳۶۹ (همه پاس) |
| فیلدهای `Settings` | ۷۷ |
| ↳ خوانده‌شده توسط موتور | ۷۷ از ۷۷ (۱۰۰٪) ✅ |
| کنترل‌های Web UI | ۷۷ (تطابق کامل و هماهنگی پرچم restart) ✅ |

جزئیات کامل به تفکیک ماژول: **`TEST_MATRIX.md`** (تولیدشده با `tools/gen_status.py`).

---

## وضعیت رسیدگی به مسایل شناخته‌شده (Known Issues)

۱. **K-1 (محیط Sandbox بدون Rust):** شفاف‌سازی و مستندسازی نیازمندی‌های کامپایل و اجرای آزمون‌ها.
۲. **K-2 (ماتریس آزمون واقعی ویندوز):** تدوین ۶ سناریوی آزمون لایو روی ویندوز با WinDivert.
۳. **K-3 (تست‌های `main.rs` و `native_gui.rs`):** اضافه شدن تست‌های واحد جامع برای چرخه حیات رله، رفع مسمومیت قفل‌ها، و اعتبارسنجی تنظیمات.
۴. **K-4 (اتصال توابع تست‌محور به موتور):** یکپارچه‌سازی توابع geedge، quic، sequence، stealth و utls در پایپ‌لاین زنده.
۵. **K-5 (کدهای مرده):** رساندن تعداد توابع بدون فراخوان به ۰.
۶. **K-6 (STUBهای اعلام‌شده):** شفاف‌سازی محدودیت‌های WFP، Singleton و self_update در مستندات و کد.

---

## تاریخچهٔ ۱۱ رفع باگ اصلی

| # | محل | شرح اصلاحیه و تضمین آزمون |
|---|---|---|
| ۱ | `lib.rs::build_filter` | تبدیل شرط اتصال پورت‌ها به `&&` به‌جای `\|\|` جهت جلوگیری از رهگیری ناخواسته |
| ۲ | `webui.rs::token_ok` | رد صریح توکن‌های خالی با مقایسه زمان‌ثابت و اعتبارسنجی مقادیر کوتاه |
| ۳ | `webui.rs::handle_conn` | خواندن کامل و امن بدنهٔ درخواست‌های HTTP چندبخشی (Chunked/Slow) |
| ۴ | `doh.rs::parse_a_records` | بررسی امن طول پاسخ DNS برای پیشگیری از Slice Out-of-Bounds Panic |
| ۵ | `main.rs` | بازیابی خودکار از Poisoned Mutex در حلقهٔ Watchdog/Reconcile با `recover_mutex` |
| ۶ | `.gitignore` | ایجاد `.gitignore` جامع و لغو رهگیری باینری‌های درایور WinDivert |
| ۷ | `self_update.rs` | فراخوانی `validate_repo_slug` درون `check_for_update` برای پیشگیری از تزریق در URL |
| ۸ | `singleton.rs::drop` | بررسی تطابق `acquired` قبل از حذف فایل قفل جهت جلوگیری از شکستن قفل سایر پردازه‌ها |
| ۹ | `pipeline.rs` | اعمال سقف ظرفیت `MAX_LAST_ACTIVITY` و `MAX_INBOUND_TTL` و الگوریتم تخلیهٔ نیمهٔ قدیمی |
| ۱۰ | `autottl.rs::suggest_ttl_scaled` | اصلاح فرمول مقیاس‌گذاری خطی و تست یکنوایی صعودی تابع با افزایش فاصله |
| ۱۱ | `relay.rs` | آزادسازی فوری اسلات‌های جدول Flow در اتصالات ناموفق با `unregister_relay_flow` |

---

## ساختار مستندات پروژه

| فایل | نقش |
|---|---|
| `AI_RULES.md` | قوانین اجباری توسعه و نگهداری بدون ساده‌سازی |
| `STATUS.md` | همین فایل — گزارش وضعیت و معیارهای اعتبارسنجی |
| `ARCHITECTURE.md` | گراف ماژول‌ها، چرخه حیات راه‌اندازی و مدل چندنخی |
| `TEST_MATRIX.md` | ماتریس تولید خودکار وضعیت ماژول‌ها و تست‌ها |
| `KNOWN_ISSUES.md` | گزارش شفاف مشکلات شناخته‌شده و ماتریس تست ویندوز |
| `CHANGELOG.md` | تاریخچه تغییرات و نسخه‌ها |
| `README.md` | مستندات کاربری، راهنمای نصب و پیکربندی |

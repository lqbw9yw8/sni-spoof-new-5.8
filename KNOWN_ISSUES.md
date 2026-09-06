# KNOWN ISSUES — مشکلات واقعی و تأییدشده

آخرین به‌روزرسانی: ۲۰۲۶/۰۹/۰۵

این فایل فقط مشکلاتی را فهرست می‌کند که **با مدرک** تأیید شده‌اند.
حدس و گمان اینجا نمی‌آید.

---

## 🔴 K-1 — کد Rust هرگز کامپایل نشده است

**شدت:** بحرانی برای اعتماد به هر ادعای دیگری

تمام کار بازبینی و رفع باگ در نشست ۲۰۲۶/۰۹ در محیطی انجام شد که
`cargo` نداشت و `crates.io` مسدود بود. یعنی:

* ۱۱ رفع باگ اعمال‌شده **کامپایل نشده‌اند**
* ۳۴۴ تست `#[test]` موجود در سورس **هرگز اجرا نشده‌اند**
* ۱۹ تست جدیدی که در آن نشست نوشته شد نیز **اجرا نشده**

**تنها اقدام لازم:**
```bash
cargo test
cargo clippy -- -D warnings
```
تا وقتی این اجرا نشود، وضعیت واقعی پروژه `UNTESTED` است.

---

## 🔴 K-2 — هیچ تست واقعی روی ویندوز انجام نشده

**شدت:** بالا

پروژه Windows-only است (WinDivert) اما تست‌ها روی Linux طراحی شده‌اند.
هیچ مدرکی برای این موارد وجود ندارد:

* injection واقعی بسته
* timing تزریق نسبت به ClientHello واقعی
* رفتار درایور WinDivert زیر بار
* رفتار kill-switch در قطعی واقعی

`cargo test passes` و `the application works on Windows` دو جملهٔ
متفاوت‌اند. فقط اولی ممکن است روزی ثابت شود.

---

## 🔴 K-3 — `main.rs` با ۱٬۰۰۷ خط، صفر تست

**شدت:** بالا

بزرگ‌ترین ماژول بدون هیچ `#[test]`. منطق reconcile رله و hot-reload
اینجاست. **دو باگ از پنج باگ دستهٔ اول بازبینی دقیقاً در همین فایل بودند.**

ماژول‌های بدون تست:

| ماژول | خط | ارزیابی |
|---|---:|---|
| `main.rs` | ۱٬۰۰۷ | 🔴 باید تست بگیرد |
| `native_gui.rs` | ۶۹۸ | 🟡 UI، تست خودکار سخت |
| `engine.rs` | ۵۲۴ | ⚪ FFI ویندوز، طبیعی |
| `error.rs` | ۳۴ | ⚪ فقط تعریف نوع |

---

## 🟠 K-4 — قابلیت‌هایی که پیاده و تست شده‌اند ولی به موتور وصل نیستند

**شدت:** متوسط — منبع اصلی سوءتفاهم «DONE»

**۳۰ تابع عمومی** فقط از داخل تست‌ها صدا زده می‌شوند و هیچ مسیر اجرای
واقعی به آن‌ها نمی‌رسد. یعنی تست سبز دارند ولی در عمل اجرا نمی‌شوند.

بیشترین موارد:

| ماژول | تعداد | توابع |
|---|---:|---|
| `geedge` | ۴ | `inject_fake_record_before_hello`, `should_use_ip_fragmentation`, `sni_as_ip_literal`, `would_geedge_miss_sni` |
| `stealth` | ۴ | `add_dynamic_jitter`, `encode_tcp_options`, `fake_tcp_options`, `normalize_ttl` |
| `connection` | ۳ | `health_from_probe`, `parse_ip_list`, `smart_backoff` |
| `dns_guard` | ۳ | `dns_protection_filters`, `hijack_dns_requests_target`, `init_wfp_hook_spec` |
| `ech` | ۲ | `build_outer_sni_for_ech`, `parse_ech_config_from_https_record` |
| `quic` | ۲ | `build_quic_decoy`, `is_in_blindspot` |
| `sequence` | ۲ | `add_padding_to_decoy`, `calculate_wrong_seq` |
| `sni_mutations` | ۲ | `apply_homoglyphs`, `inject_whitespace` |

> استثنا: `packet::wrap_ipv4_tcp` و `wrap_ipv6_tcp` عمداً test-helper
> هستند و مشکل محسوب نمی‌شوند.

**هیچ‌کدام از این‌ها نباید `DONE` علامت بخورند.**

---

## 🟠 K-5 — ۹ تابع عمومی با هیچ فراخوان

**شدت:** متوسط (کد مرده)

نه کد تولیدی و نه تست صدایشان نمی‌زند:

* `client_detect` — `any_running`, `first_running`
* `proxy_cleanup` — `disable_dpi_guard_proxy`, `enable_dpi_guard_proxy`
* `dns_guard` — `block_port_53_except_localhost_spec`
* `fragmentation` — `shuffle_cipher_suites_in_hello`
* `http_host` — `tls_cuts_before_sni`
* `mobile_gateway` — `connected_device_count`
* `sni_mutations` — `disguise_sni_record`

توجه: `enable_dpi_guard_proxy` / `disable_dpi_guard_proxy` نگران‌کننده‌اند
چون تنظیم `enable_proxy_cleanup` در UI وجود دارد.

---

## 🟠 K-6 — STUBهای اعلام‌شده

**شدت:** متوسط — مستند شده، ولی نباید فراموش شود

| مورد | وضعیت | دلیل |
|---|---|---|
| `dns_guard::block_port_53_except_localhost` | `STUB` | همیشه `Err` — WFP FFI پیاده نشده |
| `stealth::prevent_dns_leak` | `STUB` | فقط `pub use` از تابع بالا |
| WFP callout driver | خارج از scope | نیاز به درایور kernel امضاشده |
| `singleton` روی غیر ویندوز/یونیکس | `STUB` | `"not implemented on this platform"` |
| `self_update` دانلود/نصب | وجود ندارد | فقط بررسی نسخه؛ `sha256` همیشه `None` |

---

## 🟡 K-7 — تورم مستندات

**شدت:** پایین، ولی باعث سردرگمی AI می‌شود

قبل از سازمان‌دهی: **۱۷ فایل markdown، حدود ۳۸۰ کیلوبایت**، که
`SECURITY_CHECKLIST.md` به‌تنهایی ۱۱۴ کیلوبایت بود. چند فایل ادعاهای
متناقض دربارهٔ وضعیت داشتند.

اسناد قدیمی به `docs/archive/` منتقل شدند. ساختار جدید در `STATUS.md`.

---

## ✅ مواردی که بررسی شد و مشکلی نداشت

* هر ۷۷ فیلد `Settings` در حداقل یک ماژول موتور خوانده می‌شود (۰ یتیم)
* هر ۷۷ کنترل UI دقیقاً با ۷۷ فیلد `Settings` تطابق دارد (۰ اختلاف)
* هیچ `todo!()` یا `unimplemented!()` در کد نیست
* هیچ فراخوانی shell بدون escape نیست (PowerShell درست escape شده،
  `Command::args()` بدون shell استفاده شده)
* ۱۹۲ تابع از ۲۳۱ تابع عمومی از کد تولیدی صدا زده می‌شوند

---

## نحوهٔ به‌روزرسانی این فایل

اعداد این فایل از `tools/gen_status.py` می‌آیند:

```bash
python3 tools/gen_status.py    # TEST_MATRIX.md و tools/status.json را می‌سازد
```

اگر عددی اینجا با `TEST_MATRIX.md` نخواند، `TEST_MATRIX.md` درست است.

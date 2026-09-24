# گزارش نهایی ارزیابی امنیتی USSO

تاریخ ارزیابی: ۲۰۲۶-۰۸-۰۷  
شاخه: `pure`  
وضعیت تغییرات: اعمال‌شده در working tree و هنوز commit نشده

## جمع‌بندی مدیریتی

پس از مرور عمیق کد backend، جریان‌های احراز هویت و مجوزدهی، OAuth/OIDC، KYC، workspace/tenant، پیام‌رسانی، تنظیمات Docker و اجرای تست‌ها، در محدوده‌ی backend بررسی‌شده مورد Critical یا High شناخته‌شده و باز باقی نمانده است. موارد قابل بهره‌برداری که حین ارزیابی پیدا شدند اصلاح و با تست پوشش داده شده‌اند.

این نتیجه «تضمین صددرصدی امنیت» نیست. امنیت مطلق را نمی‌توان فقط با code review و تست واحد اثبات کرد؛ به‌خصوص سورس dashboard در این checkout موجود نیست و محیط واقعی production، ingress، MongoDB/Redis، مدیریت دسترسی زیرساخت و تست نفوذ پویا در دسترس این ارزیابی نبودند. بنابراین نتیجه‌ی دقیق این است:

> backend فعلی پس از اصلاحات، هیچ آسیب‌پذیری Critical/High شناخته‌شده‌ای در محدوده‌ی بررسی‌شده ندارد و برای ورود به pre-production مناسب است؛ انتشار production باید پس از تکمیل موارد اجرایی انتهای این گزارش انجام شود.

## محدوده‌ی بررسی

- تمام کد Python زیر `app/`
- احراز هویت password، OTP، magic link، OAuth/OIDC، Telegram، WebAuthn، TOTP و QR login
- access/refresh/temporary/secure token و sessionها
- OAuth authorization server، client management، device code و service-account grant
- API key و Agent
- tenant، workspace، role، scope، user، profile، referral، KYC و setup
- outbound HTTP، webhook، template rendering، proxy/IP handling و rate limiting
- Dockerfile، `docker-compose.prod.yml`، متغیرهای نمونه و secret defaults
- الگوهای خطرناک مانند command execution، deserialization ناامن، TLS bypass، open redirect، SSRF، mass assignment، IDOR، replay و account enumeration
- وابستگی‌های نصب‌شده با `pip-audit`

خارج از محدوده یا ناقص:

- پوشه‌ی `dashboard/` یک submodule مقداردهی‌نشده و خالی است؛ frontend عملاً قابل audit نبود.
- تنظیم واقعی TLS/ACL/backup برای MongoDB و Redis و پیکربندی Traefik/شبکه‌ی production بررسی runtime نشد.
- DAST، fuzzing، تست نفوذ از بیرون، image/SBOM scan و ارزیابی سرویس‌های ثالث انجام نشد.

## اصلاحات امنیتی مهم

### احراز هویت و session

- bypass ورود موجود ناشی از نبودن `method` یا `secret` بسته شد؛ هیچ روش احراز هویتی بدون proof معتبر وارد AMR نمی‌شود.
- ثبت‌نام مستقیم با نام‌بردن OAuth، magic link، Telegram، OTP یا WebAuthn مسدود شد؛ فقط مسیر اختصاصی و cryptographically verified هر روش اجازه‌ی ثبت‌نام می‌دهد.
- OTP ثابت حالت debug حذف شد و تولید OTP همیشه با CSPRNG انجام می‌شود.
- OTPها فقط به‌صورت Argon2 ذخیره و اتمیک مصرف می‌شوند؛ fallback متن خام حذف شد.
- replay در TOTP، magic link، refresh token، QR، WebAuthn و Agent assertion کنترل شد؛ Agent assertion دارای `jti` اجباری و مصرف یک‌بارمصرف fail-closed است.
- reset password تمام sessionهای کاربر را revoke می‌کند.
- policy رمز عبور و bootstrap superadmin سخت‌گیرانه شد و secretهای اصلی کمتر از ۳۲ بایت باعث توقف startup می‌شوند.
- account enumeration در login-attempt، OTP و magic-link تا حد قابل‌عمل یکسان‌سازی شد.

### OAuth/OIDC

- implicit flow به‌طور کامل منسوخ و حذف شده است؛ تنها Authorization Code Flow فعال است.
- PKCE با روش `S256` برای همه‌ی clientها، از جمله داده‌های legacy، اجباری است.
- redirect URI تطبیق دقیق دارد؛ HTTP فقط برای loopback مجاز است و open redirect مسیر return URL بسته شد.
- state اجباری، nonce بررسی، issuer/audience/JWKS اعتبارسنجی و endpointهای discovery به HTTPS عمومی محدود شدند.
- authorization code، device code، refresh token و consent session اتمیک و یک‌بارمصرف شدند. دو consent هم‌زمان دیگر نمی‌توانند از یک state چند code بگیرند.
- client secret و registration access token با Argon2 ذخیره می‌شوند. fallback پذیرش client secret ذخیره‌شده به‌صورت plaintext حذف شد.
- متادیتای client مانند `logo_uri` و `client_uri` فقط URL مطلق HTTPS بدون credential می‌پذیرد تا Stored XSS در consent UI رخ ندهد.
- client management، rotate secret، update و delete نیازمند مالکیت و recent-auth/secure-token هستند.
- scopeهای صادرشده به subset مجاز client/service account محدود شده‌اند.

نکته‌ی مهاجرت: OAuth clientهای قدیمی که secret آن‌ها در DB با hash امن ذخیره نشده، اکنون عمداً authenticate نمی‌شوند و باید از مسیر rotate-secret رمز جدید بگیرند.

### مجوزدهی و جداسازی tenant

- self-service privilege escalation در roles، scopes، workspace roles، activation flags، custom claims و metadata بسته شد.
- واگذاری role/scope فقط در سقف دسترسی caller مجاز است و تغییرات حساس recent-auth می‌خواهند.
- tenant scoping در user، workspace، profile، KYC، role، referral، API key، Agent و OAuth اعمال یا سخت‌تر شد.
- IDORهای KYC، profile، identifier، workspace membership/invite و مدیریت service account بسته شدند.
- generic credential create/update حذف شد؛ password/passkey/TOTP فقط از flow اختصاصی و تأییدشده مدیریت می‌شوند.
- generic session create/update و organization update/delete که سطح حمله‌ی غیرضروری داشتند غیرفعال شدند.
- schemaهای حساس `extra="forbid"` شده و فیلدهای server-owned مانند `verified_at`، counters و status از ورودی caller حذف شدند.

### API key و Agent

- cache اعتبارسنجی API key دیگر فقط با UID عمومی کلید ساخته نمی‌شود؛ کل credential ارائه‌شده با SHA-256 وارد cache key می‌شود و collision احراز هویت بسته شد.
- وضعیت inactive/revoked/expired، tenant، IP allowlist و rate limit در هر استفاده دوباره بررسی می‌شود.
- ثبت آمار استفاده با API فعلی Beanie اصلاح شد و اکنون واقعاً در DB انجام می‌شود.
- client secretهای service account با Argon2 ذخیره می‌شوند و scopeها از دسترسی سازنده فراتر نمی‌روند.
- الگوریتم متقارن برای Agent assertion رد می‌شود و فقط verification key نامتقارن پذیرفته می‌شود.

### race، replay و abuse control

- مصرف referral code اتمیک شد؛ تست هم‌زمان نشان می‌دهد ظرفیت `max_usage=1` فقط یک مصرف موفق دارد.
- شمارنده‌های CAPTCHA و مصرف authorization/device/refresh/OTP اتمیک شدند.
- rate limit اختصاصی برای auth، OAuth token/device/introspection/revoke، API-key verify، Agent auth، setup، verification، impersonation و KYC اعمال شد.
- حداکثر اندازه‌ی request body برای Content-Length و بدنه‌ی chunked enforce می‌شود.

### ورودی، خروجی و زیرساخت برنامه

- SSRF در webhook/template/OIDC endpoint با HTTPS-only و رد IPهای private، loopback، link-local و reserved محدود شد؛ redirect خودکار نیز غیرفعال است.
- template rendering در sandbox انجام می‌شود و اندازه‌ی پاسخ remote محدود است.
- avatar URL و URLهای متادیتای OAuth از schemeهای اجرایی مانند `javascript:` پاک‌سازی شدند.
- regex injection/ReDoS در جست‌وجوی identifier بسته شد.
- headerهای HSTS، nosniff، frame deny، referrer policy و no-store برای auth/OAuth اضافه شد.
- client IP فقط از زنجیره‌ی proxy مورداعتماد و از راست به چپ استخراج می‌شود.
- Docker backend با user غیر-root، filesystem فقط‌خواندنی، drop همه‌ی capabilityها، `no-new-privileges` و tmpfs محدود سخت‌سازی شد.
- secretهای واقعی در repository track نشده‌اند؛ `.env` در gitignore است.

## حذف ICE

وابستگی عملیاتی ICE از backend حذف شده است:

- KYC provider قدیمی و فایل‌های سرویس آن حذف شدند؛ KYC فعلی provider-neutral و در وضعیت `PENDING` برای بررسی مستقل ایجاد می‌شود.
- pluginهای verification مربوط به ICE در workspace حذف شدند.
- workspace دیگر `organization_code` دریافت نمی‌کند و contract آن بر `slug` استوار است.
- `app/utils/ice.py` و داده‌های سازمانی وابسته حذف شدند.
- channel پیام‌رسان ICE و enum/config مربوط به آن حذف شد.
- role قدیمی `exchange-user` از فعال‌سازی KYC حذف شد.

جست‌وجوی دقیق نهایی در کد فعال هیچ اشاره‌ی ICE پیدا نکرد. فقط URL تاریخی submodule در `.gitmodules` (`ice-exchange/usso-dashboard`) باقی است و خود dashboard در این checkout خالی است. این مورد کد اجرایی یا وابستگی backend نیست؛ برای حذف کامل نام نیز باید URL repository جایگزین dashboard مشخص شود. تست `test_workspace_pure.py` فقط نبودن `organization_code` را assert می‌کند.

## شواهد اعتبارسنجی

- کل تست‌ها: `1079 passed, 6 skipped` در ۲۳٫۸۹ ثانیه
- تست‌های OAuth هدفمند پس از اصلاح replay: `98 passed`
- تست referral/KYC/login هدفمند: `58 passed`
- Ruff روی کل پروژه: بدون خطا
- `git diff --check`: بدون whitespace/error
- `pip-audit` در تاریخ گزارش: `No known vulnerabilities found`
- اسکن command execution/deserialization/TLS bypass: بدون match در کد فعال
- اسکن implicit flow: فقط توضیح صریح «پشتیبانی نمی‌شود» و تست رد `response_type=token`
- اسکن ICE: بدون match اجرایی؛ فقط `.gitmodules` و assertion منفی تست

## ریسک‌های باقیمانده و محدودیت‌ها

### ۱. Frontend بررسی نشده — وضعیت نامشخص

dashboard خالی است. هرگونه XSS، نگهداری token در browser، CSP، dependency vulnerability یا OAuth callback bug در frontend خارج از این نتیجه است. اگر image فعلی dashboard در production استفاده می‌شود، audit سورس همان image قبل از انتشار ضروری است.

### ۲. SSRF و DNS rebinding — متوسط

URL پیش از درخواست resolve و بررسی می‌شود، اما HTTP client دوباره DNS را resolve می‌کند. مهاجم دارای DNS authoritative در تئوری می‌تواند بین این دو resolution پاسخ را تغییر دهد. راه‌حل کامل، اتصال به IP تأییدشده همراه با حفظ SNI/Host یا egress proxy دارای policy است.

### ۳. افت Redis و rate limit توزیع‌شده — متوسط عملیاتی

در نبود Redis، برنامه به limiter درون‌پردازه‌ای fallback می‌کند تا availability حفظ شود. در deployment چند replica، این حالت سقف سراسری را ضعیف می‌کند. alert روی قطع Redis و rate limit در ingress/WAF توصیه می‌شود.

### ۴. revocation توکن access — کم تا متوسط

access tokenها stateless هستند و پس از revoke session/reset password ممکن است تا پایان TTL کوتاه ۱۰ دقیقه‌ای معتبر بمانند. برای عملیات بسیار حساس secure-token/recent-auth وجود دارد؛ اگر revocation فوری لازم است باید denylist مشترک `jti` اضافه شود.

### ۵. زیرساخت و secret storage — عملیاتی

TLS/ACL واقعی MongoDB و Redis، دسترسی Docker network، backup encryption و rotation در این ارزیابی قابل مشاهده نبود. secretهای tenant فعلاً در MongoDB نگهداری می‌شوند؛ با توجه به اولویت اعلام‌شده، مهاجرت به Vault blocker فعلی در نظر گرفته نشده، اما کنترل دسترسی DB و encryption-at-rest الزامی است.

### ۶. Supply chain و تست پویا — پوشش‌داده‌نشده

dependency audit Python پاک است، اما imageها با tag و نه digest pin شده‌اند و image scan/SBOM و DAST انجام نشده است. نتیجه‌ی `pip-audit` نیز فقط CVEهای شناخته‌شده در زمان اجرا را پوشش می‌دهد.

## چک‌لیست قبل از production

1. سورس دقیق dashboard image را checkout و audit کنید؛ CSP و محل ذخیره‌ی token را هم بررسی کنید.
2. تمام OAuth clientهای legacy با secret غیر-hash را rotate کنید.
3. `SYSTEM_PASSWORD`، `CAPTCHA_KEY`، `SUPERADMIN_PASSWORD` و secretهای tenant/provider را با مقادیر تصادفی مستقل تنظیم کنید؛ default یا secret مشترک نداشته باشید.
4. HTTPS اجباری، trusted proxy networks محدود و domainهای tenant دقیق تنظیم شوند.
5. MongoDB/Redis با ACL، TLS یا شبکه‌ی private سخت‌گیرانه، backup رمزگذاری‌شده و مانیتورینگ اجرا شوند.
6. قطع Redis، افزایش 401/403/429، خطاهای OAuth، تلاش setup و مصرف impersonation alert داشته باشند.
7. imageها را با digest pin و با scanner مستقل بررسی کنید.
8. یک DAST/pentest روی محیط staging با تمرکز بر OAuth consent/callback، tenant isolation، SSRF و abuse/rate-limit اجرا کنید.

## نتیجه

در backend بررسی‌شده، مشکلات امنیتی شناخته‌شده‌ی مهم اصلاح شده‌اند، implicit flow حذف است و ICE دیگر وابستگی عملیاتی ندارد. با شواهد فعلی backend از نظر code-level در وضعیت مناسبی است؛ ادعای امنیت کل سیستم منوط به audit dashboard و تأیید پیکربندی runtime و زیرساخت production است.

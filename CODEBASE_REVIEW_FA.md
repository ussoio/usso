# گزارش شناخت کدبیس و نتیجه‌ی بررسی USSO

تاریخ: ۲۰۲۶-۰۸-۰۷  
شاخه‌ی بررسی‌شده: `pure`  
نسخه‌ی پروژه: `0.3.1`  
وضعیت: تغییرات در working tree قرار دارند و هنوز commit نشده‌اند

## ۱. خلاصه‌ی نتیجه

این پروژه یک SSO چندمستاجری (multi-tenant) برای SaaS و معماری microservice است. هسته‌ی آن یک backend مبتنی بر FastAPI و Python 3.13 است که هم نقش سرویس احراز هویت کاربران را دارد و هم یک OAuth2/OIDC Authorization Server ارائه می‌کند. علاوه بر کاربران عادی، API key و Agent نیز به‌عنوان service account پشتیبانی می‌شوند.

در بررسی انجام‌شده، ساختار و جریان‌های اصلی کد، مدل امنیتی، OAuth/OIDC، مدیریت tenant/workspace، KYC، messaging، session/token، API key/Agent، Docker و تست‌ها مرور شدند. آسیب‌پذیری‌های مهم پیدا‌شده در همان شاخه اصلاح شدند.

نتیجه‌ی امنیتی دقیق:

- در backend بررسی‌شده، مورد Critical یا High شناخته‌شده و باز باقی نمانده است.
- implicit flow حذف شده و فقط Authorization Code Flow همراه با PKCE S256 فعال است.
- وابستگی عملیاتی ICE از backend حذف شده است.
- کل suite با نتیجه‌ی `1079 passed, 6 skipped` اجرا شده است.
- Ruff و `git diff --check` پاک هستند.
- `pip-audit` هیچ CVE شناخته‌شده‌ای در وابستگی‌های نصب‌شده پیدا نکرد.

این نتیجه تضمین مطلق امنیت کل محصول نیست؛ سورس dashboard در checkout فعلی موجود نیست و تنظیم واقعی زیرساخت production و تست نفوذ پویا در دسترس نبود.

## ۲. تصویر کلی معماری

کدبیس از نظر معماری یک modular monolith است: برنامه یک process اصلی FastAPI دارد، اما قابلیت‌ها در appهای مستقل تفکیک شده‌اند.

```text
Client / Dashboard / Service Account
                 │
             Traefik / TLS
                 │
        FastAPI + Security Middleware
                 │
       Host-based Tenant Resolution
                 │
  Authentication + Ownership + Scope checks
                 │
       Domain Routers / Services / Models
              │              │
           MongoDB          Redis
```

اجزای اصلی runtime:

- FastAPI برای HTTP API و schema generation
- Uvicorn با یک worker در هر container
- `fastapi-mongo-base` و Beanie/PyMongo برای مدل‌ها، route base، audit و MongoDB
- Redis برای rate limiting، replay protection، cache و stateهای کوتاه‌عمر
- `usso` و `usso-jwt` برای token، principal و authorization scope
- Argon2id برای password و secret hashing
- Traefik برای routing، HTTPS و تفکیک API از dashboard

برنامه از `app/main.py` شروع می‌شود. `server/server.py` app را می‌سازد، init functionها را ثبت می‌کند، middlewareها را اضافه می‌کند و routerهای دامنه‌ای را mount می‌کند. API اصلی زیر `/api/sso/v1` قرار دارد و endpointهای استاندارد OAuth/OIDC و well-known نیز جداگانه mount می‌شوند.

## ۳. نقشه‌ی ماژول‌ها

| ناحیه | مسئولیت |
|---|---|
| `apps/identity/auth` | login، registration، MFA، OTP، magic link، OAuth upstream، QR، refresh و secure token |
| `apps/identity/user` | User، identifier، credential، passkey، TOTP، password و impersonation |
| `apps/identity/session` | نگهداری و revoke کردن sessionهای احراز هویت |
| `apps/identity/profile` | اطلاعات نمایشی کاربر و حساب‌های بانکی تأییدنشده/تأییدشده |
| `apps/identity/kyc` | ثبت KYC مستقل از provider و بازیابی tenant-scoped آن |
| `apps/identity/api_key` | ساخت و اعتبارسنجی API key و client credential مربوط به آن |
| `apps/identity/agent` | service account نامتقارن با assertion امضاشده |
| `apps/identity/referral` | کد دعوت، ظرفیت مصرف و webhook ثبت‌نام |
| `apps/identity/legal` | اسناد حقوقی و انتشار کنترل‌شده |
| `apps/access_control/workspace` | workspace، عضویت، invite و workspace login |
| `apps/access_control/role` | roleهای tenant و محاسبه‌ی scopeهای ناشی از آن‌ها |
| `apps/tenant` | tenant، domain، config، secret، messaging و bootstrap |
| `apps/tenant/integration` | OAuth2/OIDC server، client management، token و device flow |
| `apps/tenant/scope_catalog` | کاتالوگ scopeهای شناخته‌شده‌ی سامانه |
| `apps/captcha` | challenge و verification با شمارنده‌ی مصرف |
| `apps/setup` | راه‌اندازی اولیه‌ی محافظت‌شده با system password |
| `server` | config، DB/Redis، app factory، middleware و rate limiter |
| `utils` | hashing، network، outbound validation، OAuth transport و validatorها |

الگوی رایج هر دامنه `models.py / schemas.py / routes.py / services.py` است. این تفکیک در بیشتر قسمت‌ها خوب رعایت شده، هرچند `identity/user/routes.py` و `identity/auth/routes.py` به‌مرور بزرگ شده‌اند و بخشی از business logic همچنان در route handlerها قرار دارد.

## ۴. مدل دامنه و رابطه‌ی موجودیت‌ها

### Tenant

Tenant مرز اصلی جداسازی داده است. tenant بر اساس hostname درخواست resolve می‌شود و تقریباً تمام queryهای حساس `tenant_id` دارند. هر tenant شامل موارد زیر است:

- domainها و primary URL
- تنظیمات login/registration/token/cookie
- OAuth providerها و channelهای پیام‌رسان
- signing keyها و secretهای مورد نیاز
- workspace، role، scope و userهای همان tenant

این انتخاب معماری مناسب است، اما امنیت آن به این وابسته است که هیچ route یا query نتواند `tenant_id` را از ورودی caller بپذیرد یا فراموش کند. بخش زیادی از اصلاحات انجام‌شده دقیقاً برای enforce کردن همین مرز بوده است.

### User، Identifier و Credential

هویت کاربر به سه لایه تقسیم شده است:

- `User`: وضعیت حساب، role، scope، workspace، MFA و custom claims
- `UserIdentifier`: email، phone، username، Telegram ID، national ID و وضعیت verification
- `Credential`: password، OTP، TOTP، passkey و credentialهای روش‌های ورود

این جداسازی امکان چند identifier و چند روش ورود را می‌دهد. credentialهای حساس در response عمومی برگردانده نمی‌شوند و create/update عمومی credential نیز حذف شده است؛ هر روش فقط از flow اختصاصی خودش قابل تغییر است.

### Workspace و Role

Workspace یک مرز دسترسی داخلی در tenant است. User می‌تواند عضو چند workspace باشد و roleهای workspace-specific داشته باشد. دسترسی نهایی از ترکیب موارد زیر ساخته می‌شود:

- scopeهای مستقیم کاربر
- roleهای عمومی tenant
- roleهای workspace
- ownership روی resource
- scope filterهایی مانند `user_id` و `workspace_id`

در مدل جدید workspace، `organization_code` حذف شده و `slug` ورودی اصلی نام‌گذاری است. workspaceهای personal و management همچنان رفتار اختصاصی خود را دارند.

### Session و Token

Session در MongoDB نگهداری می‌شود، ولی access token از نوع JWT و stateless است. tokenهای اصلی عبارت‌اند از:

- access token با TTL پیش‌فرض ۱۰ دقیقه
- refresh token با TTL پیش‌فرض ۳۰ روز و rotation/replay protection
- temporary token برای flowهای میانی
- secure token برای recent-auth و عملیات حساس

revoke session بلافاصله refresh و ادامه‌ی session را متوقف می‌کند، اما access JWT صادرشده ممکن است تا پایان TTL کوتاه خود معتبر بماند.

### Service Account

دو نوع service account وجود دارد:

- API key: credential تصادفی، hashed at rest و قابل محدودسازی با scope، IP و rate limit
- Agent: assertion امضاشده با کلید نامتقارن و `jti` یک‌بارمصرف

هر دو به user یا workspace bind می‌شوند و scope در زمان ساخت نمی‌تواند از سقف دسترسی سازنده بیشتر باشد.

## ۵. جریان درخواست و مجوزدهی

جریان معمول یک درخواست محافظت‌شده چنین است:

1. Traefik درخواست را بر اساس domain و path به backend می‌فرستد.
2. middleware اندازه‌ی body، security headerها و request context را اعمال می‌کند.
3. tenant از hostname resolve می‌شود؛ domain ناشناخته tenant دلخواه یا پیش‌فرض دریافت نمی‌کند.
4. principal از access token، API key یا Agent credential استخراج می‌شود.
5. route ابتدا tenant-scoped item را می‌خواند.
6. authorization با ownership، workspace ownership و scopeهای filterدار انجام می‌شود.
7. برای عملیات حساس `secure-token` یا recent authentication نیز لازم است.
8. تغییر در MongoDB همراه با audit actor context ذخیره می‌شود.

نقطه‌ی مهم این طراحی، router base مشترک است. استفاده‌ی درست از آن کد را کم می‌کند، اما semantics مربوط به `owner_attr`، `workspace_access` و resource path باید برای هر router روشن باشد؛ اشتباه کوچک در تنظیم این کلاس می‌تواند IDOR یا privilege escalation بسازد. به همین دلیل routeهای حساس در بررسی فعلی override و تست شده‌اند.

## ۶. جریان‌های احراز هویت

### Login معمولی

ورودی login شامل identifier، method و secret است. سیستم ابتدا tenant و policy مجاز آن را تعیین می‌کند، user و identifier را پیدا می‌کند، proof روش انتخابی را بررسی می‌کند و سپس بر اساس login flow تصمیم می‌گیرد که مرحله‌ی دیگری لازم است یا token صادر شود.

اصلاح مهم انجام‌شده این بود که method بدون secret دیگر به‌عنوان authentication موفق وارد AMR نمی‌شود. همچنین ساخت user جدید با صرفاً نام‌بردن OAuth، magic-link، Telegram یا WebAuthn ممکن نیست؛ ثبت‌نام این روش‌ها فقط پس از تأیید cryptographic در endpoint اختصاصی انجام می‌شود.

### OTP و Magic Link

OTP با CSPRNG ساخته می‌شود، فقط hash آن ذخیره می‌شود و مصرفش اتمیک است. کد ثابت debug حذف شده است. پاسخ request endpoint تا حد ممکن برای user موجود و ناموجود یکسان است تا account enumeration کاهش یابد.

Magic link نیز issuer/key، expiry و مصرف یک‌بارمصرف را بررسی می‌کند و نمی‌تواند به‌عنوان میان‌بر ثبت‌نام یا ورود مستقیم استفاده شود.

### Password، TOTP، WebAuthn و QR

- password با Argon2id ذخیره و با policy tenant بررسی می‌شود.
- TOTP یک time-window را دوبار قبول نمی‌کند و ثبت مصرف آن در DB اتمیک است.
- WebAuthn challenge و sign count را بررسی می‌کند.
- QR login یک session کوتاه‌عمر و یک‌بارمصرف دارد و approve کردن آن به user فعلی bind است.

### OAuth upstream

این بخش برای ورود کاربر با provider خارجی مانند Google یا Telegram OIDC است. discovery endpointها باید HTTPS عمومی باشند؛ ID token از نظر signature، issuer، audience و nonce بررسی می‌شود. برای providerهای email-based، `email_verified` اجباری است و claimهای provider مستقیماً به فیلدهای privileged کاربر تبدیل نمی‌شوند.

## ۷. OAuth2/OIDC Authorization Server داخلی

پروژه علاوه بر مصرف OAuth خارجی، خودش نیز Authorization Server است. این دو نقش در کد جدا هستند اما نام‌گذاری نزدیک آن‌ها ممکن است برای توسعه‌دهنده‌ی جدید گیج‌کننده باشد.

ویژگی‌های flow داخلی:

- فقط `response_type=code`
- state اجباری
- redirect URI با تطبیق دقیق
- HTTP فقط برای loopback
- PKCE S256 اجباری
- consent session متصل به user/client/redirect/scope/nonce/challenge
- authorization code یک‌بارمصرف و اتمیک
- refresh rotation و replay protection
- device authorization مطابق الگوی RFC 8628
- introspection و revocation با client authentication
- client management همراه با ownership و secure-token

client secretها با Argon2 نگهداری می‌شوند. پذیرش legacy plaintext حذف شده است؛ در نتیجه clientهای قدیمی با secret خام باید secret خود را rotate کنند.

## ۸. KYC، Profile و اطلاعات مالی

KYC فعلی provider-neutral است. user احراز‌شده می‌تواند national code و birth date را ثبت کند و رکورد در حالت `PENDING` قرار می‌گیرد. سیستم دیگر به ICE برای تأیید KYC متصل نیست و تأیید خودکار خارجی انجام نمی‌دهد.

خواندن KYC به مالک همان user یا scope صریح tenant محدود شده است. ایجاد KYC نیز rate limit اختصاصی دارد.

Profile شامل داده‌های نمایشی و حساب‌های بانکی است. caller نمی‌تواند `verified_at` را تزریق کند؛ حساب بانکی جدید همیشه unverified ساخته می‌شود و عملیات آن recent-auth می‌خواهد. avatar URL فقط HTTPS معتبر می‌پذیرد تا URL اجرایی یا credential-bearing وارد client نشود.

## ۹. Messaging و Template

پیام‌رسانی بر اساس channelهای مستقل tenant انجام می‌شود؛ channelهای باقی‌مانده شامل email، SMS/Kavenegar و Bale هستند. channel مربوط به ICE حذف شده است.

templateها می‌توانند local یا remote باشند. برای remote template:

- URL باید HTTPS و public باشد.
- IPهای private/loopback/link-local/reserved رد می‌شوند.
- redirect خودکار خاموش است.
- اندازه‌ی response محدود می‌شود.
- Jinja در sandbox render می‌شود.

Webhookهای referral نیز همین سیاست کلی outbound را رعایت می‌کنند و به‌صورت best-effort غیرمسدودکننده dispatch می‌شوند.

## ۱۰. وضعیت حذف ICE

ICE دیگر در مسیر اجرایی backend وجود ندارد:

- `app/utils/ice.py` حذف شده است.
- KYC service قدیمی ICE حذف شده است.
- pluginهای workspace verification مربوط به ICE حذف شده‌اند.
- `organization_code` از مدل/ورودی workspace حذف شده است.
- messaging channel مربوط به ICE حذف شده است.
- role قدیمی `exchange-user` از KYC activation حذف شده است.

جست‌وجوی نهایی فقط دو رد غیراجرایی نشان می‌دهد:

- URL submodule در `.gitmodules` هنوز به `ice-exchange/usso-dashboard` اشاره دارد.
- تست `test_workspace_pure.py` نبودن `organization_code` را assert می‌کند.

برای حذف نام ICE از `.gitmodules` باید آدرس repository جایگزین dashboard مشخص شود. حذف یا حدس‌زدن URL بدون دانستن repository مقصد صحیح نیست.

## ۱۱. نتیجه‌ی ارزیابی امنیتی

مهم‌ترین دسته‌های اصلاح‌شده:

- authentication bypass ناشی از proof ناقص
- ثبت‌نام با روش federated تأییدنشده
- implicit OAuth flow و PKCE اختیاری
- replay در token، OTP، TOTP، Agent و OAuth consent
- collision امنیتی cache API key
- privilege escalation در role/scope/workspace role
- IDOR و tenant leakage در KYC، workspace، profile و user resources
- mass assignment فیلدهای server-owned
- open redirect و return URL validation
- SSRF در endpointها، webhook و template
- Stored XSS احتمالی از avatar/client metadata URL
- debug OTP ثابت
- race در referral max usage و CAPTCHA counters
- plaintext OAuth client secret fallback
- account enumeration و endpointهای فاقد rate limit

جزئیات کامل هر اصلاح در `SECURITY_AUDIT_FA.md` ثبت شده است.

## ۱۲. نقاط قوت کدبیس

- دامنه‌ها تا حد خوبی ماژولار و قابل‌ردیابی هستند.
- Pydantic schemaها مرز روشنی بین ورودی، مدل DB و response ایجاد می‌کنند.
- تست‌ها گسترده‌اند و ترکیبی از unit، integration و testcontainers واقعی Mongo/Redis دارند.
- معماری multi-tenant و scope filter از ابتدا در طراحی حضور دارد، نه اینکه بعداً به سیستم اضافه شده باشد.
- OAuth/OIDC به استانداردهای درست مانند Authorization Code، PKCE، nonce و device code نزدیک است.
- استفاده از CSPRNG، Argon2id و asymmetric key برای Agent انتخاب‌های مناسبی هستند.
- Docker backend با user غیر-root، read-only filesystem، capability drop و `no-new-privileges` سخت‌سازی شده است.
- lint امنیتی Ruff و type annotation در سطح خوبی فعال‌اند.

## ۱۳. بدهی فنی و نقاط شکننده

### Routeهای بسیار بزرگ

`identity/user/routes.py` و `identity/auth/routes.py` مسئولیت‌های زیادی دارند. authorization، validation، orchestration و persistence در چند handler مخلوط شده‌اند. این موضوع احتمال regression امنیتی را بالا می‌برد. بهتر است عملیات حساس به service/use-caseهای کوچک منتقل شوند.

### وابستگی زیاد به router base و authorization string

بخش مهمی از مجوزدهی از resource pathهای متنی و رفتار کلاس پایه می‌آید. typo یا تغییر namespace/service می‌تواند scopeها را بی‌اثر یا بیش‌ازحد باز کند. تست contract برای resource path هر router توصیه می‌شود.

### Dictهای آزاد

`meta_data`، `custom_claims` و بخشی از configها هنوز dict آزاد هستند. دسترسی آن‌ها کنترل شده، ولی schema تایپ‌شده احتمال payload غیرمنتظره، رشد بدون حد و ناسازگاری بین سرویس‌ها را کم می‌کند.

### دو مفهوم OAuth

پروژه هم OAuth client برای ورود با provider خارجی دارد و هم OAuth Authorization Server داخلی. جداسازی پکیج و نام‌گذاری صریح‌تر مثل `federated_login` و `authorization_server` فهم کد را آسان‌تر می‌کند.

### کدهای نیمه‌استفاده‌شده

`JibitClient` و متغیرهای نمونه‌ی JIBIT هنوز وجود دارند، ولی KYC اجرایی فعلی از آن استفاده نمی‌کند. حذف یا انتقال آن به integration اختیاری، سطح نگهداری را کم می‌کند.

### Dashboard ناموجود

backend در compose یک dashboard image اجرا می‌کند، ولی سورس submodule موجود نیست. در نتیجه قرارداد API/frontend و امنیت browser قابل تأیید نیست.

### Startup و وابستگی Redis

Redis در import/startup initialize می‌شود. این رفتار fail-closed مناسبی برای production است، اما startup و recovery را به availability Redis وابسته می‌کند. health check و restart policy باید این وابستگی را صریح پوشش دهند.

## ۱۴. ریسک‌های باقی‌مانده

1. امنیت frontend نامشخص است چون dashboard checkout نشده است.
2. SSRF validation در برابر DNS rebinding بین validation و اتصال HTTP کامل نیست.
3. هنگام خطای Redis در rate limiter، fallback درون‌پردازه‌ای در چند replica محدودیت سراسری را ضعیف می‌کند.
4. access JWT تا پایان TTL ده‌دقیقه‌ای خود فوراً قابل revoke نیست.
5. TLS، ACL، backup encryption و network policy واقعی MongoDB/Redis بررسی نشده‌اند.
6. secretهای tenant در MongoDB نگهداری می‌شوند؛ Vault فعلاً اولویت نیست، اما DB encryption/access control ضروری است.
7. imageها با tag و نه digest pin شده‌اند و image/SBOM scan انجام نشده است.
8. DAST، fuzzing و pentest روی محیط staging انجام نشده است.

## ۱۵. پیشنهاد ادامه‌ی کار

### قبل از production

1. dashboard واقعی را checkout و از نظر XSS، CSP، OAuth callback و محل نگهداری token بررسی کنید.
2. OAuth clientهای legacy با secret خام را rotate کنید.
3. secretهای system/captcha/superadmin/provider را با مقادیر تصادفی مستقل تنظیم کنید.
4. MongoDB و Redis را با ACL، شبکه‌ی private، TLS مناسب و backup رمزگذاری‌شده اجرا کنید.
5. `TRUSTED_PROXY_NETWORKS` و domainهای tenant را دقیق و محدود تنظیم کنید.
6. image scan و DAST/pentest روی staging اجرا کنید.

### بهبود بعدی کد

1. routeهای user/auth/workspace را به use-case serviceهای کوچک‌تر تقسیم کنید.
2. برای resource path و tenant isolation تست contract خودکار اضافه کنید.
3. metadata و custom claims را به schemaهای تایپ‌شده و size-limited تبدیل کنید.
4. outbound HTTP را پشت egress proxy یا DNS/IP pinning قرار دهید.
5. Jibit و configهای بلااستفاده را حذف یا به plugin اختیاری منتقل کنید.
6. imageها را با digest pin و SBOM منتشر کنید.

## ۱۶. نتیجه‌ی نهایی

USSO از نظر مفهومی یک سامانه‌ی احراز هویت چندمستاجری نسبتاً کامل است، نه صرفاً یک login API. پیچیدگی اصلی آن از ترکیب user authentication، OAuth server، workspace authorization و service accountها می‌آید. ساختار ماژولار و تست‌های گسترده پایه‌ی خوبی ایجاد کرده‌اند، اما همین گستردگی باعث شده routeهای مرکزی و مجوزدهی مبتنی بر scope حساس‌ترین بخش‌های نگهداری باشند.

پس از اصلاحات فعلی، backend از نظر code-level وضعیت قابل‌قبولی دارد و آسیب‌پذیری Critical/High شناخته‌شده‌ای در محدوده‌ی بررسی‌شده باقی نمانده است. برای ادعای امنیت کل محصول، بررسی dashboard و تأیید زیرساخت و رفتار runtime production همچنان لازم است.

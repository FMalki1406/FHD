# بيئة التطوير والتحقق

تحديث وصف البيئة: 2026-09-23. الإعداد المحلي الموضح هنا Windows x64. يوجد CI على Windows وmacOS وLinux، وتُنسب نتائجه إلى النسخ في [سجل التنفيذ](execution-status.md). وصف البيئة المحلية لا يحصر تحقق المشروع كله في Windows، ولا يعني نجاح CI اعتماد كل نظام كمنصة توزيع للمنتج.

## Rust

أُعدت أدوات Rust محليًا تحت `.tools/cargo` و`.tools/rustup` داخل المشروع، دون تعديل PATH العام. هذه الملفات غير مضمّنة في المصدر. إصدار المشروع مثبت في `rust-toolchain.toml` على **1.98.1**، وهو الإصدار الذي أعاده manifest الرسمي للقناة stable عند الإعداد (تاريخ الإصدار الوارد فيه 2026-09-03). هذه واقعة إعداد وليست ضمانًا لخلو الأدوات من العيوب أو اعتمادها إلى الأبد.

جرى تنزيل rustup-init من `https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe` والتحقق من SHA-256 مقابل الملف المنشور بجواره قبل تشغيله:

```text
6F4BEF66261261FCB43131BE8720BAB817D403A09EDEC7455C371974B90BDB7E
```

تطابق البصمة يحمي من اختلاف الملف المنقول؛ تحميل الملف والبصمة من نفس المصدر ليس توثيقًا مستقلًا ضد اختراق المصدر. أدوات MSVC الموجودة على الجهاز هي Visual Studio 2019 Build Tools؛ لم يُثبت SDK أو Visual Studio إضافي.

إعادة إعداد جهاز Windows جديد: استخدم [تعليمات Rust الرسمية](https://rust-lang.org/tools/install/) و[متطلبات Windows](https://rust-lang.github.io/rustup/installation/windows.html)، ثم ثبت النسخة المسجلة في ملف toolchain مع rustfmt وclippy. عند استخدام العزل المحلي عين CARGO_HOME وRUSTUP_HOME إلى `.tools/cargo` و`.tools/rustup` تحت جذر المشروع قبل تشغيل المثبت مع `--no-modify-path`. لا تشغل مثبتًا من مصدر غير موثق.

## أوامر المشروع

في PowerShell من جذر المشروع:

```powershell
./tools/rust.ps1 -CargoArguments @('fmt', '--all', '--', '--check')
./tools/rust.ps1 -CargoArguments @('test', '--workspace', '--locked', '--offline')
./tools/rust.ps1 -CargoArguments @('clippy', '--workspace', '--all-targets', '--locked', '--offline', '--', '-D', 'warnings')
npm.cmd test
```

الـwrapper يضبط متغيرات أدوات المشروع أثناء الأمر ويعيدها بعده، ويعيد رمز الخروج. مرر قائمة المعاملات صراحة كما في المثال حتى لا يفسر PowerShell خيارات مثل `-p` أو `--` لنفسه بدل Cargo. على بيئة تملك Rust قياسيًا يمكن تشغيل أوامر cargo المقابلة مباشرة؛ اختبار macOS/Linux لم ينفذ بعد.

يحفظ Cargo.lock مدخلات البناء المحلولة. أضيفت reqwest 0.13.5 وTokio 1.51.4 وrusqlite 0.40.2 وsha2 0.11.0 بنسخ مباشرة مثبتة؛ يتطلب الجهاز الجديد cargo fetch --locked قبل التشغيل offline. مراجعة النسخ والتراخيص والإشعارات المحدودة في network-storage-security-review.md؛ ليست تدقيق تبعيات شاملًا.

## نطاق الأدلة المحلية الأولى — سجل تاريخي

القائمة التالية تصف أول إعداد قبل إضافة المحرك الجديد. الحالة الحالية في [سجل التطبيق](enterprise-implementation-status.md)؛ لا تُستخدم نتائج هذه الدفعة للحكم على النسخ اللاحقة.

- download-core: نطاقات وحالات مجال فقط؛ لا منفذ شبكة أو قرص.
- resume-policy: تحقق محافظ لرؤوس استجابة استكمال، لا HTTP client ولا TLS أو كتابة ملفات.
- tools/http-lab: خادم محلي اصطناعي؛ لا backend للمنتج.
- وقت هذه الدفعة لم يكن CI البعيد مفعّلًا. أضيف لاحقًا؛ ما زال المثبت وإصدار الموقع خارج أدلة هذه الوثيقة. أوامر الفحص المحلية ليست دليل تأهيل المنتج.

كان تثبيت Node وإضافة CI ضمن ENG-001؛ أضيفا لاحقًا إلى workflow. نسخة كل تجربة ونتيجتها مسجلتان في [حالة التنفيذ](execution-status.md).

## النقل والتخزين

أضيف في الدفعة التالية download-engine وtransfer-store؛ تعليماتهما في [دليل الناقل](../crates/download-engine/README.md). نجح البناء وقتها على MSVC الموجود، ثم جاءت لاحقًا نتائج CI متعددة الأنظمة في سجل الأدلة. حدود تلك الدفعة لا تنفي التحقق اللاحق أو وجود المحرك الجديد.

اختبار TLS المحلي: npm.cmd run test:tls بعد بناء executable. يحتاج PowerShell 7 لإنشاء شهادة ومفتاح مؤقتين في الذاكرة؛ لا يثبت شهادة في النظام. اختبارات الإلغاء الشبكية ضمن cargo test --workspace. مخطط تخزين المهام الجديد v2 لا يستعيد ملفات v1؛ تحفظ كما هي دون تحويل تلقائي.

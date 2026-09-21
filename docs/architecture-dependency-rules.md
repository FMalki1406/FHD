# قواعد اعتماديات المعمارية

التاريخ: 2026-09-21. هذه بوابة تنفيذية لحدود الاعتماديات المباشرة في Cargo وفق القسم 4 من [معمارية المحرك](enterprise-engine-architecture.md). وجود القاعدة لا يعني اكتمال إعادة البناء أو تأهيل الأداء.

## الفحص المنفذ

الأداة `tools/check-architecture.mjs` تقرأ `cargo metadata`، وتفحص جميع أعضاء workspace، وكل اعتماد عادي أو اعتماد اختبار أو بناء، بما فيه اعتماديات المنصات والاعتماديات الاختيارية غير المفعلة. تستخدم اسم الحزمة الأصلي، لذلك تغيير اسم الاستيراد بـ `package`/alias لا يتجاوز المنع. كل اسم workspace جديد يحتاج تصنيفًا صريحًا؛ لا يوجد قبول تلقائي للأسماء التي تبدأ بـ `fhd-`.

| الحزمة | الاعتماديات الداخلية المسموحة |
| --- | --- |
| `fhd-domain` | `resume-policy` مؤقتًا فقط |
| `fhd-app` | domain، config |
| `fhd-runtime` | app، domain، config، telemetry |
| كل محول: http/storage/persistence/secrets/platform/policy | app، domain، config، telemetry؛ لا محول آخر |
| `fhd-protocol` | domain |
| `fhd-ipc` | app، protocol، config، telemetry |
| `fhd-config` | domain |
| `fhd-telemetry` | لا اعتماد داخلي |
| `fhd-testkit` | app، domain، config |
| `fhd` و`fhd-native-host` | protocol، config، telemetry |
| `fhd-daemon` | نقطة تجميع الطبقات والمحولات؛ لا testkit في الإنتاج |

الأسماء المختصرة في الجدول تحمل البادئة `fhd-`. السماح بـ config وtelemetry يوضح اعتماديات الدعم غير المرسومة في الرسم المختصر؛ لا يجيز لمحولات النظام الاعتماد بعضها على بعض. `fhd-testkit` مسموح كاعتماد اختبار فقط للحزم الجديدة عدا domain وtestkit نفسه؛ هذا يمنع عكس اتجاه الدومين النقي نحو طبقة التطبيق.

تعتمد الحزم النقية `fhd-domain` و`download-core` و`resume-policy` على قائمة سماح خارجية صغيرة: `serde` و`thiserror`، و`proptest` للاختبارات فقط. أي اعتماد بناء خارجي فيها مرفوض. القائمة تمنع مكتبة IO جديدة غير معروفة، وليس فقط أسماء tokio وreqwest. إضافة مكتبة للقائمة قرار يحتاج مراجعة، ولا تعني القائمة أن المكتبات مضافة فعليًا للمشروع.

## استثناء الترحيل

تبقى الحزم الست الحالية قابلة للبناء أثناء نقل التنفيذ: download-core، resume-policy، transfer-store، download-engine، queue-secrets، platform-files. الاستثناء يسمح فقط باعتمادياتها الداخلية الحالية: download-engine على الحزم الخمس الأخرى؛ لا يوجد إعفاء مفتوح يسمح بربط جديد.

يسمح للدومين الجديد بالاعتماد على `resume-policy` وحده لإعادة استخدام قواعد الاستكمال النقية المختبرة. هذا جسر ترحيل مؤقت ينتهي عند نقل القواعد إلى الدومين؛ لا يجيز اعتماد طبقات جديدة على مدير التنزيل أو التخزين القديم. مسؤول إزالته فريق Engineering ضمن مرحلة نقل الدومين. القواعد النقية القديمة نفسها خاضعة لمنع اعتماديات IO.

## التشغيل والتحقق

في بيئة Cargo المهيأة بالإصدار المثبت في المشروع:

```sh
node tools/check-architecture.mjs
node tools/check-architecture.test.mjs
```

الأمر الأول يستدعي `cargo metadata --no-deps --format-version=1 --locked --offline` دون shell. ويمكن تمرير ملف metadata أنتجه غلاف Rust المحلي:

```powershell
& .\tools\rust.ps1 -CargoArguments @('metadata','--no-deps','--format-version=1','--locked','--offline') | Set-Content -Encoding utf8 .architecture-metadata.json
node tools/check-architecture.mjs --metadata .architecture-metadata.json
```

يجب التحقق من نجاح توليد metadata قبل تشغيل القاعدة؛ الملف وسيط محلي لا يدخل المستودع. ملف toolchain المثبت يحدد نسخة Cargo، ولا تحدد الأداة إصدارًا منافسًا له.

التحقق المحلي لهذه الأداة على Windows: **8 اختبارات نجحت**. تختبر السماح بالرسم الحالي والترحيل، منع ربط المحولات، منع التجاوز عبر alias أو target أو optional أو dev/build، منع IO في الدومين، قيد testkit، رفض حزم جديدة بلا تصنيف، ورفض metadata ناقصة. تشغيل الأداة على workspace الكامل وربطها بـ CI يسجلان في حالة التنفيذ بعد تنفيذهما، ولا تستنتجهما اختبارات fixtures.

## حدود الدليل

هذا فحص اعتماديات Cargo المباشرة، وليس محللًا لشفرة Rust. لا يثبت غياب استعمال `std::fs` أو `std::net` داخل الدومين، ولا يغني عن مراجعة المصدر والتبعيات الانتقالية وbuild scripts والتراخيص والأمان. لا يفحص نسخة مزيفة من ملف metadata؛ CI يجب أن ينتجه من checkout الذي يبنيه. لا يستبدل cargo-deny أو cargo-audit أو مراجعة Engineering/Security.

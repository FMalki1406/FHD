# أساس قواعد محرك التنزيل

الحالة: تنفيذ داخلي أولي لقواعد خالصة في الذاكرة، وليس محرك نقل أو تطبيقًا جاهزًا للإطلاق. يرتبط بـDL-005 وPR-004. لا تبعيات خارجية ولا شبكة أو ملفات أو SQLite أو ترخيص. نتائج التشغيل الفعلية في [سجل التنفيذ](../../docs/execution-status.md).

## النطاقات

`ByteRange` نطاق غير فارغ `[start, end)` بحقول خاصة. الإنشاء والتحويل من نهاية HTTP الشاملة يرفضان الفراغ والترتيب المعكوس والفائض. `split_at` يقسم إلى نطاقين متجاورين دون تخصيص ذاكرة بحسب حجم الملف. أقصى نهاية حصرية مدعومة `u64::MAX`؛ تمثيل ملف فارغ حالة مستقلة لم تُنفذ بعد، وليس نطاقًا مزيفًا.

## دورة الحالة

مالك واحد يرسل `Command` وأحداث المنسق بالتتابع. لا يجوز اعتبار enum الأحداث بروتوكول IPC، ولا السماح لواجهة أو امتداد بإرسال `Verified` أو `PublishSucceeded` مباشرة. نجاح الحدث إقرار من محول موثوق بأن أثره تحقق؛ هذه الوحدة لا تثبت البايتات أو المزامنة أو إعادة التسمية.

| الحالة | العملية | النتيجة |
| --- | --- | --- |
| Queued | Start | Probing، محاولة جديدة |
| Paused / NeedsAction | Resume | Probing، محاولة جديدة |
| RetryWait | Retry | Probing، محاولة جديدة |
| Probing | ProbeSucceeded | Downloading |
| Downloading | TransferFinished | Verifying |
| Verifying | Verified | Publishing |
| Publishing | PublishSucceeded | Completed |
| Probing / Downloading / Verifying | Pause | Pausing |
| Queued / RetryWait / NeedsAction | Pause | Paused |
| Pausing | WorkersStopped | Paused |
| Probing / Downloading / Verifying / Pausing | Cancel | Cancelling |
| Queued / Paused / RetryWait / NeedsAction | Cancel | Cancelled |
| Cancelling | WorkersStopped | Cancelled |
| Probing / Downloading / Verifying | RetryableFailureAfterStop | RetryWait |
| Probing / Downloading / Verifying / Publishing / Recovering | ActionRequiredAfterStop | NeedsAction |
| أي حالة غير نهائية عدا Recovering | Recover | Recovering، محاولة جديدة |
| Recovering | Reconciled | Paused |

أي انتقال آخر مرفوض دون تعديل الحالة. Completed وCancelled نهائيتان. لا تقبل مرحلة Publishing إلغاء أو إيقافًا؛ على المنسق حسم الأثر ثم نشر نتيجته أو المصالحة. الأحداث التي تنتهي بـAfterStop لا تصدر قبل توقف جميع العمال، وتحتاج نتيجة نشر محسومة عند فشل النشر. Recover يتطلب توقف العمال السابقين قبل استدعائه.

`AttemptToken` يرفض أحداث محاولة سابقة بعد الاستكمال أو إعادة المحاولة أو دخول الاستعادة، ويستخدم عدادًا لا يلتف عند الفائض. يتضمن الرمز DownloadId صريحًا غير سري ورقم المحاولة؛ إنشاء Download يتطلب المعرف، وتُرفض أحداث مهمة أخرى حتى عند تساوي رقم المحاولة. مسؤولية المالك ضمان تفرد المعرف وعدم إعادة استخدامه ما دام وصول حدث قديم ممكنًا؛ لا عداد عالمي ولا توليد معرفات ضمن الوحدة. ليس generation لهوية المورد أو إثبات صلاحية، ويجب إرفاق engine epoch في بروتوكول العملية المستقبلي. هوية تمثيل المورد والتحقق من الاستكمال وإصدار عملية المحرك عقود لاحقة.

## الاختبارات والحدود

توجد اختبارات للمدخلات المعيبة والفائض وحدود الحجم، ومجموعة تقسيمات تثبت التغطية وعدم التداخل، وترتيب التحقق والنشر، وحاجز توقف العمال، وأحداث المحاولة القديمة، والاستعادة المحافظة، ونهائية الحالات وفائض عداد المحاولات. تنفيذ `cargo test -p download-core` يحتاج بيئة Rust المثبتة في جذر المشروع.

تحقق 2026-09-21 على Windows: تنسيق crate ناجح؛ `cargo test -p download-core --locked --offline` عبر `tools/rust.ps1` نجح 10/10 بلا تخطٍ بعد إصلاح ربط الأحداث بمعرف المهمة وإضافة اختبار رفض أحداث مهمة أخرى. هذه اختبارات ذاكرة فقط.

لم تُنفذ: جدولة زمنية، backoff، ملفات فارغة، generation للمورد، persistence/restore من قرص، استعادة ملف نُشر قبل التعطل، حماية IPC، تفويض أوامر تجارية، اختبارات قتل عملية أو حقن أعطال القرص، أو ضمانات المنصات. `Reconciled` يعود Paused فقط؛ إتمام نشر عُثر عليه عند الاستعادة يتطلب عقد أدلة منفصلًا قبل إضافته.

قرار نطاق: حالات Scheduled وأوامر Schedule/ReleaseSchedule مؤجلة إلى عقد الجدولة (DL-015) الذي يحتاج ساعة وسياسة استعادة ومواعيد. حالة Failed الدائمة مؤجلة حتى تعريف أسبابها وسياسة الاحتفاظ والاستعادة؛ الفشل الحالي يُصنف RetryWait أو NeedsAction بعد توقف العمال. لذلك هذا العقد أساس جزئي لـDL-005، وليس جدول دورة الحياة النهائي لكل متطلبات المنتج.

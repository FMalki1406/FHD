# تشخيص سجلي CI — 36b96715

التاريخ: 2026-09-24. الرأس: `36b967155b60f06cd3880ecebcb6a339a288c475`.
[التشغيل 36040543639](https://github.com/FMalki1406/FHD/actions/runs/36040543639).

قرأت السجلين مباشرة عبر المتصفح وطابقت الأسطر بالكود. Windows ناجح، وUbuntu وmacOS فاشلان. هذه قراءة تشخيصية، لا إعادة اعتماد الملاحظات السابقة. لم أعدل الكود أو أثبت أدوات أو أدمج شيئًا.

## الرسائل الفعلية

### Ubuntu — فشلان، وليس واحدًا

[السجل](https://github.com/FMalki1406/FHD/actions/runs/36040543639/job/107771454906)، الخطوة 33:

```text
pause_stops_the_run_and_a_later_run_finishes_it
crates/bins/daemon/tests/end_to_end.rs:414:5
the resume fetched 147461 bytes with 0 committed, out of 2097152

a_later_run_continues_what_it_remembers_without_being_told_the_link
crates/bins/daemon/tests/end_to_end.rs:815:13
assertion `left == right` failed
  left: Some(Network)
 right: Some(Storage)

11 passed; 2 failed; 1 ignored; finished in 9.67s
```

### macOS — الاختباران نفسيهما، برسالة ثانية مختلفة

[السجل](https://github.com/FMalki1406/FHD/actions/runs/36040543639/job/107771454606)، الخطوة 33:

```text
pause_stops_the_run_and_a_later_run_finishes_it
crates/bins/daemon/tests/end_to_end.rs:414:5
the resume fetched 229381 bytes with 0 committed, out of 2097152

a_later_run_continues_what_it_remembers_without_being_told_the_link
crates/bins/daemon/tests/end_to_end.rs:754:13
only 163878 of 524296 bytes arrived in 60s, so the pause never had
a part-way transfer to land in

11 passed; 2 failed; 1 ignored; finished in 60.19s
```

## ما يثبته الدليل وما لا يثبته

- اختلاف مدتي الخطوة لا يثبت سببين جذريين مستقلين. الاختبار الأول يفشل عند التأكيد نفسه على المنصتين؛ وفي الثاني توقف Ubuntu بسبب Network، وmacOS لم يبلغ شرط إرسال الإيقاف.
- في اختبار الإيقاف، `outcome` و`reason` متاحان قبل السطر 414 لكن تأكيد عداد البايتات يفشل قبل فحصهما عبر `published_as_declared`. لذا تخفي الرسالة الحالية سبب نهاية جلسة الاستئناف. يلزم إدراجهما في رسالة الفشل أو فحص النتيجة أولًا دون إضعاف فحص البايتات.
- `serve_slowly` يعد البايتات بعد `write_all` إلى المقبس. هذا دليل إرسال من الخادم، وليس استلامًا أو تثبيتًا لدى المحرك. وهو عداد تراكمي مشترك عبر اتصالات التشغيلين؛ لا يكفي وحده لإثبات أن فرق العداد يعود حصريًا إلى طلبات الاستئناف.
- `tokio::join!` ينتظر حلقة بلوغ ربع الملف حتى لو كانت جلسة النقل قد انتهت بالفعل. المهلة تمنع التعليق غير المحدود، لكنها لا تكشف سبب انتهاء الجلسة مبكرًا. الأفضل أن يظهر انتهاء النقل وحالته فورًا إذا سبق شرط الإيقاف.
- السجلات تحدد مواضع الفشل، ولا تحسم بعد إن كان أصل فشل الشبكة في خادم الاختبار أو النقل. لا أوصي بزيادة المهل أو قبول Network بدل Storage لإخضار الاختبار.

## الخطوة التالية المقترحة

تشغيل الاختبارين منفردين على Linux، مع تسجيل نتيجة الجلسة وسبب التوقف، ونطاق كل طلب HTTP وعدد البايتات المكتوبة وخطأ المقبس إن وقع. ثم إصلاح السبب وإعادة الاختبارات المجمعة. لا حاجة إلى خطاف إنتاج للحصول على هذه الأدلة من خادم الاختبار والواجهات المتاحة.

بيئة WSL المحلية مفيدة لهذه الدورة، لكنها لا تستبدل تحقق macOS وUbuntu 24.04 في CI. لم أتحقق في هذه الجولة من حالة حزم WSL ولم أنفذ أمر التثبيت المنقول في التقرير.

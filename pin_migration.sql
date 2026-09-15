-- شغّل الملف ده مرة واحدة على قاعدة البيانات الموجودة عندك بالفعل، عشان يضيف دعم
-- الدخول بالـ PIN بدل رقم الهاتف (رقم الهاتف هيفضل موجود لبيانات التواصل بس).

ALTER TABLE members ADD COLUMN pin_hash TEXT;
ALTER TABLE members ADD COLUMN recovery_code_hash TEXT;

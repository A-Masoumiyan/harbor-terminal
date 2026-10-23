export async function hostJSON(response, operation='info') {
  const text=await response.text();
  const uncertain=operation==='rotate'?' وضعیت تغییر رمز نامشخص است؛ قبل از تکرار، ورود با رمز جدید و سپس قبلی را امتحان کنید.':'';
  const fail=message=>{throw new Error(message+uncertain);};
  const prefix=`پاسخ هاست: HTTP ${response.status}. `;
  if(response.status===404)fail(prefix+'فایل ترمینال در این آدرس پیدا نشد؛ نام فایل و دامنه را با File Manager تطبیق دهید.');
  if(response.status===403 && text.includes('Harbor Terminal requires HTTPS.'))fail(prefix+'PHP اتصال را HTTPS تشخیص نمی‌دهد. تنظیم HTTPS دامنه یا پراکسی باید در هاست اصلاح شود.');
  if(response.status===503 && text.includes('Credential configuration unavailable.'))fail(prefix+'اطلاعات ورود داخل فایل PHP خوانده نشد؛ فایل را بدون دستکاری از پشتیبان همین ترمینال بازیابی کنید.');
  if(/<\?php\b/.test(text))fail(prefix+'هاست کد PHP را اجرا نمی‌کند. تنظیم اجرای PHP این دامنه را در cPanel بررسی کنید.');
  if(!response.ok && !(response.headers.get('content-type')||'').toLowerCase().includes('application/json')){
    if(response.status>=500)fail(prefix+'اجرای فایل روی هاست خطا دارد. در cPanel بخش Errors، خطای همین فایل و نسخهٔ PHP دامنه را بررسی کنید؛ حداقل PHP 8.1 لازم است.');
    if(response.status===403||response.status===406)fail(prefix+'دسترسی به درخواست مسدود شده است؛ پاسخ ممکن است از ModSecurity، فایروال یا محدودیت فایل باشد.');
    fail(prefix+'هاست به‌جای پاسخ ترمینال، صفحهٔ خطا فرستاد.');
  }
  if(!(response.headers.get('content-type')||'').toLowerCase().includes('application/json')){
    if(/cf-chl-|challenge-platform|just a moment/i.test(text))fail(prefix+'صفحهٔ بررسی مرورگر یا چالش امنیتی دریافت شد؛ درخواست افزونه به API ترمینال نرسیده است.');
    fail(prefix+'به‌جای اطلاعات ترمینال، صفحهٔ HTML یا پاسخ دیگری دریافت شد. آدرس فایل و قوانین بازنویسی سایت را بررسی کنید.');
  }
  try { const data=JSON.parse(text);if(!data||typeof data!=='object'||Array.isArray(data))fail(prefix+'ساختار پاسخ JSON معتبر نیست.');return data; }
  catch(error){if(error instanceof SyntaxError)fail(prefix+'پاسخ JSON خراب است؛ ممکن است پیام خطای PHP قبل از آن چاپ شده باشد.');throw error;}
}
export async function probeHost(profile,fetcher=fetch) {
  const url=new URL(profile.url);url.searchParams.set('api','info');
  let response;
  try {response=await fetcher(url.href,{cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(15000)});}
  catch(error){throw new Error(error.name==='TimeoutError'?'هاست در ۱۵ ثانیه پاسخ نداد.':'ارتباط با فایل ترمینال برقرار نشد؛ گواهی HTTPS، تغییر مسیر دامنه و اجازهٔ دسترسی افزونه را بررسی کنید.');}
  const data=await hostJSON(response);
  if(!response.ok)throw new Error(`پاسخ هاست: HTTP ${response.status}. بررسی نصب انجام نشد.`);
  if(data.id!==profile.id||data.product!=='harbor-terminal')throw new Error('پاسخ JSON دریافت شد، اما هویت فایل با اتصال انتخاب‌شده مطابقت ندارد. آدرس همان فایل ترمینال را وارد کنید.');
  return data;
}

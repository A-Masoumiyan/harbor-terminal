export async function cpanelRequest(expected, operation, params, upload) {
  const deadline = expected.deadline ?? Date.now() + 60000;
  if (Date.now() >= deadline) return {error: 'مهلت این درخواست گذشته است؛ عملیات انجام نشد.'};
  if (location.origin !== expected.origin || !location.pathname.startsWith(expected.session + '/')) {
    return {error: 'نشست تب عوض شده است؛ نشانی تازهٔ Upload را وارد کنید.'};
  }
  const endpoint = expected.origin + expected.session + '/execute/' + operation;
  let stage='ارتباط با پنل';
  try {
    let response;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1, Math.min(60000, deadline - Date.now())));
    try {
      if (upload) {
        const body = new FormData();
        body.set('dir', params.dir); body.set('overwrite', params.overwrite === '1' ? '1' : '0');
        body.set('file-1', new Blob([upload.source], {type: 'application/x-httpd-php'}), upload.filename);
        if (Date.now() >= deadline) return {error: 'مهلت آپلود گذشته است؛ فایل ارسال نشد.'};
        response = await fetch(endpoint, {method: 'POST', credentials: 'same-origin', body, signal: controller.signal, redirect: 'error'});
      } else {
        response = await fetch(endpoint + '?' + new URLSearchParams(params), {credentials: 'same-origin', signal: controller.signal, redirect: 'error'});
      }
      if (!response.ok) return {error:`cPanel / HTTP ${response.status}: ${[401,403].includes(response.status)?'نشست یا اجازهٔ دسترسی معتبر نیست؛ دوباره وارد cPanel شوید و آدرس تازهٔ Upload را وارد کنید.':'پنل پاسخ موفق نداد؛ در تب اصلی cPanel اتصال را بررسی کنید.'}`};
      stage='خواندن پاسخ API';
      let json;
      try{json=await response.json();}catch{return {error:'cPanel به‌جای پاسخ API، صفحهٔ وب برگرداند؛ معمولاً نشست منقضی شده است. دوباره وارد شوید و آدرس تازهٔ Upload را بگیرید.'};}
      const result = json.result ?? json;
      if (Number(result.status) !== 1) return {error:`cPanel درخواست ${operation} را نپذیرفت. وجود فایل یا پوشه و دسترسی این قابلیت را در File Manager بررسی کنید؛ برای نصب تازه می‌توانید از نصب دستی استفاده کنید.`};
      // Upload responses sometimes contain per-file failures even with top-level success.
      if (upload) {
        const files = result.data?.uploads;
        if (Array.isArray(files) && files.some(file => file.status !== undefined && Number(file.status) !== 1)) throw new Error('File upload failed');
        if ((Array.isArray(result.data?.failed) && result.data.failed.length) || Number(result.data?.failed) > 0) throw new Error('File upload failed');
      }
      return {data: upload ? true : result.data};
    } finally { clearTimeout(timer); }
  } catch { return {error: `cPanel / ${stage}: پاسخ معتبر دریافت نشد. ورود و اتصال پنل را بررسی کنید. اگر مرحله آپلود بود، پیش از تکرار وجود فایل را در File Manager بررسی کنید.`}; }
}

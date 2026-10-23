export async function cpanelRequest(expected, operation, params, upload) {
  const deadline = expected.deadline ?? Date.now() + 60000;
  if (Date.now() >= deadline) return {error: 'مهلت این درخواست گذشته است؛ عملیات انجام نشد.'};
  if (location.origin !== expected.origin || !location.pathname.startsWith(expected.session + '/')) {
    return {error: 'نشست تب عوض شده است؛ نشانی تازهٔ Upload را وارد کنید.'};
  }
  const endpoint = expected.origin + expected.session + '/execute/' + operation;
  try {
    let response;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1, Math.min(60000, deadline - Date.now())));
    try {
      if (upload) {
        const body = new FormData();
        body.set('dir', params.dir); body.set('overwrite', '0');
        body.set('file-1', new Blob([upload.source], {type: 'application/x-httpd-php'}), upload.filename);
        if (Date.now() >= deadline) return {error: 'مهلت آپلود گذشته است؛ فایل ارسال نشد.'};
        response = await fetch(endpoint, {method: 'POST', credentials: 'same-origin', body, signal: controller.signal, redirect: 'error'});
      } else {
        response = await fetch(endpoint + '?' + new URLSearchParams(params), {credentials: 'same-origin', signal: controller.signal, redirect: 'error'});
      }
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const json = await response.json();
      const result = json.result ?? json;
      if (Number(result.status) !== 1) throw new Error('cPanel API rejected the request');
      // Upload responses sometimes contain per-file failures even with top-level success.
      if (upload) {
        const files = result.data?.uploads;
        if (Array.isArray(files) && files.some(file => file.status !== undefined && Number(file.status) !== 1)) throw new Error('File upload failed');
        if (Array.isArray(result.data?.failed) && result.data.failed.length) throw new Error('File upload failed');
      }
      return {data: upload ? true : result.data};
    } finally { clearTimeout(timer); }
  } catch { return {error: 'پاسخ معتبر از cPanel دریافت نشد. ورود، اجازهٔ API و نتیجهٔ آپلود را در File Manager بررسی کنید؛ عملیات را کورکورانه تکرار نکنید.'}; }
}

import {permissionPattern} from './core.js';
import {cpanelRequest} from './cpanel.js';

export async function withTimeout(promise, milliseconds, message) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

export async function requestCpanel(api, config, operation, params = {}, upload = null, timeoutMs = upload ? 70000 : 20000) {
  const timeoutMessage = upload
    ? 'زمان ارتباط با cPanel تمام شد؛ نتیجهٔ آپلود نامشخص است. پیش از تکرار، وجود فایل را در File Manager بررسی کنید.'
    : 'cPanel تا ۲۰ ثانیه پاسخ نداد. تب Upload را یک‌بار تازه‌سازی کنید، منتظر بازشدن آن بمانید و نشانی تازه را دوباره وارد کنید.';
  const deadline = Date.now() + Math.max(1, timeoutMs - Math.min(1000, timeoutMs / 10));
  return withTimeout((async () => {
    const tabs = await api.tabs.query({url: permissionPattern(config.origin)});
    const matching = tabs.filter(tab => {
      try { const url = new URL(tab.url); return url.origin === config.origin && url.pathname.startsWith(config.session + '/'); }
      catch { return false; }
    });
    // Prefer the actual page supplied by the user, rather than the oldest cPanel tab.
    const tab = matching.find(t => new URL(t.url).pathname === config.pagePath)
      ?? matching.find(t => /\/filemanager\/upload[^/]*\.html$/.test(new URL(t.url).pathname))
      ?? matching.find(t => t.active) ?? matching[0];
    if (!tab) throw new Error('تب واردشدهٔ cPanel پیدا نشد. صفحهٔ Upload را در همین مرورگر باز نگه دارید.');
    if (Date.now() >= deadline) throw new Error(timeoutMessage);
    const results = await api.scripting.executeScript({target: {tabId: tab.id}, injectImmediately: true,
      func: cpanelRequest, args: [{...config, deadline}, operation, params, upload]});
    const result = results[0]?.result;
    if (!result || result.error) throw new Error(result?.error || 'ارتباط با تب cPanel انجام نشد.');
    return result.data;
  })(), timeoutMs, timeoutMessage);
}

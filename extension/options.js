import {cpanelRequest} from './cpanel.js';
import {parseCpanel, permissionPattern, domainChoices, terminalURL, normalizePath,
  randomHex, generatePassword, renderTerminal, newerVersion, REPOSITORY, RELEASES, httpsURL} from './core.js';
const api = globalThis.browser ?? globalThis.chrome;
const $ = id => document.getElementById(id);
let inspected = null, choices = [], busy = false, currentProfile = null;
const actionButtons = ['inspect', 'install', 'verify', 'forget', 'check-update'];
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
async function task(work) {
  if (busy) return;
  busy = true;
  actionButtons.forEach(id => $(id).disabled = true);
  $('rotate-form').querySelector('button').disabled = true;
  try { await work(); } catch (error) { status(error.message || 'عملیات انجام نشد.', true); }
  finally { busy = false; actionButtons.forEach(id => $(id).disabled = false); $('rotate-form').querySelector('button').disabled = false; }
}
async function grant(url) {
  if (!await api.permissions.request({origins: [permissionPattern(url)]})) throw new Error('اجازهٔ دسترسی به این دامنه داده نشد.');
}
// Executed only in an explicitly selected, already authenticated cPanel tab.

async function callCpanel(config, operation, params = {}, upload = null) {
  const tabs = await api.tabs.query({url: permissionPattern(config.origin)});
  const tab = tabs.find(t => {
    try { const u = new URL(t.url); return u.origin === config.origin && u.pathname.startsWith(config.session + '/'); } catch { return false; }
  });
  if (!tab) throw new Error('تب واردشدهٔ cPanel پیدا نشد. صفحهٔ Upload را در همین مرورگر باز نگه دارید.');
  const results = await api.scripting.executeScript({target: {tabId: tab.id}, func: cpanelRequest, args: [config, operation, params, upload]});
  const result = results[0]?.result;
  if (!result || result.error) throw new Error(result?.error || 'ارتباط با تب cPanel انجام نشد.');
  return result.data;
}
async function displayProfile() {
  const {profile} = await api.storage.local.get('profile');
  currentProfile = profile ?? null;
  $('saved').hidden = $('rotation').hidden = !profile;
  if (profile) {
    $('saved-url').textContent = profile.url;
    $('verification').textContent = profile.verified ? 'هویت فایل نصب‌شده بررسی شده است.' : 'آپلود ثبت شده؛ بررسی دسترسی HTTPS هنوز انجام نشده است.';
  }
}
function invalidate() { inspected = null; choices = []; $('destination').hidden = true; }
$('upload-url').addEventListener('input', invalidate);
$('directory').addEventListener('input', invalidate);
function preview() {
  const selected = choices[Number($('domain').value)];
  $('preview').textContent = selected ? `https://${selected.domain}/${selected.relative ? selected.relative + '/' : ''}harbor-terminal-<شناسه>.php` : '';
}
$('domain').addEventListener('change', preview);
$('inspect').addEventListener('click', () => task(async () => {
  const config = parseCpanel($('upload-url').value.trim());
  await grant(config.origin); // Request permission directly from this user gesture.
  status('در حال خواندن اطلاعات دامنه از cPanel…');
  const directory = normalizePath($('directory').value.trim() || config.directory);
  const data = await callCpanel(config, 'DomainInfo/domains_data', {format: 'list'});
  choices = domainChoices(data, directory);
  if (!choices.length) throw new Error('برای این پوشه دامنه‌ای با document root معتبر پیدا نشد. مسیر داخل پوشهٔ وب دامنه را انتخاب کنید.');
  inspected = {...config, directory};
  $('directory').value = directory;
  $('domain').replaceChildren(...choices.map((choice, i) => new Option(`${choice.domain} — ${choice.root}`, String(i))));
  $('destination').hidden = false; $('owner').checked = false; preview();
  status('دامنه تشخیص داده شد. مقصد را بررسی و نصب را انتخاب کنید.');
}));
$('install').addEventListener('click', () => task(async () => {
  if (!inspected || !$('owner').checked) throw new Error('ابتدا مقصد را تشخیص بدهید و مالکیت هاست را تأیید کنید.');
  const choice = choices[Number($('domain').value)];
  if (!choice) throw new Error('دامنه را انتخاب کنید.');
  status('در حال ساخت رمز و فایل اختصاصی…');
  const id = randomHex(8), filename = `harbor-terminal-${id}.php`, password = generatePassword();
  const template = await (await fetch(api.runtime.getURL('terminal.template.php'))).text();
  const source = await renderTerminal(template, password, id);
  // Show the password before upload: a lost HTTP response must never lose the only copy.
  $('generated-password').value = password; $('generated').hidden = false;
  $('pending-note').textContent = 'هنوز موفقیت آپلود تأیید نشده است. در صورت قطع ارتباط، پیش از نصب مجدد File Manager را بررسی کنید.';
  const profile = {id, filename, url: terminalURL(choice, filename), directory: inspected.directory, verified: false};
  await api.storage.local.set({pending: profile}); // No password or cPanel session is persisted.
  status('در حال آپلود فایل از نشست cPanel…');
  await callCpanel(inspected, 'Fileman/upload_files', {dir: inspected.directory}, {filename, source});
  await api.storage.local.set({profile}); await api.storage.local.remove('pending');
  $('pending-note').textContent = 'آپلود انجام شد. رمز را در مدیر رمز ذخیره کنید و «بررسی نصب» را بزنید.';
  $('upload-url').value = ''; invalidate();
  await displayProfile(); status('آپلود انجام شد. اکنون «بررسی نصب» را بزنید.');
}));
async function info(profile) {
  const url = httpsURL(profile.url); url.searchParams.set('api', 'info');
  const response = await fetch(url.href, {cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15000)});
  if (!response.ok || !(response.headers.get('content-type') || '').includes('application/json')) throw new Error('فایل نصب‌شده پاسخ معتبر نداد. HTTPS، نسخهٔ PHP و مسیر را بررسی کنید.');
  const data = await response.json();
  if (data.id !== profile.id || data.product !== 'harbor-terminal') throw new Error('هویت فایل با نصب این افزونه مطابقت ندارد.');
  return data;
}
$('verify').addEventListener('click', () => task(async () => {
  const profile = currentProfile; if (!profile) return;
  await grant(profile.url); const data = await info(profile);
  profile.verified = true; await api.storage.local.set({profile}); await displayProfile();
  status(data.commands ? 'نصب تأیید شد و اجرای فرمان فعال است.' : 'نصب تأیید شد؛ هاست توابع اجرای فرمان را بسته است.', !data.commands);
}));
$('open').addEventListener('click', async () => {
  const {profile} = await api.storage.local.get('profile'); if (profile) await api.tabs.create({url: httpsURL(profile.url).href});
});
$('forget').addEventListener('click', () => task(async () => {
  await api.storage.local.remove(['profile', 'pending']); await displayProfile();
  $('generated-password').value = ''; $('generated').hidden = true;
  status('اتصال از افزونه حذف شد. برای حذف دسترسی، فایل PHP را هم از File Manager پاک کنید.');
}));
$('clear-password').addEventListener('click', () => { $('generated-password').value = ''; $('generated').hidden = true; });
$('rotate-form').addEventListener('submit', event => {
  event.preventDefault();
  task(async () => {
    const profile = currentProfile; if (!profile) return;
    const oldPassword = $('old-password').value, newPassword = $('new-password').value;
    if (newPassword !== $('confirm-password').value) throw new Error('دو نسخهٔ رمز جدید برابر نیستند.');
    if (Array.from(newPassword).length < 16 || new TextEncoder().encode(newPassword).length > 256) throw new Error('رمز جدید باید حداقل ۱۶ نویسه و حداکثر ۲۵۶ بایت باشد.');
    await grant(profile.url);
    await info(profile); // Verify installation identity before transmitting credentials.
    const url = httpsURL(profile.url); url.searchParams.set('api', 'rotate');
    status('در حال ثبت رمز جدید روی هاست…');
    let response;
    try {
      response = await fetch(url.href, {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: profile.id, current_password: oldPassword, new_password: newPassword}),
        credentials: 'omit', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(30000)});
    } catch { throw new Error('ارتباط قطع شد؛ وضعیت تغییر رمز نامشخص است. ابتدا ورود با رمز جدید را امتحان کنید و سپس رمز قبلی.'); }
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || 'رمز تغییر نکرد.');
    $('rotate-form').reset(); status('رمز روی هاست تغییر کرد. همهٔ ورودهای قبلی باطل شدند.');
  });
});
$('check-update').addEventListener('click', () => task(async () => {
  await grant('https://api.github.com');
  $('update-status').textContent = 'در حال بررسی…';
  const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/releases/latest`, {
    headers: {Accept: 'application/vnd.github+json'}, credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000)});
  if (response.status === 404) { $('update-status').textContent = 'هنوز نسخهٔ عمومی در Releases منتشر نشده است.'; return; }
  if (!response.ok) throw new Error('بررسی به‌روزرسانی انجام نشد؛ احتمال محدودیت درخواست گیت‌هاب وجود دارد.');
  const release = await response.json(), version = String(release.tag_name).replace(/^v/, '');
  $('update-status').textContent = newerVersion(version, api.runtime.getManifest().version) ? `نسخهٔ ${version} برای دریافت موجود است.` : 'نسخهٔ جدیدتری منتشر نشده است.';
  $('release-link').href = RELEASES; $('release-link').hidden = false;
}));
$('version').textContent = api.runtime.getManifest().version;
await displayProfile();
const {pending} = await api.storage.local.get('pending');
if (pending) status(`نتیجهٔ نصب قبلی نامشخص است. پیش از تکرار، وجود ${pending.filename} را در File Manager بررسی کنید. رمز آن فقط در صفحهٔ قبلی نمایش داده شده بود.`, true);

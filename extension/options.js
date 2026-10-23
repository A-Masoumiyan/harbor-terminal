import {requestCpanel, withTimeout} from './transport.js';
import {upgradeSource, restoreSource} from './upgrade.js';
import {loadConnections, saveConnection, selectConnection, removeConnection} from './connections.js';
import {probeHost,hostJSON} from './host-response.js';
import {parseCpanel, permissionPattern, domainChoices, terminalURL, normalizePath,
  randomHex, generatePassword, renderTerminal, newerVersion, REPOSITORY, RELEASES, httpsURL, passwordLengthError} from './core.js';
const api = globalThis.browser ?? globalThis.chrome;
const $ = id => document.getElementById(id);
let inspected = null, choices = [], busy = false, currentProfile = null, preparedUpgrade = null, backupURL = null;
let manualProfile=null,manualURL=null,lastDiagnostics=null;
const actionButtons = ['inspect', 'install', 'verify', 'forget', 'check-update', 'prepare-upgrade', 'apply-upgrade','save-connection','connect-existing','diagnose','export-diagnostics','manual-generate','manual-verify','restore-host'];
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
async function task(work) {
  if (busy) return;
  busy = true;
  actionButtons.forEach(id => $(id).disabled = true);
  ['upload-url', 'directory', 'domain', 'owner'].forEach(id => $(id).disabled = true);
  $('connections').disabled=true;
  $('rotate-form').querySelector('button').disabled = true;
  try { await work(); } catch (error) { status(error.message || 'عملیات انجام نشد.', true); }
  finally { busy = false; actionButtons.forEach(id => $(id).disabled = false); ['upload-url', 'directory', 'domain', 'owner'].forEach(id => $(id).disabled = false); $('rotate-form').querySelector('button').disabled = false; $('connections').disabled=false; }
}
async function grant(url) {
  status('در انتظار اجازهٔ دسترسی مرورگر؛ اگر پنجرهٔ اجازه باز است، آن را بررسی کنید.');
  const granted = await withTimeout(api.permissions.request({origins: [permissionPattern(url)]}), 30000,
    'پاسخ پنجرهٔ اجازهٔ دسترسی دریافت نشد. درخواست دسترسی Edge را بررسی و سپس دوباره تلاش کنید.');
  if (!granted) throw new Error('اجازهٔ دسترسی به این دامنه داده نشد.');
}
// Executed only in an explicitly selected, already authenticated cPanel tab.

async function callCpanel(config, operation, params = {}, upload = null) {
  return requestCpanel(api, config, operation, params, upload);
}
async function displayProfile() {
  const {profile,connections} = await loadConnections(api);
  currentProfile = profile ?? null;
  $('active-color').style.backgroundColor=profile?.color??'#b5ed89';
  $('connections').replaceChildren(...connections.map(p=>new Option(p.name,p.id)));
  if(profile)$('connections').value=profile.id;else $('connections').append(new Option('هنوز اتصالی ثبت نشده است',''));
  $('connection-name').value=profile?.name??'';$('connection-color').value=profile?.color??'#b5ed89';
  $('extension-version').textContent=api.runtime.getManifest().version;
  $('terminal-version').textContent=profile?.serverVersion??'بررسی نشده';$('connection-health').textContent=profile?.verified?'تأیید شده':'بررسی نشده';
  $('prepare-upgrade').hidden = !profile;
  $('saved').hidden = $('rotation').hidden = !profile;
  if (profile) {
    $('saved-url').textContent = profile.url;
    $('verification').textContent = profile.verified ? 'هویت فایل نصب‌شده بررسی شده است.' : 'آپلود ثبت شده؛ بررسی دسترسی HTTPS هنوز انجام نشده است.';
  }
}
function clearUpgrade() {
  preparedUpgrade = null; $('upgrade-review').hidden = true; $('upgrade-consent').checked = false;
  if (backupURL) URL.revokeObjectURL(backupURL); backupURL = null; $('backup-link').removeAttribute('href');
}
function invalidate() { inspected = null; choices = []; $('destination').hidden = true; clearUpgrade(); }
$('upload-url').addEventListener('input', invalidate);
$('directory').addEventListener('input', invalidate);
function preview() {
  const selected = choices[Number($('domain').value)];
  $('preview').textContent = selected ? `https://${selected.domain}/${selected.relative ? selected.relative + '/' : ''}harbor-terminal-<شناسه>.php` : '';
}
$('domain').addEventListener('change', () => { clearUpgrade(); preview(); });
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
  const template = await (await fetch(new URL('./terminal.template.php',import.meta.url))).text();
  const source = await renderTerminal(template, password, id);
  // Show the password before upload: a lost HTTP response must never lose the only copy.
  $('generated-password').value = password; $('generated').hidden = false;
  $('pending-note').textContent = 'هنوز موفقیت آپلود تأیید نشده است. در صورت قطع ارتباط، پیش از نصب مجدد File Manager را بررسی کنید.';
  const profile = {id, filename, url: terminalURL(choice, filename), directory: inspected.directory, verified: false};
  await api.storage.local.set({pending: profile}); // No password or cPanel session is persisted.
  status('در حال آپلود فایل از نشست cPanel…');
  await callCpanel(inspected, 'Fileman/upload_files', {dir: inspected.directory}, {filename, source});
  await saveConnection(api,profile); await api.storage.local.remove('pending');
  $('pending-note').textContent = 'آپلود انجام شد. رمز را در مدیر رمز ذخیره کنید و «بررسی نصب» را بزنید.';
  $('upload-url').value = ''; invalidate();
  await displayProfile(); status('آپلود انجام شد. اکنون «بررسی نصب» را بزنید.');
}));
$('prepare-upgrade').addEventListener('click', () => task(async () => {
  const profile = currentProfile, choice = choices[Number($('domain').value)];
  if (!profile || !inspected || !choice || !$('owner').checked) throw new Error('ابتدا مقصد را تشخیص بدهید و مالکیت هاست را تأیید کنید.');
  if (profile.filename !== `harbor-terminal-${profile.id}.php` || (profile.directory && normalizePath(profile.directory) !== inspected.directory) || terminalURL(choice, profile.filename) !== profile.url) {
    throw new Error('پوشه و دامنهٔ انتخاب‌شده با ترمینال فعلی یکی نیستند. همان پوشهٔ نصب قبلی را انتخاب کنید.');
  }
  profile.directory=inspected.directory;
  await grant(profile.url); clearUpgrade();
  status('در حال خواندن فایل فعلی برای حفظ اطلاعات ورود…');
  const old = await callCpanel(inspected, 'Fileman/get_file_content', {dir: profile.directory, file: profile.filename, from_charset: 'utf-8', to_charset: 'utf-8'});
  if (typeof old?.content !== 'string') throw new Error('محتوای فایل قبلی از cPanel دریافت نشد؛ فایلی تغییر نکرد.');
  const template = await (await fetch(new URL('./terminal.template.php',import.meta.url))).text();
  const source = upgradeSource(template, old.content, profile.id);
  preparedUpgrade = {profile: {...profile}, config: {...inspected}, source, template};
  backupURL = URL.createObjectURL(new Blob([old.content], {type: 'text/plain;charset=utf-8'}));
  $('backup-link').href = backupURL; $('backup-link').download = profile.filename + '.backup.txt';
  $('upgrade-review').hidden = false;
  status('ارتقا آماده است. پشتیبان فایل قبلی را دریافت کنید و سپس ارتقای همان فایل را تأیید کنید.');
}));
$('apply-upgrade').addEventListener('click', () => task(async () => {
  if (!preparedUpgrade || !$('upgrade-consent').checked) throw new Error('ابتدا پشتیبان را نگه دارید و ارتقای فایل فعلی را تأیید کنید.');
  const prepared = preparedUpgrade;
  status('در حال ارتقای ترمینال فعلی؛ آدرس و رمز حفظ می‌شوند…');
  const latest = await callCpanel(prepared.config, 'Fileman/get_file_content', {dir: prepared.profile.directory, file: prepared.profile.filename, from_charset: 'utf-8', to_charset: 'utf-8'});
  // Preserve a password rotated after the review step as well.
  const source = upgradeSource(prepared.template, latest?.content, prepared.profile.id);
  // No retry: a lost response can mean that the upload already succeeded.
  preparedUpgrade = null;
  await callCpanel(prepared.config, 'Fileman/upload_files', {dir: prepared.profile.directory, overwrite: '1'}, {filename: prepared.profile.filename, source});
  const data = await info(prepared.profile);
  if (data.version !== api.runtime.getManifest().version) throw new Error('آپلود انجام شد اما نسخهٔ جدید هنوز از وب‌سرور پاسخ نمی‌دهد؛ کش PHP هاست را بررسی کنید.');
  await saveConnection(api,{...prepared.profile,serverVersion:data.version,verified:true});
  await displayProfile(); clearUpgrade(); status('ترمینال فعلی ارتقا پیدا کرد. صفحهٔ ترمینال را تازه‌سازی کنید؛ آدرس و رمز فعلی حفظ شدند.');
}));
async function info(profile) {
  return probeHost(profile);
}
$('verify').addEventListener('click', () => task(async () => {
  const profile = currentProfile; if (!profile) return;
  await grant(profile.url); const data = await info(profile);
  profile.verified = true; profile.serverVersion=data.version; await saveConnection(api,profile); await displayProfile();
  status(data.commands ? 'نصب تأیید شد و اجرای فرمان فعال است.' : 'نصب تأیید شد؛ هاست توابع اجرای فرمان را بسته است.', !data.commands);
}));
$('open').addEventListener('click', async () => {
  const {profile} = await api.storage.local.get('profile'); if (profile) await api.tabs.create({url: httpsURL(profile.url).href});
});
$('forget').addEventListener('click', () => task(async () => {
  clearUpgrade();
  await removeConnection(api,currentProfile.id); await api.storage.local.remove('pending'); await displayProfile();
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
    const lengthError = passwordLengthError(newPassword);
    if (lengthError) throw new Error(lengthError);
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
    const data = await hostJSON(response,'rotate');
    if (!response.ok || !data.ok) throw new Error(data.error || 'رمز تغییر نکرد.');
    $('rotate-form').reset(); status('رمز روی هاست تغییر کرد. همهٔ ورودهای قبلی باطل شدند.');
  });
});
$('check-update').addEventListener('click', () => task(async () => {
  $('package-link').hidden=true;
  await grant('https://api.github.com');
  $('update-status').textContent = 'در حال بررسی…';
  const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/releases/latest`, {
    headers: {Accept: 'application/vnd.github+json'}, credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000)});
  if (response.status === 404) { $('update-status').textContent = 'هنوز نسخهٔ عمومی در Releases منتشر نشده است.'; return; }
  if (!response.ok) throw new Error('بررسی به‌روزرسانی انجام نشد؛ احتمال محدودیت درخواست گیت‌هاب وجود دارد.');
  const release = await response.json(), version = String(release.tag_name).replace(/^v/, '');
  $('update-status').textContent = newerVersion(version, api.runtime.getManifest().version) ? `نسخهٔ ${version} برای دریافت موجود است.` : 'نسخهٔ جدیدتری منتشر نشده است.';
  $('release-link').href = RELEASES; $('release-link').hidden = false;
  const browserName = api.runtime.getURL('').startsWith('moz-extension:') ? 'firefox' : 'chrome-edge';
  const asset = release.assets?.find(file => file.name === `harbor-terminal-${browserName}-${version}.zip`);
  if (asset) {
    const assetURL = httpsURL(asset.browser_download_url);
    if (assetURL.origin === 'https://github.com' && assetURL.pathname.startsWith(`/${REPOSITORY}/releases/download/`)) {
      $('package-link').href = assetURL.href; $('package-link').textContent = `دریافت نسخهٔ ${version} برای مرورگر من`;
      $('package-link').hidden = false;
    }
  } else $('update-status').textContent+=' بستهٔ دریافت این نسخه هنوز در Releases آماده نشده است.';
}));
$('connections').addEventListener('change',()=>task(async()=>{if(!$('connections').value)return;await selectConnection(api,$('connections').value);clearUpgrade();lastDiagnostics=null;await displayProfile();status('اتصال فعال تغییر کرد.');}));
$('save-connection').addEventListener('click',()=>task(async()=>{if(!currentProfile)throw new Error('ابتدا یک اتصال اضافه کنید.');await saveConnection(api,{...currentProfile,name:$('connection-name').value.trim()||new URL(currentProfile.url).hostname,color:$('connection-color').value});await displayProfile();status('نام و رنگ اتصال ذخیره شد.');}));
$('connect-existing').addEventListener('click',()=>task(async()=>{
  const url=httpsURL($('existing-url').value.trim());url.search='';url.hash='';
  const match=url.pathname.match(/\/harbor-terminal-([a-f0-9]{16})\.php$/);
  if(!match)throw new Error('آدرس فایل harbor-terminal-شناسه.php را از صفحهٔ ترمینال فعلی کپی کنید.');
  await grant(url.href);const profile={id:match[1],url:url.href,filename:`harbor-terminal-${match[1]}.php`,directory:''};
  const data=await info(profile);await saveConnection(api,{...profile,verified:true,serverVersion:data.version});await displayProfile();status('اتصال قبلی بازیابی شد؛ نیازی به نصب دوباره روی هاست نیست.');
}));
$('diagnose').addEventListener('click',()=>task(async()=>{
  if(!currentProfile)throw new Error('ابتدا یک اتصال اضافه کنید.');
  await grant(currentProfile.url);const data=await info(currentProfile);
  lastDiagnostics={checkedAt:new Date().toISOString(),extensionVersion:api.runtime.getManifest().version,terminalVersion:data.version,php:data.php??'نسخهٔ قدیمی؛ ارتقای هاست لازم است',commands:data.commands,features:data.features??{},serverHost:new URL(currentProfile.url).hostname};
  $('diagnostics').textContent=`PHP: ${lastDiagnostics.php} · اجرای فرمان: ${data.commands?'فعال':'بسته'} · ${data.version===api.runtime.getManifest().version?'نسخه‌ها یکسان‌اند':'برای یکسان‌شدن نسخه‌ها، ترمینال روی هاست را ارتقا دهید.'}`;
  await saveConnection(api,{...currentProfile,serverVersion:data.version,verified:true});await displayProfile();status('بررسی اتصال کامل شد.');
}));
$('export-diagnostics').addEventListener('click',()=>task(async()=>{
  if(!lastDiagnostics)throw new Error('ابتدا «بررسی اتصال و سازگاری» را بزنید.');
  downloadText(JSON.stringify(lastDiagnostics,null,2),'harbor-diagnostics.json','application/json');
}));
function downloadText(text,name,type='text/plain'){
  const url=URL.createObjectURL(new Blob([text],{type}));const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$('manual-generate').addEventListener('click',()=>task(async()=>{
  const base=httpsURL($('manual-base').value.trim());base.search='';base.hash='';if(!base.pathname.endsWith('/'))base.pathname+='/';
  const id=randomHex(8),filename=`harbor-terminal-${id}.php`,password=generatePassword();
  const template=await(await fetch(new URL('./terminal.template.php',import.meta.url))).text();const source=await renderTerminal(template,password,id);
  manualProfile={id,filename,url:new URL(filename,base).href,directory:'',verified:false};
  if(manualURL)URL.revokeObjectURL(manualURL);manualURL=URL.createObjectURL(new Blob([source],{type:'text/plain'}));
  $('manual-download').href=manualURL;$('manual-download').download=filename;$('manual-address').textContent=manualProfile.url;$('manual-result').hidden=false;
  $('generated-password').value=password;$('generated').hidden=false;$('pending-note').textContent='رمز را ذخیره کنید. فایل را دانلود و با File Manager در همان پوشهٔ وب آپلود کنید.';
  await api.storage.local.set({pending:manualProfile});status('فایل آماده است؛ آن را دانلود و آپلود کنید، سپس «بررسی و ثبت» را بزنید.');
}));
$('manual-verify').addEventListener('click',()=>task(async()=>{
  if(!manualProfile)throw new Error('ابتدا فایل را بسازید.');await grant(manualProfile.url);const data=await info(manualProfile);await saveConnection(api,{...manualProfile,verified:true,serverVersion:data.version});await api.storage.local.remove('pending');await displayProfile();status('نصب دستی تأیید و اتصال ذخیره شد. اکنون ترمینال را باز کنید.');
}));
$('restore-host').addEventListener('click',()=>task(async()=>{
  const profile=currentProfile,choice=choices[Number($('domain').value)],file=$('restore-file').files[0];
  if(!profile||!inspected||!choice||!file||!$('restore-consent').checked||!$('owner').checked)throw new Error('پوشهٔ cPanel، فایل پشتیبان و تأیید بازگردانی را مشخص کنید.');
  if(file.size>1000000||terminalURL(choice,profile.filename)!==profile.url)throw new Error('فایل پشتیبان یا پوشهٔ انتخاب‌شده با اتصال فعلی مطابقت ندارد.');
  await grant(profile.url);const backup=await file.text();const latest=await callCpanel(inspected,'Fileman/get_file_content',{dir:inspected.directory,file:profile.filename,from_charset:'utf-8',to_charset:'utf-8'});
  const source=restoreSource(backup,latest?.content,profile.id);await callCpanel(inspected,'Fileman/upload_files',{dir:inspected.directory,overwrite:'1'},{filename:profile.filename,source});
  const data=await info(profile);await saveConnection(api,{...profile,directory:inspected.directory,serverVersion:data.version,verified:true});await displayProfile();status('فایل قبلی بازگردانی شد؛ رمز فعلی حفظ شده است.');
}));
$('version').textContent = api.runtime.getManifest().version;
await displayProfile();
const setup=await api.storage.session.get('setupTabURL');
if(setup.setupTabURL){$('upload-url').value=setup.setupTabURL;await api.storage.session.remove('setupTabURL');status('صفحهٔ Upload از تب cPanel دریافت شد؛ «تشخیص دامنه و مسیر» را بزنید.');}
const {pending} = await api.storage.local.get('pending');
if (pending) status(`نتیجهٔ نصب قبلی نامشخص است. پیش از تکرار، وجود ${pending.filename} را در File Manager بررسی کنید. رمز آن فقط در صفحهٔ قبلی نمایش داده شده بود.`, true);

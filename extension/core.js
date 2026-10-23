export const REPOSITORY = 'A-Masoumiyan/harbor-terminal';
export const RELEASES = `https://github.com/${REPOSITORY}/releases`;
export const PBKDF_ITERATIONS = 600000;

export function httpsURL(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('فقط نشانی HTTPS بدون نام کاربری و رمز مجاز است.');
  return url;
}
export function permissionPattern(value) {
  return `https://${httpsURL(value).hostname}/*`;
}
export function normalizePath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || /[\x00-\x1f\\]/.test(value)) throw new Error('مسیر مطلق لینوکسی لازم است.');
  const parts = [];
  for (const part of value.split('/')) {
    if (part === '..') { if (!parts.length) throw new Error('مسیر نامعتبر است.'); parts.pop(); }
    else if (part && part !== '.') parts.push(part);
  }
  return '/' + parts.join('/');
}
export function parseCpanel(value) {
  const url = httpsURL(value);
  const match = url.pathname.match(/^\/(cpsess\d+)\/frontend\//);
  if (!match || !/\/filemanager\//.test(url.pathname)) throw new Error('نشانی صفحهٔ File Manager یا Upload در نشست واردشدهٔ cPanel را وارد کنید.');
  const dir = url.searchParams.get('dir');
  return {origin: url.origin, session: '/' + match[1], pagePath: url.pathname, directory: dir ? normalizePath(dir) : ''};
}
export function domainChoices(data, directory) {
  const dir = normalizePath(directory);
  const found = [];
  function visit(node) {
    if (!node || typeof node !== 'object') return;
    if (typeof node.domain === 'string' && typeof node.documentroot === 'string') {
      const root = normalizePath(node.documentroot);
      if (dir === root || dir.startsWith(root + '/')) {
        const domain = httpsURL('https://' + node.domain);
        if (domain.hostname === node.domain && domain.pathname === '/' && !domain.port && !domain.search && !domain.hash) {
          found.push({domain: node.domain, root, relative: dir.slice(root === '/' ? 0 : root.length).replace(/^\//, '')});
        }
      }
    }
    for (const child of Object.values(node)) if (child && typeof child === 'object') visit(child);
  }
  visit(data);
  const unique = [...new Map(found.map(item => [item.domain, item])).values()];
  return unique.sort((a, b) => b.root.length - a.root.length || a.domain.localeCompare(b.domain));
}
export function terminalURL(choice, filename) {
  if (!/^harbor-terminal-[a-f0-9]{16}\.php$/.test(filename)) throw new Error('نام فایل نامعتبر است.');
  const url = httpsURL('https://' + choice.domain);
  url.pathname = '/' + [choice.relative, filename].filter(Boolean).join('/').split('/').map(encodeURIComponent).join('/');
  return url.href;
}
export function randomHex(bytes = 16) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), n => n.toString(16).padStart(2, '0')).join('');
}
export function generatePassword() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export function passwordLengthError(password) {
  if (Array.from(password).length < 4) return 'رمز جدید باید حداقل ۴ کاراکتر داشته باشد.';
  if (new TextEncoder().encode(password).length > 256) return 'رمز جدید نباید بیشتر از ۲۵۶ بایت باشد.';
  return null;
}
export async function verifier(password, salt) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name: 'PBKDF2', salt: encoder.encode(salt), iterations: PBKDF_ITERATIONS, hash: 'SHA-256'}, key, 256);
  return Array.from(new Uint8Array(bits), n => n.toString(16).padStart(2, '0')).join('');
}
export async function renderTerminal(template, password, id) {
  if (!/^[a-f0-9]{16}$/.test(id)) throw new Error('شناسه نامعتبر است.');
  const salt = randomHex();
  const values = {INSTANCE_ID: id, AUTH_SALT: salt, AUTH_VERIFIER: await verifier(password, salt)};
  for (const [key, value] of Object.entries(values)) {
    if (template.split('__' + key + '__').length !== 2) throw new Error('قالب ترمینال معتبر نیست.');
    template = template.replace('__' + key + '__', value);
  }
  return template;
}
export function newerVersion(remote, local) {
  const valid = /^\d+\.\d+\.\d+$/;
  if (!valid.test(remote) || !valid.test(local)) return false;
  const a = remote.split('.').map(Number), b = local.split('.').map(Number);
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] > b[i]; }
  return false;
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pbkdf2Sync} from 'node:crypto';
import {parseCpanel, normalizePath, permissionPattern, domainChoices, terminalURL,
  generatePassword, renderTerminal, verifier, newerVersion, PBKDF_ITERATIONS} from '../extension/core.js';
import {cpanelRequest} from '../extension/cpanel.js';

test('cPanel session URL and absolute destination parsing', () => {
  const value = parseCpanel('https://panel.example:2083/cpsess123/frontend/jupiter/filemanager/upload-ajax.html?dir=%2Fhome%2Ftest%2Fpublic_html');
  assert.deepEqual(value, {origin: 'https://panel.example:2083', session: '/cpsess123', pagePath: '/cpsess123/frontend/jupiter/filemanager/upload-ajax.html', directory: '/home/test/public_html'});
  assert.equal(permissionPattern(value.origin), 'https://panel.example/*');
  assert.throws(() => parseCpanel('http://panel.example/cpsess1/frontend/jupiter/filemanager/index.html'));
  assert.throws(() => parseCpanel('https://user:secret@panel.example/cpsess1/frontend/jupiter/filemanager/index.html'));
  assert.throws(() => parseCpanel('https://panel.example/login'));
});
test('path boundary prevents sibling-root confusion; longest root first', () => {
  const data = {main_domain: {domain: 'example.test', documentroot: '/home/u/public_html'},
    addon_domains: [{domain: 'app.example.test', documentroot: '/home/u/public_html/app'},
      {domain: 'wrong.test', documentroot: '/home/u/public'},
      {domain: 'elsewhere.test', documentroot: '/home/u/other'}]};
  const choices = domainChoices(data, '/home/u/public_html/app/my folder');
  assert.deepEqual(choices.map(x => x.domain), ['app.example.test', 'example.test']);
  assert.equal(terminalURL(choices[0], 'harbor-terminal-1234567890abcdef.php'), 'https://app.example.test/my%20folder/harbor-terminal-1234567890abcdef.php');
  assert.equal(domainChoices(data, '/home/u/public_html-other').length, 0);
  assert.equal(normalizePath('/home/u/a/../b//'), '/home/u/b');
  assert.throws(() => normalizePath('/../../etc'));
  assert.throws(() => normalizePath('public_html'));
  assert.throws(() => normalizePath('/home/u\0'));
});
test('generated password is high entropy, verifier agrees with standard PBKDF2', async () => {
  const passwords = Array.from({length: 50}, generatePassword);
  assert.equal(new Set(passwords).size, 50);
  passwords.forEach(value => assert.match(value, /^[A-Za-z0-9_-]{32}$/));
  const salt = '0123456789abcdef0123456789abcdef', password = 'رمز آزمایشی طولانی 🔑';
  assert.equal(await verifier(password, salt), pbkdf2Sync(password, salt, PBKDF_ITERATIONS, 32, 'sha256').toString('hex'));
});
test('template contains verifier only and fails on incomplete template', async () => {
  const template = readFileSync(new URL('../extension/terminal.template.php', import.meta.url), 'utf8');
  const password = generatePassword();
  const output = await renderTerminal(template, password, '1234567890abcdef');
  assert.ok(!output.includes(password));
  assert.ok(!/__AUTH_|__INSTANCE_/.test(output));
  const salt = output.match(/const AUTH_SALT = '([a-f0-9]+)'/)[1];
  const hash = output.match(/const AUTH_VERIFIER = '([a-f0-9]+)'/)[1];
  assert.equal(hash, pbkdf2Sync(password, salt, PBKDF_ITERATIONS, 32, 'sha256').toString('hex'));
  await assert.rejects(renderTerminal('broken', password, '1234567890abcdef'));
});
test('release comparison handles multi-digit versions and rejects prereleases', () => {
  assert.equal(newerVersion('1.10.0', '1.9.5'), true);
  assert.equal(newerVersion('1.0.0', '1.0.0'), false);
  assert.equal(newerVersion('1.0.1-beta', '1.0.0'), false);
  assert.equal(newerVersion('0.9.9', '1.0.0'), false);
});
test('cPanel calls use matching origin, session and authenticated API; upload failures propagate', async () => {
  globalThis.location = {origin: 'https://panel.example:2083', pathname: '/cpsess123/frontend/jupiter/filemanager/index.html'};
  const expected = {origin: location.origin, session: '/cpsess123'};
  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, 'https://panel.example:2083/cpsess123/execute/DomainInfo/domains_data?format=list');
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.redirect, 'error');
      return new Response(JSON.stringify({result: {status: 1, data: [{domain: 'example.test'}]}}));
    };
    assert.equal((await cpanelRequest(expected, 'DomainInfo/domains_data', {format: 'list'}, null)).data[0].domain, 'example.test');
    globalThis.fetch = async (url, options) => {
      assert.ok(url.endsWith('/Fileman/upload_files'));
      assert.equal(options.method, 'POST');
      assert.equal(options.body.get('overwrite'), '0');
      assert.equal(options.body.get('file-1').name, 'example.php');
      assert.equal(await options.body.get('file-1').text(), '<?php echo 1;');
      return new Response(JSON.stringify({result: {status: 1, data: {uploads: [{status: 0}]}}}));
    };
    assert.ok((await cpanelRequest(expected, 'Fileman/upload_files', {dir: '/home/u/public_html'}, {filename: 'example.php', source: '<?php echo 1;'})).error);
    location.pathname = '/cpsess999/frontend/jupiter/index.html';
    assert.ok((await cpanelRequest(expected, 'DomainInfo/domains_data', {}, null)).error);
  } finally { globalThis.fetch = realFetch; delete globalThis.location; }
});
test('browser manifests have scoped optional hosts and packaged code only', () => {
  for (const browser of ['chromium', 'firefox']) {
    const manifest = JSON.parse(readFileSync(new URL(`../manifest.${browser}.json`, import.meta.url)));
    assert.equal(manifest.manifest_version, 3);
    assert.equal(manifest.version, JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version);
    assert.equal(manifest.host_permissions, undefined);
    assert.deepEqual(manifest.optional_host_permissions, ['https://*/*']);
    assert.ok(!manifest.content_security_policy.extension_pages.includes('unsafe-eval'));
    assert.equal(manifest.update_url, undefined);
  }
});

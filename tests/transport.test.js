import test from 'node:test';
import assert from 'node:assert/strict';
import {requestCpanel, withTimeout} from '../extension/transport.js';
import {cpanelRequest} from '../extension/cpanel.js';

const config = {origin: 'https://panel.example:2083', session: '/cpsess123', pagePath: '/cpsess123/frontend/jupiter/filemanager/upload-ajax.html'};
test('use the supplied Upload tab and inject before document_idle', async () => {
  const api = {tabs: {query: async () => [
    {id: 1, url: config.origin + config.session + '/frontend/jupiter/index.html'},
    {id: 2, url: config.origin + config.pagePath + '?dir=test'}]},
  scripting: {executeScript: async options => {
    assert.equal(options.target.tabId, 2);
    assert.equal(options.injectImmediately, true);
    assert.ok(options.args[0].deadline > Date.now());
    return [{result: {data: ['ok']}}];
  }}};
  assert.deepEqual(await requestCpanel(api, config, 'DomainInfo/domains_data'), ['ok']);
});
test('never-resolving tab lookup and injection both time out', async () => {
  const pending = () => new Promise(() => {});
  await assert.rejects(requestCpanel({tabs: {query: pending}}, config, 'DomainInfo/domains_data', {}, null, 25), /۲۰ ثانیه/);
  await assert.rejects(requestCpanel({tabs: {query: async () => [{id: 2, url: config.origin + config.pagePath}]},
    scripting: {executeScript: pending}}, config, 'DomainInfo/domains_data', {}, null, 25), /۲۰ ثانیه/);
});
test('expired upload cannot start after a delayed injection', async () => {
  const realFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('must not run'); };
  try {
    const result = await cpanelRequest({...config, deadline: Date.now() - 1}, 'Fileman/upload_files', {}, {source: '<?php', filename: 'test.php'});
    assert.ok(result.error);
    assert.equal(called, false);
  } finally { globalThis.fetch = realFetch; }
});
test('a delayed tab lookup never starts an upload after timeout', async () => {
  let called = false;
  const api = {tabs: {query: () => new Promise(resolve => setTimeout(() => resolve([{id: 2, url: config.origin + config.pagePath}]), 50))},
    scripting: {executeScript: async () => { called = true; return []; }}};
  await assert.rejects(requestCpanel(api, config, 'Fileman/upload_files', {}, {filename: 'test.php'}, 20), /نامشخص/);
  await new Promise(resolve => setTimeout(resolve, 70));
  assert.equal(called, false);
});
test('permission wait timeout does not continue dependent work on late approval', async () => {
  let continued = false;
  const request = new Promise(resolve => setTimeout(() => resolve(true), 40));
  await assert.rejects((async () => { await withTimeout(request, 10, 'permission timeout'); continued = true; })(), /permission timeout/);
  await new Promise(resolve => setTimeout(resolve, 60));
  assert.equal(continued, false);
});

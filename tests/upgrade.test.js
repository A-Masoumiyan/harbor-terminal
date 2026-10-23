import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {upgradeSource,restoreSource} from '../extension/upgrade.js';
const template = readFileSync(new URL('../extension/terminal.template.php', import.meta.url), 'utf8');
test('host upgrade preserves identity, verifier, salt and fixed IP', () => {
  const id='1234567890abcdef', salt='a'.repeat(32), hash='b'.repeat(64);
  const old=template.replace('__INSTANCE_ID__',id).replace('__AUTH_SALT__',salt).replace('__AUTH_VERIFIER__',hash).replace("const ALLOWED_IP = '';", "const ALLOWED_IP = '192.0.2.10';");
  const result=upgradeSource(template,old,id);
  assert.ok(result.includes(`const INSTANCE_ID = '${id}';`));
  assert.ok(result.includes(`const AUTH_VERIFIER = '${hash}';`));
  assert.ok(result.includes(`const AUTH_SALT = '${salt}';`));
  assert.ok(result.includes("const ALLOWED_IP = '192.0.2.10';"));
  assert.ok(!result.includes('__AUTH_'));
  assert.throws(()=>upgradeSource(template,old,'0000000000000000'),/شناسه/);
  assert.throws(()=>upgradeSource(template,old.replace(hash,'bad'),id),/قالب/);
  assert.throws(()=>upgradeSource(template,old.replace('192.0.2.10',"bad'; malicious(); //"),id),/قالب/);
});
test('rollback keeps current password verifier and refuses another terminal backup',()=>{
  const id='1234567890abcdef';
  const old=template.replace('__INSTANCE_ID__',id).replace('__AUTH_SALT__','a'.repeat(32)).replace('__AUTH_VERIFIER__','b'.repeat(64)).replace(/Harbor Terminal \d+\.\d+\.\d+/,'Harbor Terminal 1.0.2');
  const current=old.replace('b'.repeat(64),'c'.repeat(64));
  const result=restoreSource(old,current,id);
  assert.ok(result.includes('Harbor Terminal 1.0.2'));
  assert.ok(result.includes(`const AUTH_VERIFIER = '${'c'.repeat(64)}';`));
  assert.throws(()=>restoreSource(old,current,'0000000000000000'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../extension/terminal.template.php',import.meta.url),'utf8');
const script=source.match(/<script nonce="[^\n]+">([\s\S]*?)<\/script>/)[1];
const model=script.split('/* HARBOR_MODEL_BEGIN */')[1].split('/* HARBOR_MODEL_END */')[0];
const context=vm.createContext({});vm.runInContext(model,context);
const event=(key,more={})=>({key,altKey:false,shiftKey:false,ctrlKey:false,metaKey:false,isComposing:false,...more});
test('Shift+Enter executes and plain arrows browse history at line boundaries',()=>{
  assert.equal(context.keyboardAction(event('Enter',{shiftKey:true}),'pwd',3,3,-1),'run');
  assert.equal(context.keyboardAction(event('Enter'),'pwd',3,3,-1),null);
  assert.equal(context.keyboardAction(event('ArrowUp'),'draft',5,5,-1),'previous');
  assert.equal(context.keyboardAction(event('ArrowDown'),'draft',5,5,-1),'next');
  assert.equal(context.keyboardAction(event('ArrowUp'),'one\ntwo',6,6,-1),null);
  assert.equal(context.keyboardAction(event('ArrowDown'),'one\ntwo',1,1,-1),null);
  assert.equal(context.keyboardAction(event('ArrowUp',{isComposing:true}),'pwd',3,3,-1),null);
});
test('history navigation preserves an unfinished command and does not wrap',()=>{
  const entries=[{command:'newest'},{command:'older'}];
  let state=context.moveHistory(-1,'previous',entries,'unfinished','');
  assert.equal(state.text,'newest');assert.equal(state.draft,'unfinished');
  state=context.moveHistory(state.index,'previous',entries,state.text,state.draft);assert.equal(state.text,'older');
  state=context.moveHistory(state.index,'previous',entries,state.text,state.draft);assert.equal(state.text,'older');
  state=context.moveHistory(state.index,'next',entries,state.text,state.draft);assert.equal(state.text,'newest');
  state=context.moveHistory(state.index,'next',entries,state.text,state.draft);assert.equal(state.text,'unfinished');assert.equal(state.index,-1);
  assert.equal(context.moveHistory(-1,'next',entries,'draft','').text,'draft');
});
test('path completion quotes spaces and single quotes without shell interpolation',()=>{
  assert.equal(context.shellQuote('hello world.txt'),"'hello world.txt'");
  assert.equal(context.shellQuote("a'b.txt"),"'a'\\''b.txt'");
  assert.equal(context.shellQuote('$(id)'),"'$(id)'");
});
test('every literal terminal control used by JavaScript exists in the view',()=>{
  const controls=[...script.matchAll(/\$\('([^']+)'\)/g)].map(m=>m[1]);
  const ids=new Set([...source.matchAll(/\bid="([a-zA-Z0-9_-]+)"/g)].map(m=>m[1]));
  assert.deepEqual([...new Set(controls)].filter(id=>!ids.has(id)),[]);
  assert.ok(source.includes('connect-src \'self\''));
});

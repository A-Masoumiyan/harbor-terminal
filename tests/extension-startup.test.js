import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const base=new URL('../',import.meta.url);
function fakeStorage(){const values={};return {get:async keys=>typeof keys==='string'?{[keys]:values[keys]}:Object.fromEntries(keys.map(key=>[key,values[key]])),set:async data=>Object.assign(values,data),remove:async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete values[key];}};}
class Element {constructor(id=''){this.id=id;this.value='';this.hidden=false;this.disabled=false;this.handlers={};this.children=[];this.files=[];this.style={};this.classList={toggle(){}};}addEventListener(name,callback){this.handlers[name]=callback;}replaceChildren(...children){this.children=children;}append(child){this.children.push(child);}querySelector(){return new Element();}removeAttribute(){} }
test('actual options module starts without missing elements or browser API errors',async()=>{
  const html=readFileSync(new URL('extension/options.html',base),'utf8');const elements=new Map([...html.matchAll(/\bid="([\w-]+)"/g)].map(m=>[m[1],new Element(m[1])]));
  const previous={document:globalThis.document,browser:globalThis.browser,Option:globalThis.Option};
  try{
    globalThis.document={getElementById:id=>{assert.ok(elements.has(id),'Missing options control '+id);return elements.get(id);}};
    globalThis.Option=class{constructor(text,value){this.text=text;this.value=value;}};
    globalThis.browser={storage:{local:fakeStorage(),session:fakeStorage()},runtime:{getManifest:()=>({version:'1.1.0'}),getURL:path=>'chrome-extension://test/'+path}};
    await import(new URL('extension/options.js?startup=1',base));
    assert.equal(elements.get('version').textContent,'1.1.0');assert.equal(elements.get('connections').children[0].text,'هنوز اتصالی ثبت نشده است');
    assert.ok(elements.get('connect-existing').handlers.click);assert.ok(elements.get('manual-generate').handlers.click);
  }finally{Object.assign(globalThis,previous);}
});
test('popup starts on login and keeps settings, cPanel setup and updates accessible',async()=>{
  const html=readFileSync(new URL('extension/popup.html',base),'utf8');
  const elements=new Map([...html.matchAll(/\bid="([\w-]+)"/g)].map(m=>[m[1],new Element(m[1])]));
  const previous={document:globalThis.document,browser:globalThis.browser,Option:globalThis.Option,window:globalThis.window};
  let opened=0,closed=0;const session=fakeStorage();
  const url='https://panel.example:2083/cpsess123/frontend/jupiter/filemanager/upload-ajax.html?dir=%2Fhome%2Fu%2Fpublic_html';
  try{
    globalThis.document={getElementById:id=>{assert.ok(elements.has(id),'Missing popup control '+id);return elements.get(id);}};
    globalThis.Option=class{constructor(text,value){this.text=text;this.value=value;}};
    globalThis.window={close:()=>closed++};
    globalThis.browser={storage:{local:fakeStorage(),session},runtime:{getManifest:()=>({version:'1.2.0'}),getURL:p=>'chrome-extension://test/'+p,openOptionsPage:async()=>opened++},tabs:{query:async()=>[{url}]},permissions:{request:async()=>false}};
    await import(new URL('extension/popup.js?startup=1',base));
    assert.equal(elements.get('setup').hidden,false);assert.equal(elements.get('terminal').disabled,true);
    await elements.get('settings').handlers.click();assert.equal(opened,1);assert.equal(closed,1);
    await elements.get('setup').handlers.click();assert.equal(opened,2);assert.equal((await session.get('setupTabURL')).setupTabURL,url);
    await elements.get('check-update').handlers.click();assert.equal(elements.get('check-update').disabled,false);assert.match(elements.get('status').textContent,/اجازه/);assert.equal(elements.get('download').hidden,true);
  }finally{Object.assign(globalThis,previous);}
});

test('return bridge opens settings only from saved terminal top frames',async()=>{
  const previous=globalThis.browser;let message,updated,opened=0,injected=0;
  const local=fakeStorage(),id='1234567890abcdef',url=`https://host.test/harbor-terminal-${id}.php`;
  await local.set({profile:{id,url}});
  try{
    globalThis.browser={storage:{local},runtime:{id:'test',openOptionsPage:async()=>opened++,onInstalled:{addListener(){}},onMessage:{addListener:fn=>message=fn}},contextMenus:{onClicked:{addListener(){}}},tabs:{onUpdated:{addListener:fn=>updated=fn}},scripting:{executeScript:async()=>injected++}};
    const {isSavedTerminal}=await import(new URL('extension/background.js?startup=2',base));
    assert.equal(isSavedTerminal(url+'?api=info',{profile:{id,url}}),true);
    assert.equal(isSavedTerminal('https://other.test/'+url.split('/').pop(),{profile:{id,url}}),false);
    await updated(1,{status:'complete'},{url:'https://other.test/'});assert.equal(injected,0);
    await updated(1,{status:'complete'},{url});assert.equal(injected,1);
    const send=sender=>new Promise(resolve=>{const result=message({type:'harbor-open-settings'},sender,resolve);if(!result)resolve(null);});
    await send({id:'test',frameId:0,tab:{id:1},url:'https://other.test/'});assert.equal(opened,0);
    await send({id:'test',frameId:1,tab:{id:1},url});assert.equal(opened,0);
    await send({id:'test',frameId:0,tab:{id:1},url});assert.equal(opened,1);
  }finally{globalThis.browser=previous;}
});

test('GitHub source root is directly loadable in Edge',()=>{
  const manifest=JSON.parse(readFileSync(new URL('manifest.json',base),'utf8'));assert.equal(manifest.manifest_version,3);
  for(const path of [manifest.background.service_worker,manifest.options_ui.page,manifest.action.default_popup])assert.ok(existsSync(fileURLToPath(new URL(path,base))));
  assert.equal(manifest.version,JSON.parse(readFileSync(new URL('package.json',base),'utf8')).version);
});

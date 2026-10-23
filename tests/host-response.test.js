import test from 'node:test';
import assert from 'node:assert/strict';
import {hostJSON,probeHost} from '../extension/host-response.js';
const profile={id:'1234567890abcdef',url:'https://example.test/harbor-terminal-1234567890abcdef.php'};
const html=(code,text)=>new Response(text,{status:code,headers:{'content-type':'text/html'}});
test('hosting errors expose the HTTP cause without leaking server response contents',async()=>{
  for(const [code,body,match] of [[404,'missing',/404.*پیدا نشد/],[500,'private filesystem path',/500.*Errors/],[403,'Harbor Terminal requires HTTPS.',/HTTPS/],[403,'blocked',/مسدود/],[200,'<html>Website</html>',/HTML/],[503,'Credential configuration unavailable.',/اطلاعات ورود/],[200,'<?php secret',/PHP را اجرا نمی‌کند/]]){
    await assert.rejects(hostJSON(html(code,body)),error=>match.test(error.message)&&!error.message.includes('private filesystem path'));
  }
  await assert.rejects(hostJSON(html(500,'failure'),'rotate'),/وضعیت تغییر رمز نامشخص/);
  await assert.rejects(hostJSON(new Response('warning: {}',{headers:{'content-type':'application/json'}})),/JSON خراب/);
});
test('identity probe sends no cookies or passwords, and rejects unrelated JSON',async()=>{
  const data={product:'harbor-terminal',id:profile.id,version:'1.2.1'};
  assert.deepEqual(await probeHost(profile,async(url,options)=>{assert.equal(new URL(url).searchParams.get('api'),'info');assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.equal(options.body,undefined);return Response.json(data);}),data);
  await assert.rejects(probeHost(profile,async()=>Response.json({...data,id:'other'})),/هویت/);
  await assert.rejects(probeHost(profile,async()=>{throw new TypeError('Network');}),/ارتباط/);
});

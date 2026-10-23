import {loadConnections,selectConnection} from './connections.js';
import {permissionPattern} from './core.js';
import {checkRelease} from './updates.js';
import {withTimeout} from './transport.js';
const api=globalThis.browser??globalThis.chrome,$=id=>document.getElementById(id);
let profile=null,setupURL=null;
async function settings(section=''){
  if(section)await api.tabs.create({url:new URL(`options.html#${section}`,import.meta.url).href});
  else await api.runtime.openOptionsPage();
  window.close();
}
async function load(){
  const state=await loadConnections(api);profile=state.profile;
  $('connections').replaceChildren(...state.connections.map(p=>new Option(p.name,p.id)));
  if(profile)$('connections').value=profile.id;
  else $('connections').append(new Option('ابتدا یک اتصال اضافه کن',''));
  $('connections').disabled=!profile;$('terminal').disabled=!profile;
  $('address').textContent=profile?.url??'هنوز هاستی متصل نشده است.';
}
function showRelease(details){
  $('update-status').textContent=details.newer?`نسخهٔ ${details.version} آماده است.`:`نسخهٔ جدیدتری موجود نیست. آخرین بررسی: ${new Date(details.checkedAt).toLocaleTimeString('fa')}`;
  $('download').hidden=!(details.newer&&details.download);
  $('update-guide').hidden=!(details.newer&&details.download);
  if(details.download)$('download').href=details.download;
  if(details.newer&&!details.download)$('update-status').textContent+=' بستهٔ مرورگر هنوز آماده نشده است.';
}
async function task(work){try{$('status').textContent='';await work();}catch(error){$('status').textContent=error.message||'عملیات انجام نشد.';}}
$('settings').addEventListener('click',()=>task(()=>settings()));
$('update-help').addEventListener('click',()=>task(()=>settings('updates')));
$('terminal').addEventListener('click',()=>task(async()=>{if(profile){await api.tabs.create({url:profile.url});window.close();}}));
$('connections').addEventListener('change',()=>task(async()=>{await selectConnection(api,$('connections').value);await load();}));
$('setup').addEventListener('click',()=>task(async()=>{await api.storage.session.set({setupTabURL:setupURL});await settings();}));
$('check-update').addEventListener('click',()=>task(async()=>{
  $('check-update').disabled=true;$('download').hidden=true;$('update-guide').hidden=true;
  try{
    // Request immediately from this click so Firefox keeps the user gesture.
    const granted=await withTimeout(api.permissions.request({origins:[permissionPattern('https://api.github.com')]}),30000,'درخواست اجازهٔ مرورگر بی‌پاسخ ماند. دوباره تلاش کنید.');
    if(!granted)throw new Error('اجازهٔ بررسی گیت‌هاب داده نشد.');
    $('update-status').textContent='در حال بررسی…';showRelease(await checkRelease(api));
  }catch(error){$('update-status').textContent='بررسی کامل نشد.';throw error;}
  finally{$('check-update').disabled=false;}
}));
$('version').textContent=api.runtime.getManifest().version;
await task(async()=>{
  await load();
  const [tab]=await api.tabs.query({active:true,currentWindow:true});
  if(tab?.url&&/^https:\/\/[^/]+\/cpsess\d+\/frontend\/[^/]+\/filemanager\//.test(tab.url)){setupURL=tab.url;$('setup').hidden=false;}
});

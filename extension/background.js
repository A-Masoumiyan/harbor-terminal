import {normalizeConnections} from './connections.js';
const api = globalThis.browser ?? globalThis.chrome;
api.runtime.onInstalled.addListener(async ({reason}) => {
  try { await api.contextMenus.removeAll();
    api.contextMenus.create({id: 'harbor-settings', title: 'Harbor Terminal — تنظیمات و اتصال‌ها', contexts: ['action']});
  } catch { /* Context menu failure must not prevent opening setup. */ }
  if (reason === 'install') await api.runtime.openOptionsPage();
});
api.contextMenus.onClicked.addListener(info => {
  if (info.menuItemId === 'harbor-settings') api.runtime.openOptionsPage();
});

// Only saved terminal documents receive this navigation button. No passwords,
// command execution or page content cross this bridge.
export function isSavedTerminal(url, state) {
  try { const candidate=new URL(url);candidate.search='';candidate.hash='';
    return normalizeConnections(state).connections.some(p=>p.url===candidate.href);
  } catch { return false; }
}
function addReturnButton() {
  if(document.contentType!=='text/html'||document.getElementById('harbor-extension-return'))return;
  const button=document.createElement('button');button.id='harbor-extension-return';
  button.type='button';button.textContent='پنل و تنظیمات افزونه ↗';
  button.style.cssText='position:fixed;bottom:18px;left:18px;z-index:2147483647;background:#b5ed89;color:#142415;border:1px solid #82b95c;border-radius:10px;padding:10px 14px;font:12px Tahoma,sans-serif;cursor:pointer;box-shadow:0 4px 20px #0005;direction:rtl';
  button.addEventListener('click',()=>{(globalThis.browser??globalThis.chrome).runtime.sendMessage({type:'harbor-open-settings'}).catch(()=>{button.textContent='روی آیکون افزونه بزن و تنظیمات را انتخاب کن';});});
  document.body.append(button);
}
api.tabs.onUpdated.addListener(async(tabId,change,tab)=>{
  if(change.status!=='complete'||!tab.url)return;
  try {
    const state=await api.storage.local.get(['connections','activeId','profile']);
    if(!isSavedTerminal(tab.url,state))return;
    await api.scripting.executeScript({target:{tabId},func:addReturnButton});
  } catch { /* Without site permission, the toolbar popup still opens settings. */ }
});
api.runtime.onMessage.addListener((message,sender,reply)=>{
  if(message?.type!=='harbor-open-settings'||sender.id!==api.runtime.id||sender.frameId!==0||!sender.tab)return;
  (async()=>{
    const state=await api.storage.local.get(['connections','activeId','profile']);
    if(!isSavedTerminal(sender.url,state)){reply({ok:false});return;}
    await api.runtime.openOptionsPage();reply({ok:true});
  })().catch(()=>reply({ok:false}));return true;
});

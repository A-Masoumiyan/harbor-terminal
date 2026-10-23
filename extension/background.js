import {loadConnections} from './connections.js';
const api = globalThis.browser ?? globalThis.chrome;
api.action.onClicked.addListener(async tab => {
  try {
    if (tab?.url && /^https:\/\/[^/]+\/cpsess\d+\/frontend\/[^/]+\/filemanager\//.test(tab.url)) {
      await api.storage.session.set({setupTabURL:tab.url});
      await api.runtime.openOptionsPage(); return;
    }
    const {profile}=await loadConnections(api);
    if(profile)await api.tabs.create({url:profile.url});else await api.runtime.openOptionsPage();
  } catch {
    // The toolbar must remain usable even if an old saved connection is corrupt.
    await api.runtime.openOptionsPage();
  }
});
api.runtime.onInstalled.addListener(async ({reason}) => {
  try { await api.contextMenus.removeAll();
    api.contextMenus.create({id: 'harbor-settings', title: 'Harbor Terminal — تنظیمات و اتصال‌ها', contexts: ['action']});
  } catch { /* Context menu failure must not prevent opening setup. */ }
  if (reason === 'install') await api.runtime.openOptionsPage();
});
api.contextMenus.onClicked.addListener(info => {
  if (info.menuItemId === 'harbor-settings') api.runtime.openOptionsPage();
});

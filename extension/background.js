const api = globalThis.browser ?? globalThis.chrome;
api.action.onClicked.addListener(async () => {
  const {profile} = await api.storage.local.get('profile');
  if (profile?.url && /^https:\/\//.test(profile.url)) await api.tabs.create({url: profile.url});
  else await api.runtime.openOptionsPage();
});
api.runtime.onInstalled.addListener(async ({reason}) => {
  await api.contextMenus.removeAll();
  api.contextMenus.create({id: 'harbor-settings', title: 'Harbor Terminal — تنظیمات', contexts: ['action']});
  if (reason === 'install') await api.runtime.openOptionsPage();
});
api.contextMenus.onClicked.addListener(info => {
  if (info.menuItemId === 'harbor-settings') api.runtime.openOptionsPage();
});

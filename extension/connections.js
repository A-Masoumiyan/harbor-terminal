import {httpsURL} from './core.js';
export function normalizeConnections(state = {}) {
  const candidates = Array.isArray(state.connections) ? [...state.connections] : [];
  if (state.profile && !candidates.some(p => p.id === state.profile.id)) candidates.push(state.profile);
  const map = new Map();
  for (const item of candidates) {
    try {
      if (!/^[a-f0-9]{16}$/.test(item.id)) continue;
      const url = httpsURL(item.url); url.hash=''; url.search='';
      if (!url.pathname.endsWith(`/harbor-terminal-${item.id}.php`)) continue;
      map.set(item.id, {...item, url:url.href, filename:`harbor-terminal-${item.id}.php`, name:String(item.name || url.hostname).slice(0,80),
        color:/^#[a-f0-9]{6}$/i.test(item.color)?item.color:'#b5ed89'});
    } catch { /* Skip malformed entries without breaking startup. */ }
  }
  const connections=[...map.values()];
  const activeId=connections.some(p=>p.id===state.activeId)?state.activeId:(connections.find(p=>p.id===state.profile?.id)?.id ?? connections[0]?.id ?? null);
  return {connections,activeId,profile:connections.find(p=>p.id===activeId) ?? null};
}
export async function loadConnections(api) {
  const state=normalizeConnections(await api.storage.local.get(['connections','activeId','profile']));
  await api.storage.local.set(state); // Keep legacy profile as a compatibility alias.
  return state;
}
export async function saveConnection(api, profile) {
  const state=await loadConnections(api);
  state.connections=state.connections.filter(p=>p.id!==profile.id); state.connections.push(profile);
  const next=normalizeConnections({...state,activeId:profile.id,profile});
  if (!next.profile || next.profile.id!==profile.id) throw new Error('نشانی اتصال معتبر نیست.');
  await api.storage.local.set(next); return next;
}
export async function selectConnection(api,id) {
  const state=await loadConnections(api);
  const profile=state.connections.find(p=>p.id===id); if(!profile)throw new Error('اتصال پیدا نشد.');
  await api.storage.local.set({...state,activeId:id,profile}); return profile;
}
export async function removeConnection(api,id) {
  const state=await loadConnections(api);
  const remaining=state.connections.filter(p=>p.id!==id);
  const next=normalizeConnections({connections:remaining,activeId:remaining[0]?.id});
  await api.storage.local.set(next); return next;
}

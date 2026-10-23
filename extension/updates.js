import {REPOSITORY, newerVersion, httpsURL} from './core.js';
export function releaseDetails(release, localVersion, browserName) {
  const version=String(release.tag_name).replace(/^v/,'');
  if(!/^\d+\.\d+\.\d+$/.test(version))throw new Error('شمارهٔ نسخهٔ منتشرشده معتبر نیست.');
  const asset=release.assets?.find(file=>file.name===`harbor-terminal-${browserName}-${version}.zip`);
  let download=null;
  if(asset){
    const url=httpsURL(asset.browser_download_url);
    if(url.origin==='https://github.com' && url.pathname===`/${REPOSITORY}/releases/download/v${version}/${asset.name}` && !url.search && !url.hash)download=url.href;
  }
  return {version,newer:newerVersion(version,localVersion),download,checkedAt:Date.now()};
}
export async function checkRelease(api) {
  const response=await fetch(`https://api.github.com/repos/${REPOSITORY}/releases/latest`,{
    headers:{Accept:'application/vnd.github+json'},credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error(response.status===404?'هنوز نسخه‌ای منتشر نشده است.':'بررسی انجام نشد؛ کمی بعد دوباره تلاش کنید.');
  const browserName=api.runtime.getURL('').startsWith('moz-extension:')?'firefox':'chrome-edge';
  const details=releaseDetails(await response.json(),api.runtime.getManifest().version,browserName);
  await api.storage.local.set({lastRelease:details});
  return details;
}

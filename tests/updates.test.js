import test from 'node:test';
import assert from 'node:assert/strict';
import {releaseDetails} from '../extension/updates.js';
const name='harbor-terminal-chrome-edge-1.2.0.zip';
const url=`https://github.com/A-Masoumiyan/harbor-terminal/releases/download/v1.2.0/${name}`;
test('update download must be the exact browser asset in the official version release',()=>{
  const release=link=>({tag_name:'v1.2.0',assets:[{name,browser_download_url:link}]});
  assert.equal(releaseDetails(release(url),'1.1.0','chrome-edge').download,url);
  assert.equal(releaseDetails(release(url),'1.2.0','chrome-edge').newer,false);
  for(const link of [url.replace('github.com','example.com'),url+'?redirect=1',url.replace('v1.2.0/','v1.1.0/')])assert.equal(releaseDetails(release(link),'1.1.0','chrome-edge').download,null);
  assert.equal(releaseDetails(release(url),'1.1.0','firefox').download,null);
  assert.throws(()=>releaseDetails({tag_name:'untrusted',assets:[]},'1.1.0','chrome-edge'));
});

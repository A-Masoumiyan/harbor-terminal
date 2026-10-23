import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeConnections,loadConnections,saveConnection,selectConnection,removeConnection} from '../extension/connections.js';
const first={id:'1234567890abcdef',url:'https://first.example/harbor-terminal-1234567890abcdef.php',directory:'/home/u/public_html',verified:true};
const second={id:'abcdef1234567890',url:'https://second.example/harbor-terminal-abcdef1234567890.php'};
function storage(initial){let values=structuredClone(initial);return {local:{get:async keys=>typeof keys==='string'?{[keys]:values[keys]}:Object.fromEntries(keys.map(key=>[key,values[key]])),set:async data=>Object.assign(values,structuredClone(data)),remove:async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete values[key];}},snapshot:()=>values};}
test('legacy connection migrates without losing its server directory',async()=>{
  const api={storage:storage({profile:first})};const result=await loadConnections(api);assert.equal(result.connections.length,1);assert.equal(result.profile.directory,first.directory);assert.equal(result.activeId,first.id);
});
test('multiple hosts retain one active profile and deletion never resurrects it',async()=>{
  const api={storage:storage({profile:first})};await saveConnection(api,second);assert.equal((await loadConnections(api)).profile.id,second.id);await selectConnection(api,first.id);assert.equal((await loadConnections(api)).connections.length,2);await removeConnection(api,first.id);let state=await loadConnections(api);assert.equal(state.profile.id,second.id);assert.equal(state.connections.length,1);await removeConnection(api,second.id);state=await loadConnections(api);assert.equal(state.profile,null);assert.deepEqual(state.connections,[]);
});
test('malformed saved URLs cannot break startup or open another protocol',()=>{
  assert.equal(normalizeConnections({profile:{...first,url:'javascript:alert(1)'}}).profile,null);
  assert.equal(normalizeConnections({profile:{...first,url:'https://first.example/other.php'}}).profile,null);
});

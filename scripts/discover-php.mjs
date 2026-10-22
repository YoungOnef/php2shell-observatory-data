import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {detectPhp} from './php-scope.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const args=process.argv.slice(2);const arg=(k,d)=>{const i=args.indexOf(k);return i<0?d:args[i+1]};
const token=process.env.GITHUB_TOKEN||(args.includes('--use-gh')?execFileSync('gh',['auth','token'],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim():null);
const budget=Number(arg('--budget',token?'1200':'24'));let used=0;let limited=false;
const data=JSON.parse(await readFile(path.join(root,'dist/data/projects.json'),'utf8'));
const cacheDir=path.join(root,'.cache');await mkdir(cacheDir,{recursive:true});let cache={};try{cache=JSON.parse(await readFile(path.join(cacheDir,'scope.json'),'utf8'))}catch{}
const ttl=Number(arg('--ttl-days','7'))*86400000;const now=Date.now();const queue=data.projects.filter(p=>p.repo).sort((a,b)=>(b.stars||0)-(a.stars||0));let index=0,done=0;
async function worker(){while(index<queue.length){const p=queue[index++];if(cache[p.repo]?.checkedAt&&now-new Date(cache[p.repo].checkedAt).getTime()<ttl){done++;continue;}if(used>=budget||limited)continue;used++;
  const result={checkedAt:new Date().toISOString(),signals:[],images:[],coverage:'recursive GitHub file tree',errors:[]};
  try{const headers={Accept:'application/vnd.github+json','User-Agent':'php2shell-observatory'};if(token)headers.Authorization=`Bearer ${token}`;const r=await fetch(`https://api.github.com/repos/${p.repo}/git/trees/HEAD?recursive=1`,{headers,signal:AbortSignal.timeout(25000)});if(r.status===403||r.status===429){limited=true;throw new Error('GitHub API rate limit; will retry automatically.');}if(!r.ok)throw new Error(`GitHub tree HTTP ${r.status}`);const tree=await r.json();result.tree=tree.sha;result.truncated=!!tree.truncated;
    const files=(tree.tree||[]).filter(f=>f.type==='blob');
    const php=files.filter(f=>/\.php$/i.test(f.path));
    if(php.length){const f=php.sort((a,b)=>Number(/(^|\/)(tests?|docs?|examples?|fixtures?)\//i.test(a.path))-Number(/(^|\/)(tests?|docs?|examples?|fixtures?)\//i.test(b.path)))[0];result.signals.push({source:`https://github.com/${p.repo}/blob/HEAD/${f.path}`,file:f.path,reason:`Repository contains ${php.length} PHP source file(s), including ${f.path}.`,kind:/(^|\/)(tests?|docs?|examples?|fixtures?)\//i.test(f.path)?'development':'component',verified:true,checkedAt:result.checkedAt});}
    const candidates=files.filter(f=>/(^|\/)(composer\.json|Dockerfile(?:\.[^/]*)?|(?:docker-)?compose[^/]*\.ya?ml)$/.test(f.path)&&!/(^|\/)(vendor|node_modules)\//.test(f.path)).sort((a,b)=>a.path.split('/').length-b.path.split('/').length).slice(0,12);
    for(const f of candidates){try{const url=`https://raw.githubusercontent.com/${p.repo}/HEAD/${f.path}`;const response=await fetch(url,{signal:AbortSignal.timeout(9000)});if(!response.ok)continue;const body=await response.text();const signals=detectPhp(f.path,body).map(s=>({...s,source:url,verified:true,checkedAt:result.checkedAt}));result.signals.push(...signals);for(const s of signals)if(s.image&&!s.baseImage&&!s.image.includes('$'))result.images.push({image:s.image,source:url,publisher:'Repository Compose service',discovered:true});}catch(e){result.errors.push(`${f.path}: ${e.message}`);}}
    cache[p.repo]=result;
  }catch(e){result.errors.push(e.message);cache[p.repo]={...cache[p.repo],lastAttempt:result.checkedAt,errors:result.errors};}
  done++;if(done%50===0){await writeFile(path.join(cacheDir,'scope.json'),JSON.stringify(cache));console.log(`Scope checked ${done}/${queue.length}; ${used} tree requests.`);}
}}
await Promise.all(Array.from({length:5},()=>worker()));await writeFile(path.join(cacheDir,'scope.json'),JSON.stringify(cache));
console.log(JSON.stringify({repositories:queue.length,requests:used,checked:Object.values(cache).filter(x=>x.checkedAt).length,withPhp:Object.values(cache).filter(x=>x.signals?.length).length,rateLimited:limited}));

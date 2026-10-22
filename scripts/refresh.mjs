import {readFile,writeFile,readdir,mkdir,copyFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import YAML from 'yaml';
import {repoFromUrl,cleanText,releaseCandidate,applyEvidence} from './core.mjs';
import {applyPhpSignals} from './php-scope.mjs';
import {applyVerification,verificationCounts} from '../dist/auto-results.js';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const args=process.argv.slice(2);const arg=(k,d)=>{const i=args.indexOf(k);return i<0?d:args[i+1]};
const offline=args.includes('--offline');const budget=Number(arg('--budget',process.env.GITHUB_TOKEN?'250':'24'));
if(!Number.isInteger(budget)||budget<0)throw new Error('--budget must be a nonnegative integer');
const cache=path.join(root,'.cache');await mkdir(cache,{recursive:true});
function git(...a){return execFileSync('git',a,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();}
async function checkout(dir,url,provided){if(provided)return path.resolve(provided);const target=path.join(cache,dir);try{await readdir(target);if(!offline)git('-C',target,'pull','--ff-only');}catch(e){if(offline)throw e;git('clone','--depth','1',url,target);}return target;}
const catalogue=await checkout('catalog','https://github.com/awesome-selfhosted/awesome-selfhosted-data.git',arg('--catalog'));
const ncsc=await checkout('ncsc','https://github.com/NCSC-NL/php2shell.git',arg('--ncsc'));
const advisory=JSON.parse(await readFile(path.join(root,'config/advisory.json'),'utf8'));
const images=JSON.parse(await readFile(path.join(root,'config/images.json'),'utf8'));
const manual=JSON.parse(await readFile(path.join(root,'config/evidence.json'),'utf8')).entries;
const scope=JSON.parse(await readFile(path.join(root,'config/scope.json'),'utf8'));
const generatedAt=new Date().toISOString();const warnings=[];let projects=[];
let previousImages={},previousScopes={};try{const previous=JSON.parse(await readFile(path.join(root,'dist/data/projects.json'),'utf8'));for(const p of previous.projects){previousScopes[p.repo]={signals:p.phpSignals||[],...p.scopeCheck};for(const i of p.images)previousImages[i.image]=i;}}catch{}
const catalogueSha=git('-C',catalogue,'rev-parse','HEAD');
for(const file of await readdir(path.join(catalogue,'software'))){
  if(!/\.ya?ml$/.test(file))continue;
  const y=YAML.parse(await readFile(path.join(catalogue,'software',file),'utf8'));
  const repo=repoFromUrl(y.source_code_url);const php=(y.platforms||[]).some(v=>/^php$/i.test(v));
  const source=`https://github.com/awesome-selfhosted/awesome-selfhosted-data/blob/${catalogueSha}/software/${file}`;
  projects.push({id:file.replace(/\.ya?ml$/,''),name:y.name,repo,url:y.source_code_url,website:y.website_url,description:cleanText(y.description),category:y.tags?.[0]||'Other',platforms:y.platforms||[],php,phpEvidence:php?{source,reason:'PHP is explicitly declared in the catalogue platform metadata.'}:null,stars:Number.isFinite(y.stargazers_count)?y.stargazers_count:null,starsCheckedAt:y.updated_at||null,starsSource:'Awesome Selfhosted GitHub metadata',archived:!!y.archived,release:y.current_release?{tag:y.current_release.tag,publishedAt:y.current_release.published_at,url:repo?`https://github.com/${repo}/releases`:y.source_code_url,source:'catalogue'}:null,status:php?'pending':'excluded',images:[],evidence:[],checks:{}});
}
let discovered={};try{discovered=JSON.parse(await readFile(path.join(cache,'scope.json'),'utf8'))}catch{}
for(const p of projects){
  const exclusion=scope.exclusions.find(e=>e.repo.toLowerCase()===p.repo?.toLowerCase());
  const signals=p.php&&!exclusion?[{...p.phpEvidence,kind:'declared'}]:[];
  if(exclusion)p.scopeExclusion=exclusion;
  const discovery=discovered[p.repo]?.checkedAt?discovered[p.repo]:previousScopes[p.repo];if(discovery){signals.push(...(discovery.signals||[]));p.scopeCheck={checkedAt:discovery.checkedAt,coverage:discovery.coverage,truncated:discovery.truncated,errors:discovery.errors};}
  applyPhpSignals(p,signals);
}
// Check actual runtime requirements or a PHP web entrypoint. Catalogue claims remain labelled when not independently verified.
let phpCache={};try{phpCache=JSON.parse(await readFile(path.join(cache,'php.json'),'utf8'))}catch{}
const phpTargets=projects.filter(p=>p.php&&p.repo);let phpIndex=0;
async function checkPhp(){while(phpIndex<phpTargets.length){const p=phpTargets[phpIndex++];if(offline){if(phpCache[p.repo])p.phpEvidence=phpCache[p.repo];continue;}
  for(const file of ['composer.json','index.php']){try{const url=`https://raw.githubusercontent.com/${p.repo}/HEAD/${file}`;const r=await fetch(url,{signal:AbortSignal.timeout(9000)});if(!r.ok)continue;const body=await r.text();let reason='';if(file==='composer.json'){const c=JSON.parse(body);if(c.require?.php)reason=`Production Composer requirement: PHP ${c.require.php}`;}else if(body.includes('<?php'))reason='PHP web entrypoint present in the default branch.';if(reason){p.phpEvidence={source:url,reason,checkedAt:generatedAt,verified:true};phpCache[p.repo]=p.phpEvidence;break;}}catch{}}
}}
await Promise.all(Array.from({length:8},()=>checkPhp()));
await writeFile(path.join(cache,'php.json'),JSON.stringify(phpCache));
// Import only exact product-name matches: a vendor's other products must not inherit its status.
const ncscSha=git('-C',ncsc,'rev-parse','HEAD');const norm=s=>s.toLowerCase().replace(/[^a-z0-9]/g,'');
for(const f of await readdir(path.join(ncsc,'software'))){if(!/^software_list_.*\.md$/.test(f))continue;
  const content=await readFile(path.join(ncsc,'software',f),'utf8');
  for(const line of content.split('\n')){if(!line.startsWith('|')||line.startsWith('|:'))continue;
    const cells=line.split('|').slice(1,-1).map(x=>x.trim());if(cells.length!==7)continue;
    const p=projects.find(p=>norm(p.name)===norm(cells[1]));if(!p?.php)continue;
    const links=[...cells[6].matchAll(/\]\(<?(https:[^)>]+)>?\)/g)].map(m=>m[1]);
    const patched=cells[3]==='Fix'&&cells[4]==='Fix';
    p.status=patched?'patched':'pending';
    p.evidence.push({type:'ncsc',status:p.status,scope:'Product / runtime guidance; does not verify a Docker image digest',version:cells[2]||null,notes:cleanText(cells[5]),source:`https://github.com/NCSC-NL/php2shell/blob/${ncscSha}/software/${f}`,sources:links,checkedAt:generatedAt,cves:advisory.cves});
  }
}
for(const p of projects){const refs=[...(discovered[p.repo]?.images||[]).map(i=>({...i,role:'companion'})),...images.filter(i=>i.repo?.toLowerCase()===p.repo?.toLowerCase()||i.name===p.name).map(i=>({...i,role:'primary'}))];p.images=[...new Map(refs.map(i=>[i.image,{...previousImages[i.image],...i,status:'unverified',checkedAt:previousImages[i.image]?.checkedAt||null}])).values()];p.releaseStatus=p.status;applyEvidence(p,manual);}
let apiCache={};try{apiCache=JSON.parse(await readFile(path.join(cache,'github.json'),'utf8'))}catch{}
let requests=0,rateLimited=false;
async function gh(endpoint){
  const saved=apiCache[endpoint];const cached=()=>saved?.data?{...saved.data,_cached:true}:null;if(offline||requests>=budget||rateLimited)return cached();
  requests++;const headers={'Accept':'application/vnd.github+json','User-Agent':'php2shell-observatory','X-GitHub-Api-Version':'2022-11-28'};
  if(process.env.GITHUB_TOKEN)headers.Authorization=`Bearer ${process.env.GITHUB_TOKEN}`;if(saved?.etag)headers['If-None-Match']=saved.etag;
  try{const r=await fetch(`https://api.github.com${endpoint}`,{headers,signal:AbortSignal.timeout(18000)});if(r.status===304){saved.at=generatedAt;return saved.data;}
    if(r.status===403||r.status===429){rateLimited=true;warnings.push('GitHub rate limit reached. Cached or catalogue data retained; rerun with GITHUB_TOKEN.');return cached();}
    if(r.status===404){apiCache[endpoint]={data:null,status:404,at:generatedAt};return null;}if(!r.ok)throw new Error(`HTTP ${r.status}`);
    const data=await r.json();apiCache[endpoint]={etag:r.headers.get('etag'),data,at:generatedAt};return data;
  }catch(e){warnings.push(`${endpoint}: ${e.message}`);return cached();}
}
// Spend limited requests on PHP projects first, never on unrelated Python/Go applications.
const targets=projects.filter(p=>p.php&&p.repo).sort((a,b)=>{
  const at=apiCache[`/repos/${a.repo}/releases/latest`]?.at||'';const bt=apiCache[`/repos/${b.repo}/releases/latest`]?.at||'';
  return at.localeCompare(bt)||(b.stars||0)-(a.stars||0);
});
for(const p of targets){
  const metadata=await gh(`/repos/${p.repo}`);if(metadata){const checked=metadata._cached?apiCache[`/repos/${p.repo}`]?.at:generatedAt;p.stars=metadata.stargazers_count;p.starsCheckedAt=checked;p.starsSource=metadata._cached?'GitHub API (cached)':'GitHub API';p.archived=metadata.archived;p.checks.metadata=checked;}
  const r=await gh(`/repos/${p.repo}/releases/latest`);if(r?.tag_name){p.release={tag:r.tag_name,publishedAt:r.published_at,url:r.html_url,source:r._cached?'cached GitHub API':'GitHub API',candidate:releaseCandidate(r.body),excerpt:cleanText(r.body).slice(0,1200)};p.checks.release=r._cached?apiCache[`/repos/${p.repo}/releases/latest`]?.at:generatedAt;
    if(p.release.candidate&&p.status!=='patched')p.status='review';
  }
}
// Registry tag timestamps/digests are metadata, never proof of the PHP version inside.
if(!offline){for(const p of projects.filter(p=>p.php)){for(const image of p.images){
  if(image.image.includes('ghcr.io/')||image.image.includes('lscr.io/'))continue;
  const [ref,tag='latest']=image.image.split(':');const repository=ref.includes('/')?ref:`library/${ref}`;
  try{const r=await fetch(`https://hub.docker.com/v2/repositories/${repository}/tags/${tag}`,{signal:AbortSignal.timeout(10000)});if(!r.ok){image.error=`Registry returned HTTP ${r.status}`;continue;}const tagData=await r.json();image.checkedAt=generatedAt;image.updatedAt=tagData.last_updated;image.digest=tagData.digest||null;image.architectures=(tagData.images||[]).map(i=>({architecture:i.architecture,os:i.os,digest:i.digest}));}catch(e){image.error=e.message;}
}}}
let verified=null;try{verified=JSON.parse(await readFile(path.join(root,'dist/data/verified-images.json'),'utf8'))}catch{}
applyVerification({projects},verified);
projects.sort((a,b)=>(b.stars??-1)-(a.stars??-1)||a.name.localeCompare(b.name));let rank=0;for(const p of projects)p.rank=p.repo&&p.stars!==null?++rank:null;
const stats={catalogued:projects.length,githubRanked:rank,php:projects.filter(p=>p.php).length,patched:projects.filter(p=>p.php&&p.status==='patched').length,pending:projects.filter(p=>p.php&&p.status==='pending').length,review:projects.filter(p=>p.php&&p.status==='review').length,images:projects.filter(p=>p.php).reduce((n,p)=>n+p.images.length,0)};
stats.sourceTreesChecked=projects.filter(p=>p.repo&&p.scopeCheck?.checkedAt).length;
const imageStats=verificationCounts({projects});Object.assign(stats,{fixedImages:imageStats.fixed,affectedImages:imageStats.affected,scanErrors:imageStats.errors,scanningImages:imageStats.scanning,vendorFixes:projects.filter(p=>p.vendorStatus==='patched').length});
if(rank<1000)throw new Error(`Only ${rank} ranked GitHub projects; refusing to publish an incomplete 1,000-project catalogue.`);
const data={schemaVersion:1,generatedAt,advisory,stats,sources:{catalogue:{url:'https://github.com/awesome-selfhosted/awesome-selfhosted-data',commit:git('-C',catalogue,'rev-parse','HEAD'),license:'CC-BY-SA-3.0'},ncsc:{url:'https://github.com/NCSC-NL/php2shell',commit:ncscSha,license:'EUPL-1.2'}},refresh:{offline,githubRequests:requests,budget,warnings},projects};
await mkdir(path.join(root,'dist/data'),{recursive:true});await mkdir(path.join(root,'dist/licenses'),{recursive:true});
await writeFile(path.join(root,'dist/data/projects.json'),JSON.stringify(data,null,2));
await writeFile(path.join(root,'dist/data/projects.js'),`window.TRACKER_DATA=${JSON.stringify(data).replace(/</g,'\\u003c')};\n`);
await writeFile(path.join(root,'dist/data/verified-images.js'),`window.VERIFIED_IMAGES=${JSON.stringify(verified).replace(/</g,'\\u003c')};\n`);
await writeFile(path.join(cache,'github.json'),JSON.stringify(apiCache));
await copyFile(path.join(catalogue,'LICENSE'),path.join(root,'dist/licenses/awesome-selfhosted.txt'));await copyFile(path.join(ncsc,'LICENSE'),path.join(root,'dist/licenses/ncsc.txt'));
let history=[];try{history=JSON.parse(await readFile(path.join(root,'dist/data/history.json'),'utf8'))}catch{}
history.push({at:generatedAt,...stats});await writeFile(path.join(root,'dist/data/history.json'),JSON.stringify(history.slice(-365),null,2));
console.log(JSON.stringify({generatedAt,...stats,githubRequests:requests,warnings},null,2));

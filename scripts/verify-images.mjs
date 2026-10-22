import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {inspectRegistry} from './registry.mjs';
import {assessRuntime} from './runtime.mjs';
import {inspectWebRuntime} from './web-probe.mjs';
const run=promisify(execFile);const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const data=JSON.parse(await readFile(path.join(root,'dist/data/projects.json'),'utf8'));const advisory=JSON.parse(await readFile(path.join(root,'config/advisory.json'),'utf8'));
let previous={};try{previous=JSON.parse(await readFile(path.join(root,'dist/data/verified-images.json'),'utf8')).images||{}}catch{}
const args=process.argv.slice(2),limit=Number(args.includes('--limit')?args[args.indexOf('--limit')+1]:'60');
const probe=`set -u
for b in /usr/bin/real_php php php85 php84 php83 php82 php81 php80 php74 /usr/bin/php8.5 /usr/bin/php8.4 /usr/bin/php8.3 /usr/bin/php8.2 /usr/bin/php8.1; do
 if command -v "$b" >/dev/null 2>&1; then output=$("$b" -n -r 'echo "PATCHWATCH_CLI=".PHP_VERSION."\\n";' 2>/dev/null); case "$output" in *PATCHWATCH_CLI=*) printf '%s\\n' "$output"; break;; esac; fi
done
for b in php-fpm php-fpm85 php-fpm84 php-fpm83 php-fpm82 php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2; do
 if command -v "$b" >/dev/null 2>&1; then "$b" -n -i 2>/dev/null | grep -m1 '^PHP Version' | sed 's/^/PATCHWATCH_FPM=/'; break; fi
done
for b in php-cgi php-cgi85 php-cgi84 php-cgi83 php-cgi82; do
 if command -v "$b" >/dev/null 2>&1; then "$b" -n -v 2>/dev/null | head -1 | sed 's/^/PATCHWATCH_CGI=/'; break; fi
done
true`;
const images={};const targets=[...new Map(data.projects.filter(p=>p.php).flatMap(p=>p.images.map(i=>[i.image,{...i,project:p.id,name:p.name}]))).values()].slice(0,limit);
for(const target of targets){const checkedAt=new Date().toISOString();let result={image:target.image,project:target.project,name:target.name,checkedAt,status:'scan-error',platform:'linux/amd64',scope:'Published image runtime binaries on linux/amd64; not the user’s running deployment.'};try{
  const meta=await inspectRegistry(target.image);result={...result,digest:meta.digest,immutable:meta.immutable,publishedAt:meta.publishedAt};
  if(previous[target.image]?.digest===meta.digest&&previous[target.image]?.probeVersion===2&&['fixed','affected'].includes(previous[target.image].status)&&!args.includes('--force')){images[target.image]={...previous[target.image],tagCheckedAt:checkedAt};console.log(`${target.image}: ${images[target.image].status} (same digest)`);continue;}
  let pullRef=meta.immutable;
  if(target.image.startsWith('lscr.io/')){try{const mirror=await inspectRegistry(target.image.replace('lscr.io/','ghcr.io/'));if(mirror.digest===meta.digest){pullRef=mirror.immutable;result.mirror=pullRef;}}catch{}}
  let pullError;for(let attempt=0;attempt<3;attempt++){try{await run('docker',['pull','--platform=linux/amd64',pullRef],{timeout:180000,maxBuffer:1024*1024});pullError=null;break;}catch(e){pullError=e;if(attempt<2)await new Promise(r=>setTimeout(r,5000*(attempt+1)));}}if(pullError)throw pullError;
  result.executionRef=pullRef;
  const flags=['run','--rm','--pull=never','--platform=linux/amd64','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=192m','--pids-limit=64'];let output;
  try{output=(await run('docker',[...flags,'--user=65534:65534','--entrypoint=/bin/sh',pullRef,'-c',probe],{timeout:45000,maxBuffer:1024*1024})).stdout;}catch{output=(await run('docker',[...flags,'--entrypoint=/bin/sh',pullRef,'-c',probe],{timeout:45000,maxBuffer:1024*1024})).stdout;}
  const runtimes=[];for(const match of output.matchAll(/^PATCHWATCH_(CLI|FPM|CGI)=(.*)$/gm)){const version=match[2].match(/\b(\d+\.\d+\.\d+(?:[A-Za-z][\w.-]*)?)/)?.[1];if(version)runtimes.push({sapi:match[1],version,...assessRuntime(version,advisory)});}
  if(!runtimes.length){const raw=(await run('docker',[...flags,'--entrypoint=php',pullRef,'-n','-r','echo PHP_VERSION;'],{timeout:45000,maxBuffer:1024*1024})).stdout.trim();if(/^\d+\.\d+\.\d+(?:[A-Za-z][\w.-]*)?$/.test(raw))runtimes.push({sapi:'CLI',version:raw,...assessRuntime(raw,advisory)});}
  result.webEvidence=await inspectWebRuntime(pullRef);result.probeVersion=2;
  if(result.webEvidence.web){const web=result.webEvidence.web;runtimes.push({sapi:web.sapi,version:web.version,...assessRuntime(web.version,advisory),requestVerified:true});}
  result.runtimes=runtimes;
  if(!runtimes.length)throw new Error('No queryable PHP runtime found in the image. Automatic retry required.');
  if(runtimes.every(r=>r.status==='patched')){result.status='fixed';result.reason='All queried PHP runtime binaries meet the upstream fix versions for both CVEs.';}
  else if(runtimes.some(r=>r.status==='below-fixed')){result.status='affected';result.reason='A queried runtime is below the upstream PHP fix. No vendor backport has been automatically confirmed.';}
  else throw new Error('This PHP branch has no verified upstream version threshold; automatic vendor assessment is required.');
}catch(e){result.status='scan-error';result.error=String(e.stderr||e.message).slice(0,1200);result.reason='Automatic inspection failed; it will be retried on the next run.';}
images[target.image]=result;console.log(`${target.image}: ${result.status} ${result.runtimes?.map(r=>r.version).join(',')||result.error||''}`);
if(process.env.GITHUB_ACTIONS==='true'&&result.immutable)await run('docker',['image','rm',result.executionRef||result.immutable],{timeout:45000,maxBuffer:1024*1024}).catch(()=>{});
await mkdir(path.join(root,'dist/data'),{recursive:true});await writeFile(path.join(root,'dist/data/verified-images.json'),JSON.stringify({schemaVersion:1,generatedAt:new Date().toISOString(),runUrl:process.env.GITHUB_RUN_ID?`https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`:null,images},null,2));
}
const counts={fixed:0,affected:0,'scan-error':0};for(const i of Object.values(images))counts[i.status]++;
await writeFile(path.join(root,'dist/data/verified-images.json'),JSON.stringify({schemaVersion:1,generatedAt:new Date().toISOString(),runUrl:process.env.GITHUB_RUN_ID?`https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`:null,images},null,2));
console.log(JSON.stringify(counts));

import YAML from 'yaml';
export function phpImage(ref=''){
  const image=ref.toLowerCase().split('@')[0].replace(/:[^/]*$/,'');
  const name=image.split('/').at(-1);
  return /^(php(?:-fpm)?|wordpress|nextcloud|drupal|joomla|matomo|phpmyadmin|frankenphp)$/.test(name)||/^(serversideup\/php|webdevops\/php|shinsenter\/php|thecodingmachine\/php)/.test(image);
}
export function detectPhp(file,body){
  const found=[];const add=(reason,kind='component',extra={})=>found.push({file,reason,kind,...extra});
  const dev=/(^|\/)(tests?|fixtures?|examples?|docs?|benchmarks?|\.github)(\/|$)/i.test(file);
  if(/\.php(?:\.(?:dist|example))?$/i.test(file)&&body.includes('<?php'))add('PHP source code is present in this repository.',dev?'development':'component');
  if(/(^|\/)composer\.json$/.test(file)){try{const c=JSON.parse(body);if(c.require?.php)add(`PHP requirement: ${c.require.php}`,dev?'development':'runtime');else if(Object.keys(c.require||{}).length)add('Production Composer dependencies declare a PHP component.',dev?'development':'component');if(c['require-dev']?.php||Object.keys(c['require-dev']||{}).some(n=>/^phpunit\//.test(n)))add('PHP development tooling is declared.','development');}catch{}}
  if(/dockerfile/i.test(file)){
    for(const m of body.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)/gmi))if(phpImage(m[1]))add(`Container build uses PHP image ${m[1]}.`,dev?'development':'runtime',{image:m[1],baseImage:true});
    if(/\b(?:apk\s+add|apt(?:-get)?\s+install|dnf\s+install|yum\s+install)[^\n]*(?:\bphp(?:[0-9.]+)?(?:-\w+)?\b)/i.test(body)||/\bdocker-php-ext-(?:install|configure)\b/.test(body))add('Container build installs or configures PHP.',dev?'development':'runtime');
  }
  if(/(?:compose|docker-compose).*\.ya?ml$/i.test(file)){try{const c=YAML.parse(body,{logLevel:'silent'});for(const [service,s] of Object.entries(c?.services||{}))if(phpImage(s?.image))add(`Service ${service} references PHP image ${s.image}.`,'component',{image:s.image,service});}catch{}}
  if(/(^|\/)package\.json$/.test(file)){try{const c=JSON.parse(body);for(const [name,command] of Object.entries(c.scripts||{}))if(/(?:^|[;&|\s])php(?:[0-9.]*)?\s/.test(command))add(`Script ${name} invokes a PHP runtime.`,/test|lint|dev/.test(name)?'development':'component');}catch{}}
  return found;
}
export function applyPhpSignals(project,signals){
  const rank={runtime:0,component:1,development:2,declared:3};
  const unique=[...new Map(signals.map(s=>[`${s.source}|${s.reason}`,s])).values()].sort((a,b)=>(rank[a.kind]??4)-(rank[b.kind]??4));
  project.phpSignals=unique;project.php=unique.length>0;
  project.phpEvidence=unique.find(s=>s.verified)||unique[0]||null;
  project.phpScope=unique[0]?.kind||'unknown';
  project.status=project.php?'pending':'excluded';
  return project;
}

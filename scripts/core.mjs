export const STATUS = {patched:'Fix available',pending:'Pending verification',review:'Needs review',excluded:'Outside PHP scope'};
export function compareVersion(a,b){const x=a.split('.').map(Number),y=b.split('.').map(Number);for(let i=0;i<3;i++){if(x[i]!==y[i])return x[i]>y[i]?1:-1;}return 0;}
export function assessVersion(version,advisory){
  if(!/^\d+\.\d+\.\d+$/.test(version||''))return {status:'unknown',reason:'Missing, prerelease, or ambiguous PHP version.'};
  const branch=version.split('.').slice(0,2).join('.');const minimum=advisory.fixed[branch];
  if(!minimum)return {status:'unknown',reason:'No verified fix threshold for this branch. Check vendor backports or update the advisory.'};
  if(compareVersion(version,minimum)>=0)return {status:'patched',minimum,reason:'Meets the upstream fixed version for this PHP branch. CLI evidence does not attest the web SAPI.'};
  return {status:'below-fixed',minimum,reason:'Below upstream fix threshold; vendor backports require separate evidence.'};
}
export function cleanText(s=''){return String(s).replace(/\[([^\]]+)\]\([^)]*\)/g,'$1').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();}
export function repoFromUrl(url=''){const m=url.match(/^https:\/\/github\.com\/([^/]+\/[^/#?]+)/i);return m?m[1].replace(/\.git$/,''):null;}
export function releaseCandidate(text=''){return /php2shell|CVE-2026-10961[89]/i.test(text);}
export function applyEvidence(project,entries){
  if(!project.php)return project;
  const e=entries.find(e=>(e.repo&&e.repo.toLowerCase()===project.repo?.toLowerCase())||e.name===project.name);
  if(!e)return project;
  if(!e.source?.startsWith('https://')||!e.checkedAt||!e.scope||!e.cves?.includes('CVE-2026-109618')||!e.cves?.includes('CVE-2026-109619'))throw new Error(`Invalid scoped evidence for ${project.name}`);
  if(!['patched','pending','review'].includes(e.status))throw new Error('Invalid evidence status');
  project.status=e.status;project.evidence.push({...e,type:'reviewed'});return project;
}

import {assessVersion} from './core.mjs';
export function reusableEvidence(previous,digest,previousKey,currentKey,{force=false,selected=false}={}){
  return !force&&!selected&&previousKey===currentKey&&previous?.digest===digest&&previous?.probeVersion===2&&['fixed','affected'].includes(previous?.status);
}
export function assessRuntime(version,advisory){
  const match=String(version).match(/^(\d+)\.(\d+)\.(\d+)(.*)$/);
  if(!match)return assessVersion(version,advisory);
  const major=Number(match[1]),minor=Number(match[2]);
  if(major<8||(major===8&&minor<2))return {status:'below-fixed',reason:'Legacy PHP branch has no supported upstream fixed release. No vendor backport has been automatically confirmed.'};
  if(match[4])return {status:'below-fixed',reason:'Prerelease or nonstandard PHP build; update to a supported stable fixed version. No vendor fix was automatically confirmed.'};
  return assessVersion(version,advisory);
}

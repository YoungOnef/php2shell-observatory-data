export const FEED='https://raw.githubusercontent.com/YoungOnef/php2shell-observatory-data/main/dist/data/verified-images.json';
export const PROJECT_FEED='https://raw.githubusercontent.com/YoungOnef/php2shell-observatory-data/main/dist/data/projects.json';
export function verdictImages(project){const primary=project.images.filter(i=>i.role==='primary');return primary.length?primary:project.images;}
export function applyVerification(data,report){
  for(const p of data.projects){
    p.vendorStatus??=p.status;
    if(!p.php){p.status='excluded';continue;}
    for(const image of p.images){const result=report?.images?.[image.image];image.verification=result||null;image.status=result?.status||'scanning';}
    if(!p.images.length){p.status=['component','development'].includes(p.phpScope)?'component-only':'runtime-external';continue;}
    const primary=p.images.filter(i=>i.role==='primary');
    p.verdictScope=primary.length?'Published project image':'PHP component images';
    p.companionWarnings=p.images.filter(i=>i.role==='companion'&&i.status==='affected').length;
    const statuses=verdictImages(p).map(i=>i.status);
    p.status=statuses.includes('affected')?'affected':statuses.includes('scan-error')?'scan-error':statuses.every(s=>s==='fixed')?'fixed':'scanning';
  }
  data.verification=report?{generatedAt:report.generatedAt,runUrl:report.runUrl}:null;
  return data;
}
export function verificationCounts(data){const images=[...new Map(data.projects.filter(p=>p.php).flatMap(p=>p.images.map(i=>[i.image,i]))).values()];return {total:images.length,fixed:images.filter(i=>i.status==='fixed').length,affected:images.filter(i=>i.status==='affected').length,errors:images.filter(i=>i.status==='scan-error').length,scanning:images.filter(i=>i.status==='scanning').length};}

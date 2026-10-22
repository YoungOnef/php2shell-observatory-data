"""Independent, read-only image spot check. Does not import the dashboard classifier.

Requests a harmless PHP JSON page through Apache/FPM where present. No exploit,
no host ports, no network access, and only generated audit files are mounted.
"""
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(args, timeout=150):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    return {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr[-8000:]}


INFO = '''<?php echo json_encode(array('version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'binary'=>PHP_BINARY,'session_upload_progress'=>ini_get('session.upload_progress.enabled'),'memory_limit'=>ini_get('memory_limit')));'''

FCGI = r'''<?php
function rec($t,$p) {return pack('CCnnCC',1,$t,1,strlen($p),0,0).$p;}
function exact($s,$n) {$r='';while(strlen($r)<$n){$p=fread($s,$n-strlen($r));if($p===false||$p==='')throw new Exception('FastCGI EOF');$r.=$p;}return $r;}
$s=fsockopen('127.0.0.1',9000,$e,$m,5);if(!$s)throw new Exception($m);stream_set_timeout($s,5);
$p='';foreach(array('SCRIPT_FILENAME'=>'/audit/info.php','SCRIPT_NAME'=>'/info.php','REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/info.php','SERVER_PROTOCOL'=>'HTTP/1.1','SERVER_NAME'=>'localhost','SERVER_PORT'=>'9000','REMOTE_ADDR'=>'127.0.0.1','CONTENT_LENGTH'=>'0') as $k=>$v){$p.=chr(strlen($k)).chr(strlen($v)).$k.$v;}
fwrite($s,rec(1,pack('nCxxxxx',1,0)).rec(4,$p).rec(4,'').rec(5,''));$out='';
while(true){$h=unpack('Cversion/Ctype/nid/nlength/Cpadding/Creserved',exact($s,8));$d=$h['length']?exact($s,$h['length']):'';if($h['padding'])exact($s,$h['padding']);if($h['type']===6)$out.=$d;if($h['type']===3)break;}
echo preg_replace('/^.*?\r?\n\r?\n/s','',$out);
'''

PROBE = r'''
set -eu
P=$(command -v php || command -v php85 || command -v php84 || command -v php83 || command -v php82 || command -v php81)
printf '\nAUDIT_CLI\n'; "$P" -r 'echo json_encode(array("version"=>PHP_VERSION,"sapi"=>PHP_SAPI,"binary"=>PHP_BINARY));'
printf '\nAUDIT_OS\n'; cat /etc/os-release
printf '\nAUDIT_PACKAGES\n'
if command -v apk >/dev/null; then apk info -v | grep -E '^php[0-9]*[-0-9]' || true; fi
if command -v dpkg-query >/dev/null; then dpkg-query -W -f='${Package} ${Version}\n' 'php*' 2>/dev/null || true; fi
printf '\nAUDIT_WEB\n'
LIB=$(find /usr/lib/apache2/modules /usr/local/apache2/modules -name 'libphp*.so' 2>/dev/null | head -1 || true)
if [ -n "$LIB" ]; then
  MOD=php_module; case "$LIB" in *libphp7.so) MOD=php7_module;; esac
  cat >/tmp/audit-apache.conf <<EOF
ServerRoot /etc/apache2
ServerName localhost
Listen 127.0.0.1:8080
PidFile /tmp/audit-apache.pid
DefaultRuntimeDir /tmp
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule $MOD $LIB
User www-data
Group www-data
DocumentRoot /audit
ErrorLog /dev/stderr
<Directory /audit>
Require all granted
<FilesMatch "\\.php$">
SetHandler application/x-httpd-php
</FilesMatch>
</Directory>
EOF
  apache2 -f /tmp/audit-apache.conf -DFOREGROUND >/tmp/audit-server.log 2>&1 &
  sleep 2
  "$P" -r '$s=@file_get_contents("http://127.0.0.1:8080/info.php"); if(!$s)exit(2); echo $s;' || { cat /tmp/audit-server.log; exit 2; }
else
  F=''; for f in php-fpm php-fpm85 php-fpm84 php-fpm83 php-fpm82 php-fpm81; do if command -v "$f" >/dev/null; then F=$(command -v "$f"); break; fi; done
  if [ -n "$F" ]; then
    cat >/tmp/audit-fpm.conf <<EOF
[global]
daemonize = no
error_log = /tmp/audit-fpm.log
[audit]
listen = 127.0.0.1:9000
user = nobody
group = nobody
pm = static
pm.max_children = 1
catch_workers_output = yes
security.limit_extensions = .php
EOF
    "$F" -F -y /tmp/audit-fpm.conf >/tmp/audit-server.log 2>&1 &
    sleep 2
    "$P" /audit/fcgi.php || { cat /tmp/audit-server.log; exit 2; }
  else
    printf 'No separate Apache module or FPM binary. The image uses the CLI binary.\n'
    printf '\nAUDIT_APP_RUNTIME\n'
    if [ -d /etc/shlink ]; then grep -R -n -E 'command:|php |bin/rr|SHLINK_RUNTIME' /etc/shlink/docker-entrypoint.sh /etc/shlink/config/roadrunner* /etc/shlink/.rr* 2>/dev/null || true; fi
  fi
fi
printf '\nAUDIT_DONE\n'
'''


def section(output, name):
    match = re.search(r"\nAUDIT_" + name + r"\n(.*?)(?=\nAUDIT_|\Z)", output, re.S)
    return match.group(1).strip() if match else ""


sample = json.loads(Path('config/spotcheck-sample.json').read_text(encoding='utf-8'))
report = {"generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "seed": sample['seed'], "sampling": sample['sampling'], "scope": "Pinned linux/amd64 images; harmless PHP page through isolated Apache/FPM, plus CLI binary for RoadRunner images. No exploit attempt.", "results": []}
outpath = Path('dist/data/independent-spot-check.json')
outpath.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory() as tmp:
    probe = Path(tmp)
    probe.chmod(0o755)
    (probe/'info.php').write_text(INFO)
    (probe/'fcgi.php').write_text(FCGI)
    for item in sample['samples']:
        result = {k: item[k] for k in ('image','immutable','digest','status')}
        result['expectedLabel'] = result.pop('status')
        print('CHECK', item['image'], flush=True)
        try:
            pull = run(['docker','pull','--platform','linux/amd64',item['immutable']], timeout=240)
            if pull['code']:
                raise RuntimeError(pull['stderr'])
            config = run(['docker','image','inspect',item['immutable']])
            inspected = json.loads(config['stdout'])[0]
            result['repoDigests'] = inspected.get('RepoDigests')
            result['created'] = inspected.get('Created')
            result['buildMetadata'] = [v for v in inspected['Config'].get('Env',[]) if v.startswith(('PHP_VERSION=','PHP_URL=','PHP_SHA256=','SHLINK_VERSION=','SHLINK_RUNTIME='))]
            # www-data for Debian Apache; unprivileged nobody for Alpine/FPM.
            uid = '33:33' if item['image'].startswith(('joomla:','wordpress:','phpmyadmin')) else '65534:65534'
            check = run(['docker','run','--rm','--pull=never','--platform','linux/amd64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--pids-limit','64','--user',uid,'--tmpfs','/tmp:rw,nosuid,nodev,size=32m','-v',str(probe)+':/audit:ro','--entrypoint','/bin/sh',item['immutable'],'-c',PROBE])
            result['probe'] = check
            for key in ('CLI','WEB'):
                raw = section(check['stdout'],key)
                try: result[key.lower()] = json.loads(raw)
                except ValueError: result[key.lower()] = {'output':raw}
            result['os'] = section(check['stdout'],'OS')
            result['packages'] = section(check['stdout'],'PACKAGES')
            version = result['web'].get('version') or result['cli'].get('version')
            fixed = {'8.2':35,'8.3':36,'8.4':27,'8.5':12}
            nums = version.split('.') if version else []
            branch = '.'.join(nums[:2])
            result['independentVerdict'] = ('fixed' if branch in fixed and int(nums[2]) >= fixed[branch] else 'below-upstream-fix') if version else 'probe-error'
            result['note'] = 'Version comparison to PHP official advisory. Distro backports require package evidence. No exploitability or deployment attestation.'
            print(json.dumps({k: result.get(k) for k in ('image','cli','web','packages','independentVerdict')}), flush=True)
        except Exception as exc:
            result['error'] = str(exc)
        report['results'].append(result)
        outpath.write_text(json.dumps(report,indent=2)+'\n')
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            run(['docker','image','rm',item['immutable']])
print('Saved',outpath,flush=True)

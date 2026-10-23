<?php
declare(strict_types=1);
// Harbor Terminal 1.1.0 | PHP 8.1+ | Deploy only on your own hosting account.
const INSTANCE_ID = '__INSTANCE_ID__';
// HARBOR_AUTH_BEGIN
const AUTH_SALT = '__AUTH_SALT__';
const AUTH_VERIFIER = '__AUTH_VERIFIER__';
// HARBOR_AUTH_END
const AUTH_ITERATIONS = 600000;
const ALLOWED_IP = ''; // Optional fixed public IP; no proxy headers are trusted.

$scriptNonce = base64_encode(random_bytes(18));
ini_set('display_errors', '0');
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; connect-src 'self'; script-src 'nonce-$scriptNonce'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
if (empty($_SERVER['HTTPS']) || strtolower((string)$_SERVER['HTTPS']) === 'off') {
    http_response_code(403); exit('Harbor Terminal requires HTTPS.');
}
if (ALLOWED_IP !== '' && ($_SERVER['REMOTE_ADDR'] ?? '') !== ALLOWED_IP) {
    http_response_code(403); exit('Access denied.');
}
function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function field(string $name): string { return isset($_POST[$name]) && is_string($_POST[$name]) ? $_POST[$name] : ''; }
function authConfig(): array {
    // Read current on-disk credentials even when the host has stale OPcache bytecode.
    static $config = null;
    if ($config !== null) return $config;
    $source = @file_get_contents(__FILE__);
    if ($source === false || preg_match("~// HARBOR_AUTH_BEGIN\\Rconst AUTH_SALT = '([a-f0-9]{32})';\\Rconst AUTH_VERIFIER = '([a-f0-9]{64})';\\R// HARBOR_AUTH_END~", $source, $m) !== 1) {
        http_response_code(503); exit('Credential configuration unavailable.');
    }
    return $config = ['salt' => $m[1], 'verifier' => $m[2]];
}
function validPassword(string $password): bool {
    $auth = authConfig();
    return strlen($password) <= 256 && hash_equals($auth['verifier'], hash_pbkdf2('sha256', $password, $auth['salt'], AUTH_ITERATIONS, 64));
}
function jsonReply(int $code, array $value): never {
    http_response_code($code); header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($value, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
function commandsAvailable(): bool {
    foreach (['proc_open', 'proc_get_status', 'proc_terminate', 'proc_close', 'stream_set_blocking', 'stream_get_contents'] as $function) {
        if (!is_callable($function)) return false;
    }
    return true;
}
function privateRoot(): ?string {
    static $done=false,$root=null;
    if($done)return $root; $done=true;
    $sessionPath=explode(';',session_save_path());
    foreach([sys_get_temp_dir(),end($sessionPath)] as $base){
        if(!is_string($base)||$base===''||!@is_dir($base)||!@is_writable($base))continue;
        $dir=rtrim($base,'/\\').'/harbor-'.substr(hash('sha256',__FILE__.'|'.getmyuid()),0,24);
        if(!@is_dir($dir)&&!@mkdir($dir,0700))continue;
        if(@is_link($dir)||!@is_writable($dir))continue;
        if(PHP_OS_FAMILY!=='Windows'&&@fileowner($dir)!==getmyuid())continue;
        @chmod($dir,0700); return $root=$dir;
    }
    return null;
}
function stateUpdate(string $name,callable $change): array {
    $root=privateRoot();if(!$root)throw new RuntimeException('Private storage unavailable.');
    if(!preg_match('/^[a-z0-9-]+$/',$name))throw new RuntimeException('Invalid state key.');
    $handle=@fopen($root.'/'.$name.'.json','c+');
    if(!$handle||!flock($handle,LOCK_EX))throw new RuntimeException('Private storage is not writable.');
    try{
        $raw=stream_get_contents($handle);$data=json_decode($raw?:'[]',true);if(!is_array($data))$data=[];
        $next=$change($data);$encoded=json_encode($next,JSON_INVALID_UTF8_SUBSTITUTE);
        if($encoded===false)throw new RuntimeException('Cannot encode state.');
        rewind($handle);if(!ftruncate($handle,0)||fwrite($handle,$encoded)!==strlen($encoded)||!fflush($handle))throw new RuntimeException('Cannot save state.');
        return $next;
    }finally{flock($handle,LOCK_UN);fclose($handle);}
}
function rateKey():string{return 'rate-'.substr(hash('sha256',$_SERVER['REMOTE_ADDR']??'local'),0,32);}
function rateWait():int{
    if(!privateRoot())return max(0,(int)($_SESSION['blocked_until']??0)-time());
    $data=stateUpdate(rateKey(),fn($data)=>$data);return max(0,(int)($data['until']??0)-time());
}
function rateRecord(bool $success):void{
    if(!privateRoot()){
        $_SESSION['failed']= $success?0:(int)($_SESSION['failed']??0)+1;
        $_SESSION['blocked_until']= $success?0:($_SESSION['failed']>=5?time()+30:0);return;
    }
    stateUpdate(rateKey(),function($data)use($success){
        if($success)return [];
        $count=time()-(int)($data['start']??0)>600?1:(int)($data['count']??0)+1;
        return ['start'=>$count===1?time():$data['start'],'count'=>$count,'until'=>$count>=5?time()+min(240,30*(2**min(3,$count-5))):0];
    });
}
function sessionKey():string{return hash('sha256',session_id());}
function sessionCheck():bool{
    if(!privateRoot())return true;
    $key=sessionKey();$revoked=false;
    stateUpdate('sessions',function($sessions)use($key,&$revoked){
        foreach($sessions as $id=>$entry)if(time()-(int)($entry['last']??0)>86400)unset($sessions[$id]);
        if(!empty($sessions[$key]['revoked'])){$revoked=true;return $sessions;}
        $sessions[$key]=['created'=>$sessions[$key]['created']??time(),'last'=>time(),'ip'=>substr($_SERVER['REMOTE_ADDR']??'',0,64),'agent'=>substr($_SERVER['HTTP_USER_AGENT']??'',0,140),'revoked'=>false,'fingerprint'=>authConfig()['verifier']];
        return $sessions;
    });return !$revoked;
}
function apiPayload():array{
    if($_SERVER['REQUEST_METHOD']!=='POST')jsonReply(405,['error'=>'POST required.']);
    if(!str_starts_with(strtolower($_SERVER['CONTENT_TYPE']??''),'application/json'))jsonReply(415,['error'=>'JSON required.']);
    $raw=file_get_contents('php://input',false,null,0,65537);$data=json_decode($raw?:'',true);
    if($raw===false||strlen($raw)>65536||!is_array($data))jsonReply(400,['error'=>'درخواست معتبر نیست.']);
    if(!is_string($data['csrf']??null)||!hash_equals($_SESSION['csrf'],$data['csrf']))jsonReply(403,['error'=>'نشست صفحه تغییر کرده است؛ صفحه را تازه‌سازی کنید.']);
    return $data;
}
function directoryPath(mixed $value):string{
    if(!is_string($value)||str_contains($value,"\0"))jsonReply(400,['error'=>'مسیر پوشه معتبر نیست.']);
    $path=realpath($value);if($path===false||!is_dir($path)||!is_readable($path))jsonReply(400,['error'=>'پوشه وجود ندارد یا قابل خواندن نیست.']);
    return $path;
}
function safeJob(mixed $value):string{
    if(!is_string($value)||!preg_match('/^[a-f0-9]{32}$/',$value))jsonReply(400,['error'=>'شناسهٔ اجرا معتبر نیست.']);return $value;
}
function auditCommand(string $command,string $cwd,int $code,float $duration):void{
    if(!privateRoot())return;
    try { stateUpdate('audit',function($items)use($command,$cwd,$code,$duration){
        array_unshift($items,['at'=>time(),'command'=>substr($command,0,8192),'cwd'=>$cwd,'code'=>$code,'duration'=>round($duration,3)]);return array_slice($items,0,100);
    }); } catch(Throwable $error) { /* Optional audit storage must not hide a completed command. */ }
}

// A public identity probe contains no password, hash, account path or session information.
$api = isset($_GET['api']) && is_string($_GET['api']) ? $_GET['api'] : '';
if ($api === 'info' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    jsonReply(200, ['product' => 'harbor-terminal', 'id' => INSTANCE_ID, 'version' => '1.1.0', 'minimum_password_characters' => 4, 'commands' => commandsAvailable(), 'php'=>PHP_VERSION, 'features'=>['stream'=>commandsAvailable(),'files'=>true,'privateStorage'=>privateRoot()!==null,'sessions'=>privateRoot()!==null,'sharedRateLimit'=>privateRoot()!==null]]);
}
// Credentials are sent only in the HTTPS POST body, never in a URL or a cookie.
if ($api === 'rotate') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonReply(405, ['error' => 'POST required.']);
    if (!str_starts_with(strtolower($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) jsonReply(415, ['error' => 'JSON required.']);
    $raw = file_get_contents('php://input', false, null, 0, 4097);
    if ($raw === false || strlen($raw) > 4096) jsonReply(413, ['error' => 'Request too large.']);
    $input = json_decode($raw, true);
    if (!is_array($input) || !isset($input['id'], $input['current_password'], $input['new_password']) ||
        !is_string($input['id']) || !is_string($input['current_password']) || !is_string($input['new_password'])) {
        jsonReply(400, ['error' => 'Invalid request.']);
    }
    $wait=rateWait(); if($wait>0){header('Retry-After: '.$wait);jsonReply(429,['error'=>'تلاش‌های ناموفق زیاد بوده است؛ '.$wait.' ثانیه بعد دوباره امتحان کنید.']);}
    if (!hash_equals(INSTANCE_ID, $input['id']) || !validPassword($input['current_password'])) {
        rateRecord(false);
        usleep(800000); jsonReply(403, ['error' => 'رمز فعلی اشتباه است.']);
    }
    rateRecord(true);
    $new = $input['new_password'];
    if (!preg_match('//u', $new) || preg_match_all('/./us', $new) < 4 || strlen($new) > 256) {
        jsonReply(400, ['error' => 'رمز جدید باید حداقل ۴ کاراکتر و حداکثر ۲۵۶ بایت باشد.']);
    }
    if (hash_equals($input['current_password'], $new)) jsonReply(400, ['error' => 'رمز جدید باید متفاوت باشد.']);
    // Stable lock serializes rotations even though atomic replacement changes the PHP inode.
    $lock = @fopen(__DIR__ . '/.harbor-lock-' . INSTANCE_ID . '.php', 'c');
    if (!$lock || !flock($lock, LOCK_EX)) jsonReply(500, ['error' => 'دسترسی نوشتن یا قفل‌کردن فایل وجود ندارد؛ رمز تغییر نکرد.']);
    $source = @file_get_contents(__FILE__);
    $pattern = '~// HARBOR_AUTH_BEGIN\Rconst AUTH_SALT = \'([a-f0-9]{32})\';\Rconst AUTH_VERIFIER = \'([a-f0-9]{64})\';\R// HARBOR_AUTH_END~';
    if ($source === false || preg_match($pattern, $source, $matches) !== 1 || !hash_equals(authConfig()['verifier'], $matches[2])) {
        flock($lock, LOCK_UN); fclose($lock);
        jsonReply(409, ['error' => 'فایل تغییر کرده است؛ با رمز جدید دوباره امتحان کنید.']);
    }
    $salt = bin2hex(random_bytes(16));
    $hash = hash_pbkdf2('sha256', $new, $salt, AUTH_ITERATIONS, 64);
    $replacement = "// HARBOR_AUTH_BEGIN\nconst AUTH_SALT = '$salt';\nconst AUTH_VERIFIER = '$hash';\n// HARBOR_AUTH_END";
    $updated = preg_replace($pattern, $replacement, $source, 1, $count);
    $temp = __DIR__ . '/.harbor-write-' . bin2hex(random_bytes(12)) . '.php';
    $mask = umask(0077);
    $handle = @fopen($temp, 'x');
    umask($mask);
    $ok = false;
    if ($handle && $updated !== null && $count === 1) {
        $written = fwrite($handle, $updated);
        $flushed = fflush($handle); fclose($handle);
        if ($written === strlen($updated) && $flushed) $ok = @rename($temp, __FILE__);
    } elseif ($handle) fclose($handle);
    if (!$ok && is_file($temp)) @unlink($temp);
    if ($ok && is_callable('opcache_invalidate')) @opcache_invalidate(__FILE__, true);
    flock($lock, LOCK_UN); fclose($lock);
    if (!$ok) jsonReply(500, ['error' => 'نوشتن فایل انجام نشد؛ رمز قبلی حفظ شد.']);
    jsonReply(200, ['ok' => true]);
}
if ($api !== '' && !in_array($api,['context','files','download','upload','sessions','revoke','audit','stream','stop'],true)) jsonReply(404,['error'=>'Unknown endpoint.']);
ini_set('session.use_strict_mode', '1'); ini_set('session.use_only_cookies', '1');
session_name('harbor_' . INSTANCE_ID);
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
// Every request compares the verifier fingerprint; a password rotation revokes every old login.
if (isset($_SESSION['last']) && (time() - $_SESSION['last'] > 900 ||
    !hash_equals(authConfig()['verifier'], (string)($_SESSION['fingerprint'] ?? '')))) {
    $_SESSION = []; session_regenerate_id(true);
}
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));
if(!empty($_SESSION['authenticated'])&&!sessionCheck()){$_SESSION=[];session_regenerate_id(true);$_SESSION['csrf']=bin2hex(random_bytes(32));}
if($api!=='' && $api!=='info' && $api!=='rotate'){
    if(empty($_SESSION['authenticated']))jsonReply(401,['error'=>'ورود منقضی شده است؛ صفحه را تازه‌سازی و دوباره وارد شوید.']);
    $_SESSION['last']=time();$owner=sessionKey();$csrf=$_SESSION['csrf'];
    if($api==='download'){
        if($_SERVER['REQUEST_METHOD']!=='GET')jsonReply(405,['error'=>'GET required.']);
        $file=is_string($_GET['path']??null)&&!str_contains($_GET['path'],"\0")?realpath($_GET['path']):false;
        if(!$file||!is_file($file)||!is_readable($file))jsonReply(404,['error'=>'فایل قابل دریافت نیست.']);
        $size=filesize($file);if($size===false||$size>10485760)jsonReply(413,['error'=>'حداکثر اندازهٔ دریافت از این صفحه ۱۰ مگابایت است.']);
        session_write_close();header('Content-Type: application/octet-stream');header('Content-Disposition: attachment; filename="download.bin"; filename*=UTF-8\'\''.rawurlencode(basename($file)));header('Content-Length: '.$size);readfile($file);exit;
    }
    if($api==='upload'){
        if($_SERVER['REQUEST_METHOD']!=='POST'||!hash_equals($csrf,field('csrf')))jsonReply(403,['error'=>'درخواست آپلود معتبر نیست.']);
        $cwd=directoryPath(field('cwd'));$file=$_FILES['file']??null;
        if(!is_array($file)||($file['error']??1)!==UPLOAD_ERR_OK)jsonReply(400,['error'=>'آپلود انجام نشد؛ اندازه و تنظیمات آپلود PHP را بررسی کنید.']);
        $name=$file['name']??'';
        if(!is_string($name)||$name===''||$name==='.'||$name==='..'||preg_match('/[\/\\\\\x00-\x1f]/',$name))jsonReply(400,['error'=>'نام فایل معتبر نیست.']);
        if(($file['size']??0)>5242880)jsonReply(413,['error'=>'حداکثر اندازهٔ آپلود ۵ مگابایت است.']);
        $target=$cwd.DIRECTORY_SEPARATOR.$name;
        if(file_exists($target)||is_link($target))jsonReply(409,['error'=>'فایلی با همین نام وجود دارد؛ فایل موجود بازنویسی نشد.']);
        // Exclusive creation prevents a second upload from overwriting a concurrent upload.
        $out=@fopen($target,'x+b');if(!$out)jsonReply(403,['error'=>'اجازهٔ نوشتن در این پوشه وجود ندارد.']);
        $in=@fopen($file['tmp_name'],'rb');$written=$in?stream_copy_to_stream($in,$out,5242881):false;
        if($in)fclose($in);fclose($out);
        if($written===false||$written!==($file['size']??-1)){@unlink($target);jsonReply(500,['error'=>'نوشتن فایل کامل نشد.']);}
        jsonReply(200,['ok'=>true]);
    }
    $payload=apiPayload();
    if($api==='context'||$api==='files'){
        $cwd=directoryPath($payload['cwd']??'');$items=[];$names=scandir($cwd)?:[];
        foreach($names as $name){if($name==='.'||$name==='..')continue;$path=$cwd.DIRECTORY_SEPARATOR.$name;
            $isDir=is_dir($path);$items[]=['name'=>$name,'directory'=>$isDir,'size'=>$isDir?null:(@filesize($path)?:0)];if(count($items)>=300)break;}
        usort($items,fn($a,$b)=>($b['directory']<=>$a['directory'])?:strnatcasecmp($a['name'],$b['name']));
        jsonReply(200,['cwd'=>$cwd,'parent'=>dirname($cwd),'items'=>$items,'truncated'=>count($names)>302]);
    }
    if($api==='sessions'||$api==='revoke'){
        if(!privateRoot())jsonReply(503,['error'=>'ذخیرهٔ خصوصی روی هاست قابل استفاده نیست؛ مدیریت نشست‌ها غیرفعال است.']);
        if($api==='revoke'){
            $target=$payload['target']??'';
            if(!is_string($target)||($target!=='others'&&!preg_match('/^[a-f0-9]{64}$/',$target)))jsonReply(400,['error'=>'شناسهٔ نشست معتبر نیست.']);
            stateUpdate('sessions',function($sessions)use($target,$owner){foreach($sessions as $id=>&$entry)if(($target==='others'&&$id!==$owner)||$id===$target)$entry['revoked']=true;return $sessions;});
            jsonReply(200,['ok'=>true]);
        }
        $sessions=stateUpdate('sessions',fn($items)=>$items);$result=[];
        foreach($sessions as $id=>$entry)if(empty($entry['revoked'])&&hash_equals(authConfig()['verifier'],(string)($entry['fingerprint']??''))&&time()-(int)$entry['last']<=900)$result[]=['id'=>$id,'current'=>$id===$owner,'created'=>$entry['created'],'last'=>$entry['last'],'ip'=>$entry['ip'],'agent'=>$entry['agent']];
        jsonReply(200,['items'=>$result]);
    }
    if($api==='audit'){
        if(!privateRoot())jsonReply(503,['error'=>'تاریخچهٔ سمت هاست در دسترس نیست.']);
        $items=stateUpdate('audit',fn($items)=>$items);if(!empty($payload['clear'])){stateUpdate('audit',fn($items)=>[]);$items=[];}jsonReply(200,['items'=>$items]);
    }
    if($api==='stop'){
        if(!privateRoot())jsonReply(503,['error'=>'توقف جداگانه روی این هاست فعال نیست.']);
        $id=safeJob($payload['job']??'');$job=stateUpdate('job-'.$id,fn($job)=>$job);
        if(($job['owner']??'')!==$owner||empty($job['running']))jsonReply(404,['error'=>'اجرای فعال متعلق به این نشست پیدا نشد.']);
        stateUpdate('job-'.$id,function($job){$job['stop']=true;return $job;});jsonReply(200,['ok'=>true]);
    }
    if($api==='stream'){
        if(!commandsAvailable())jsonReply(503,['error'=>'هاست اجرای فرمان را بسته است.']);
        $command=is_string($payload['command']??null)?trim($payload['command']):'';$cwd=directoryPath($payload['cwd']??'');$id=safeJob($payload['job']??'');
        if($command===''||strlen($command)>8192||str_contains($command,"\0"))jsonReply(400,['error'=>'فرمان معتبر نیست.']);
        if(privateRoot()){
            $job=stateUpdate('job-'.$id,function($job)use($owner){if($job)jsonReply(409,['error'=>'شناسهٔ اجرا قبلاً استفاده شده است.']);return ['owner'=>$owner,'running'=>true,'stop'=>false,'at'=>time()];});
        }
        $_SESSION['cwd']=$cwd;session_write_close();
        header('Content-Type: application/x-ndjson; charset=UTF-8');header('X-Accel-Buffering: no');@ini_set('zlib.output_compression','0');
        while(ob_get_level()>0){if(!@ob_end_flush())break;}ob_implicit_flush(true);
        $emit=function(array $event):void{echo json_encode($event,JSON_INVALID_UTF8_SUBSTITUTE|JSON_UNESCAPED_UNICODE)."\n";flush();};
        $emit(['type'=>'start','job'=>$id,'stopAvailable'=>privateRoot()!==null]);
        $pipes=[];$process=@proc_open(['/bin/sh','-c',$command],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,$cwd);
        if(!is_resource($process)){$emit(['type'=>'error','message'=>'اجازهٔ شروع فرمان داده نشد.']);if(privateRoot())stateUpdate('job-'.$id,fn($job)=>['owner'=>$owner,'running'=>false]);exit;}
        fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);
        $started=microtime(true);$bytes=0;$reason='complete';$state=['exitcode'=>-1];$lastCheck=0.0;
        while(true){
            foreach([1,2] as $fd){$remaining=262144-$bytes;if($remaining>0){$chunk=stream_get_contents($pipes[$fd],$remaining);if($chunk!==false&&$chunk!==''){$bytes+=strlen($chunk);$emit(['type'=>'chunk','data'=>base64_encode($chunk),'encoding'=>'base64','stream'=>$fd===1?'stdout':'stderr']);}}}
            $state=proc_get_status($process);if(!$state['running'])break;
            $now=microtime(true);$stop=false;
            if(privateRoot()&&$now-$lastCheck>.15){$job=stateUpdate('job-'.$id,fn($job)=>$job);$stop=!empty($job['stop']);$lastCheck=$now;}
            if($stop||connection_aborted()||$now-$started>20||$bytes>=262144){$reason=$stop?'stopped':(connection_aborted()?'disconnected':($bytes>=262144?'output_limit':'time_limit'));proc_terminate($process,9);break;}
            usleep(20000);
        }
        foreach([1,2] as $fd){$remaining=262144-$bytes;if($remaining>0){$chunk=stream_get_contents($pipes[$fd],$remaining);if($chunk!==false&&$chunk!==''){$bytes+=strlen($chunk);$emit(['type'=>'chunk','data'=>base64_encode($chunk),'encoding'=>'base64','stream'=>$fd===1?'stdout':'stderr']);}}fclose($pipes[$fd]);}
        $closed=proc_close($process);$code=$state['exitcode']>=0?$state['exitcode']:$closed;$duration=microtime(true)-$started;
        if(privateRoot()){stateUpdate('job-'.$id,fn($job)=>['owner'=>$owner,'running'=>false,'at'=>time()]);auditCommand($command,$cwd,$code,$duration);}
        $emit(['type'=>'done','code'=>$code,'duration'=>round($duration,3),'bytes'=>$bytes,'reason'=>$reason]);exit;
    }
    jsonReply(404,['error'=>'قابلیت درخواست‌شده وجود ندارد.']);
}

$code = null; $elapsed = null;
$message = ''; $output = ''; $command = ''; $cwd = $_SESSION['cwd'] ?? __DIR__;
$available = commandsAvailable();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], field('csrf'))) { http_response_code(403); exit('درخواست نامعتبر است. صفحه را دوباره باز کنید.'); }
    $action = field('action');
    if ($action === 'login') {
        $wait=rateWait();
        if($wait>0){http_response_code(429);$message='تلاش‌های ناموفق زیاد بوده است؛ '.$wait.' ثانیه بعد دوباره امتحان کنید.';}
        elseif (validPassword(field('password'))) {
            rateRecord(true);
            session_regenerate_id(true); $_SESSION['authenticated'] = true;
            $_SESSION['fingerprint'] = authConfig()['verifier']; $_SESSION['csrf'] = bin2hex(random_bytes(32));
        } else { rateRecord(false); usleep(800000); $message = 'رمز ورود اشتباه است.'; }
    } elseif (!empty($_SESSION['authenticated']) && $action === 'logout') {
        if(privateRoot()){$key=sessionKey();stateUpdate('sessions',function($items)use($key){if(isset($items[$key]))$items[$key]['revoked']=true;return $items;});}
        $_SESSION = []; session_regenerate_id(true); $_SESSION['csrf'] = bin2hex(random_bytes(32));
    } elseif (!empty($_SESSION['authenticated']) && $action === 'run') {
        $command = trim(field('command')); $candidate = realpath(field('cwd'));
        if (!$available) $message = 'هاست اجرای پردازش از PHP را بسته است. با پشتیبانی هاست تماس بگیرید.';
        elseif ($candidate === false || !is_dir($candidate)) $message = 'مسیر پوشه معتبر نیست.';
        elseif ($command === '' || strlen($command) > 8192 || str_contains($command, "\0")) $message = 'یک فرمان معتبر وارد کنید.';
        else {
            $cwd = $candidate; $_SESSION['cwd'] = $cwd; $pipes = [];
            $process = @proc_open(['/bin/sh', '-c', $command], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $cwd);
            if (!is_resource($process)) $message = 'هاست اجازهٔ شروع پردازش نداد.';
            else {
                fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
                $started = microtime(true); $stopped = false; $state = ['exitcode' => -1];
                while (true) {
                    foreach ([1, 2] as $fd) {
                        $remaining = 262144 - strlen($output);
                        if ($remaining > 0) $output .= stream_get_contents($pipes[$fd], $remaining);
                    }
                    $state = proc_get_status($process);
                    if (!$state['running']) break;
                    if (strlen($output) >= 262144 || microtime(true) - $started > 10) {
                        proc_terminate($process, 9); $stopped = true; break;
                    }
                    usleep(20000);
                }
                foreach ([1, 2] as $fd) {
                    $remaining = 262144 - strlen($output);
                    if ($remaining > 0) $output .= stream_get_contents($pipes[$fd], $remaining);
                    fclose($pipes[$fd]);
                }
                $closed = proc_close($process); $elapsed = microtime(true) - $started; $code = $state['exitcode'] >= 0 ? $state['exitcode'] : $closed;
                $message = $stopped ? 'حد زمان یا خروجی رسید؛ توقف تمام پردازش‌های فرزند تضمین نمی‌شود.' : 'کد پایان: ' . $code;
            }
        }
    }
}
if (!empty($_SESSION['authenticated'])) { $_SESSION['last'] = time(); sessionCheck(); }
?>
<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Harbor Terminal</title>
<style>
:root{color-scheme:dark;--bg:#0c1117;--panel:#121c25;--line:#273742;--muted:#9bacba;--text:#e7eef4;--mint:#b5ed89;--blue:#8fc9ff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.9 Tahoma,Arial,sans-serif}button,input,textarea{font:inherit}button,a{touch-action:manipulation}button{cursor:pointer;border:1px solid var(--line);background:#1b2a36;color:var(--text);border-radius:9px;padding:9px 14px}button:hover{border-color:#6c8190;background:#233847}button:disabled{opacity:.45;cursor:wait}.primary{background:var(--mint);color:#152717;border-color:var(--mint);font-weight:bold}.primary:hover{background:#cef9aa}input,textarea{width:100%;background:#0b131b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:12px}input:focus,textarea:focus,button:focus-visible{outline:2px solid var(--mint);outline-offset:3px}input[type=checkbox]{width:auto}label{display:block;color:var(--muted);font-size:12px}h1,h2,p{margin:0}h2{font-size:17px}small{color:var(--muted)}a{color:var(--mint)}[hidden]{display:none!important}.shell{max-width:1480px;margin:auto;padding:28px 36px 18px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line);padding-bottom:24px}.brand{display:flex;align-items:center;gap:14px}.logo{width:48px;height:48px;border-radius:13px;background:var(--mint);color:#162419;display:grid;place-items:center;font:25px monospace}.brand h1{font:600 19px/1.5 monospace;letter-spacing:1px}.brand p{font-size:11px;color:var(--muted)}.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.pill{border:1px solid var(--line);padding:4px 12px;border-radius:99px;color:var(--muted);font:11px/1.8 monospace}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--mint);margin-left:7px;box-shadow:0 0 12px #b5ed8955}.intro{display:flex;justify-content:space-between;align-items:center;padding:28px 0 24px;gap:16px}.intro h2{font-size:24px}.intro p{color:var(--muted);font-size:12px;margin-top:6px}.workspace{display:grid;grid-template-columns:1fr 280px;gap:22px;align-items:start;direction:ltr}.main,.sidebar{direction:rtl;min-width:0}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;margin-bottom:20px}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 20px;border-bottom:1px solid var(--line)}.panelhead strong{font-size:13px}.eyebrow{font:10px monospace;color:var(--mint);letter-spacing:2px}.editor{padding:20px}.pathline{display:flex;align-items:center;gap:12px;margin-bottom:16px}.pathline label{white-space:nowrap}.pathline input{font:12px/1.8 monospace}.commandwrap{position:relative}.prompt{position:absolute;left:16px;top:11px;font:18px monospace;color:var(--mint)}#command{direction:ltr;text-align:left;resize:vertical;min-height:145px;font:14px/1.8 Consolas,monospace;padding-left:40px;tab-size:2}.editorfoot{display:flex;align-items:center;justify-content:space-between;margin-top:16px;gap:14px}.keys{font:10px/2 monospace;color:var(--muted);direction:ltr}kbd{font:inherit;border:1px solid #3d4a54;border-radius:4px;padding:2px 5px}.message{padding:12px 18px;border:1px solid #695032;background:#302617;color:#ffd79c;border-radius:10px;margin-bottom:20px}.outputtools{display:flex;flex-wrap:wrap;gap:8px;padding:12px 20px;border-bottom:1px solid var(--line)}.outputtools button{font-size:11px;padding:5px 10px}.outputtools input{font-size:11px;flex:1;min-width:120px;padding:7px 10px}.outputarea{background:#080e14;min-height:240px;max-height:65vh;overflow:auto}.outputarea pre{direction:ltr;text-align:left;font:13px/1.8 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin:0;padding:22px;color:#d6e7dd}.outputarea pre.nowrap{white-space:pre;overflow-wrap:normal}mark{background:#d8ed85;color:#102219}.empty{padding:50px 24px;text-align:center;color:var(--muted);font-size:12px}.empty b{display:block;color:#657787;font:28px monospace;margin-bottom:12px}.metrics{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font:10px/2 monospace;direction:ltr}.sidebar .panelhead{padding:15px}.sidebody{padding:12px}.sidebody input{font-size:11px;margin-bottom:10px}.commanditem{display:block;width:100%;text-align:right;padding:10px 11px;margin-bottom:6px;background:transparent;border-color:transparent}.commanditem:hover{background:#1b2a36;border-color:var(--line)}.commanditem span{display:block;color:var(--muted);font-size:10px}.commanditem code{display:block;direction:ltr;text-align:left;font:11px/1.8 Consolas,monospace;color:var(--blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sidetitle{font-size:11px;color:var(--muted);margin:10px 8px}.hint{font-size:11px;color:var(--muted);padding:0 6px;line-height:1.9}.autocomplete{position:absolute;left:0;right:0;top:100%;z-index:3;background:#172530;border:1px solid #516d7c;box-shadow:0 16px 32px #0008;border-radius:10px;padding:8px;max-height:260px;overflow:auto}.autocomplete button{width:100%;text-align:left;direction:ltr;display:flex;justify-content:space-between;gap:12px;border-color:transparent;background:transparent;font:12px monospace}.autocomplete small{font:10px Tahoma;direction:rtl}.historyrow{display:flex;gap:4px;align-items:center}.historyrow .commanditem{flex:1;min-width:0}.remove{padding:4px 8px;font:14px monospace;background:transparent}footer{border-top:1px solid var(--line);padding-top:18px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:10px}.login{max-width:420px;margin:10vh auto 14vh;padding:30px}.login h2{font-size:26px;margin-bottom:8px}.login p{font-size:12px;color:var(--muted);margin-bottom:28px}.login input{margin:10px 0 20px}.login button{width:100%}.toast{position:fixed;bottom:24px;left:24px;max-width:360px;padding:12px 20px;background:#233d2b;color:#d7f5c0;border:1px solid #688958;border-radius:10px;z-index:10}dialog{background:var(--panel);color:var(--text);border:1px solid #536d7d;border-radius:16px;width:min(560px,90vw);padding:24px}dialog::backdrop{background:#000b;backdrop-filter:blur(4px)}dialog input{margin:18px 0 10px}#palette-results{max-height:50vh;overflow:auto}.loading{color:var(--mint);font-size:12px}.mini{font-size:10px}.soft{color:var(--muted)}@media(max-width:1000px){.workspace{grid-template-columns:1fr 240px}.shell{padding:22px}.keys{display:none}}@media(max-width:740px){.shell{padding:16px}.workspace{display:flex;flex-direction:column}.main,.sidebar{width:100%}.top,.intro{align-items:flex-start}.intro h2{font-size:20px}.top .pill{display:none}.editor{padding:16px}.panelhead{padding:14px}.editorfoot{flex-wrap:wrap}.pathline{display:block}.pathline label{margin-bottom:6px}.brand h1{font-size:16px}.outputarea{max-height:50vh}.sidebar{display:grid;grid-template-columns:1fr}.login{margin:7vh auto}footer span{font-size:9px}}

.logo{direction:ltr}#suggestions{max-height:380px;overflow:auto;scrollbar-width:thin;scrollbar-color:#425b69 transparent}

.editor .file-list{max-height:310px;overflow:auto;margin:14px 0}.file-row,.session-row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:8px 0;border-bottom:1px solid var(--line)}.file-row a,.file-row button{min-width:0;overflow-wrap:anywhere;text-align:left;font:12px/1.8 Consolas,monospace;color:var(--blue);background:transparent;border:0;text-decoration:none}.file-row small{white-space:nowrap;font:10px monospace}.files-path{font:12px/1.8 monospace;margin-bottom:12px;overflow-wrap:anywhere}.upload-label{border:1px dashed #536977;border-radius:9px;padding:12px;margin:14px 0}.upload-label input{margin-top:10px}.session-row{font-size:11px;flex-wrap:wrap}.session-row button{font-size:10px}.toast{position:fixed;top:18px;right:18px;bottom:auto;left:auto;width:min(340px,calc(100vw - 36px));padding:10px 12px;display:flex;align-items:flex-start;gap:12px;font-size:12px;line-height:1.8;box-shadow:0 10px 30px #0006;border-radius:10px;animation:toast-in .18s ease-out}.toast span{flex:1;overflow-wrap:anywhere}.toast.error{background:#352022;border-color:#925255;color:#ffcccc}.toast.warning{background:#352c1c;border-color:#8d7746;color:#ffe0a1}.toast-close{padding:0 5px;color:inherit;background:transparent;border:0;font:20px monospace;line-height:1.4}.toast-close:hover{background:#ffffff12;border-color:transparent}@keyframes toast-in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}@media(prefers-reduced-motion:reduce){.toast{animation:none}}#history{max-height:320px;overflow:auto}#history-search{margin-bottom:10px}#server-history{margin:10px 0;font-size:10px}.commandwrap{z-index:2}.panel:has(.commandwrap){overflow:visible}.panel:has(.commandwrap) .panelhead{border-radius:14px 14px 0 0}
</style></head>
<body data-instance="<?=h(INSTANCE_ID)?>" data-message="<?=h($message)?>" data-message-kind="<?= $message !== '' && (!isset($code)||$code!==0) ? 'error' : 'success' ?>"><div class="shell">
<header class="top"><div class="brand"><div class="logo" aria-hidden="true">›_</div><div><h1 dir="ltr">HARBOR TERMINAL</h1><p>کنسول شخصی هاست · نسخهٔ ۱٫۱٫۰</p></div></div><div class="row"><span class="pill"><span class="dot"></span>HTTPS / ENCRYPTED</span><?php if (!empty($_SESSION['authenticated'])): ?><form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="logout"><button>خروج از نشست ↗</button></form><?php endif; ?></div></header>
<?php if (empty($_SESSION['authenticated'])): ?>
<main class="panel login"><p class="eyebrow">YOUR HOST. YOUR CONSOLE.</p><h2>به کنسولت وصل شو.</h2><p>رمز ترمینال را وارد کن تا فرمان‌ها با دسترسی حساب هاستت اجرا شوند.</p>
<?php if ($message !== ''): ?><div class="message" role="status"><?=h($message)?></div><?php endif; ?>
<form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="login"><label for="password">رمز ورود</label><input id="password" type="password" name="password" dir="ltr" required autocomplete="current-password" autofocus><button class="primary">ورود به ترمینال ←</button></form></main>
<?php else: ?>
<div class="intro"><div><p class="eyebrow">WORKSPACE / LIVE SESSION</p><h2>فرمان بعدی، دست توست.</h2><p>مسیر را انتخاب کن، فرمان را بنویس و نتیجه را همین‌جا ببین.</p></div><button type="button" id="palette-open">جست‌وجوی فرمان <kbd>Ctrl K</kbd></button></div>
<?php if ($message !== ''): ?><noscript><p class="hint"><?=h($message)?></p></noscript><?php endif; ?>
<?php if (!$available): ?><p class="hint">هاست توابع اجرای فرمان را غیرفعال کرده است؛ اجرای فرمان در این حساب در دسترس نیست.</p><?php endif; ?>
<div class="workspace"><main class="main">
<section class="panel"><div class="panelhead"><strong>ویرایشگر فرمان</strong><span class="eyebrow">COMMAND INPUT</span></div>
<form method="post" id="command-form" class="editor"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="run">
<div class="pathline"><label for="cwd">پوشهٔ کاری</label><input id="cwd" name="cwd" dir="ltr" value="<?=h($cwd)?>" required spellcheck="false"></div>
<label for="command" class="mini">فرمان · پیشنهادها با کلیک فقط در کادر قرار می‌گیرند</label>
<div class="commandwrap"><span class="prompt" aria-hidden="true">$</span><textarea id="command" name="command" dir="ltr" rows="4" maxlength="8192" required spellcheck="false" autocomplete="off" placeholder="pwd &amp;&amp; whoami &amp;&amp; ls -la"><?=h($command)?></textarea><div id="autocomplete" class="autocomplete" aria-label="پیشنهاد فرمان" hidden></div></div>
<div class="editorfoot"><div class="row"><button class="primary" id="run" <?=!$available ? 'disabled' : ''?>>اجرای فرمان ←</button><button type="button" id="save-command" title="افزودن فرمان به منتخب‌های همین تب">☆ ذخیرهٔ فرمان</button><button type="button" id="stop-command" hidden>درخواست توقف</button><span id="running" class="loading" role="status" hidden>در حال اجرای فرمان…</span></div><span class="keys"><kbd>Shift Enter</kbd> RUN · <kbd>↑ / ↓</kbd> HISTORY</span></div></form></section>
<section class="panel"><div class="panelhead"><strong>خروجی ترمینال</strong><div class="metrics"><span id="metric-exit">EXIT <?=isset($code) ? h((string)$code) : '—'?></span><span id="metric-duration"><?=isset($elapsed) ? h(number_format($elapsed, 2)) . ' s' : '— s'?></span><span id="metric-bytes"><?=h((string)strlen($output))?> B</span></div></div>
<div class="outputtools"><input id="output-search" type="search" placeholder="جست‌وجو در خروجی…" aria-label="جست‌وجو در خروجی"><button type="button" id="copy-output">کپی</button><button type="button" id="download-output">ذخیرهٔ TXT</button><button type="button" id="wrap-output" aria-pressed="true">شکستن خط: روشن</button><button type="button" id="clear-output">پاک‌کردن نما</button></div>
<div class="outputarea"><pre id="output" <?= $output === '' ? 'hidden' : '' ?>><?=h($output)?></pre><div id="empty-output" class="empty" <?= $output !== '' ? 'hidden' : '' ?>><b>›_</b>خروجی فرمان اینجا نمایش داده می‌شود.<br>برای شروع از پیشنهادهای کنار صفحه استفاده کن.</div></div></section>
<section class="panel"><div class="panelhead"><strong>مدیریت فایل</strong><div class="row"><button type="button" id="parent-folder">↑ پوشهٔ بالاتر</button><button type="button" id="refresh-files">تازه‌سازی</button></div></div><div class="editor"><p id="files-path" class="files-path" dir="ltr"></p><input id="file-search" type="search" placeholder="جست‌وجوی فایل…" aria-label="جست‌وجوی فایل"><div id="file-list" class="file-list"></div><label class="upload-label">آپلود فایل به پوشهٔ فعلی · حداکثر ۵ مگابایت<input id="upload-file" type="file"></label><p class="hint">فایل موجود بازنویسی نمی‌شود. برای دریافت فایل، روی نام آن بزن.</p></div></section>
<section class="panel"><div class="panelhead"><strong>وضعیت هاست و ورودها</strong><div class="row"><button type="button" id="host-diagnostics">بررسی هاست</button><button type="button" id="show-sessions">نشست‌های ورود</button></div></div><div class="editor"><p id="host-health" class="hint">خروجی زنده به نحوهٔ ارسال خروجی در هاست وابسته است؛ بعضی هاست‌ها آن را پس از پایان یکجا نمایش می‌دهند. توقف فرمان هم درخواست توقف شِل است و توقف همهٔ پردازش‌های فرزند تضمین نمی‌شود.</p><div id="sessions-panel" hidden><div id="sessions-list"></div><button type="button" id="revoke-others">پایان همهٔ ورودهای دیگر</button></div></div></section>
<p class="hint">هر اجرا یک شِل تازه است؛ برای تغییر پوشه، مسیر بالا را عوض کن. برنامه‌های تعاملی پشتیبانی نمی‌شوند. خروجی تا ۲۵۶ کیلوبایت و زمان اجرای زنده تا ۲۰ ثانیه است؛ توقف پردازش‌های فرزند تضمین نمی‌شود.</p>
</main><aside class="sidebar">
<section class="panel"><div class="panelhead"><strong>پیشنهاد فرمان</strong><span class="eyebrow">QUICK START</span></div><div class="sidebody"><input id="suggestion-search" type="search" placeholder="جست‌وجوی فرمان یا کاربرد…" aria-label="جست‌وجوی پیشنهادها"><div id="suggestions"></div></div></section>
<section class="panel"><div class="panelhead"><strong>منتخب‌های من</strong><span class="soft">☆</span></div><div id="favorites" class="sidebody"></div></section>
<section class="panel"><div class="panelhead"><strong>تاریخچهٔ مرورگر</strong><button type="button" id="clear-history" class="remove" aria-label="پاک‌کردن تاریخچه">×</button></div><div class="sidebody"><input id="history-search" type="search" placeholder="جست‌وجو در فرمان و مسیر…" aria-label="جست‌وجوی تاریخچه"><div class="row"><button type="button" id="history-up">↑ قبلی</button><button type="button" id="history-down">↓ بعدی</button></div><button type="button" id="server-history">دریافت تاریخچهٔ هاست</button><div id="history"></div></div></section>
<p class="hint">تاریخچه و منتخب‌ها فقط در همین مرورگر نگه داشته می‌شوند و قابل پاک‌کردن‌اند. فیلد رمز ورود ذخیره نمی‌شود.</p>
</aside></div>
<dialog id="palette"><div class="row"><h2>جست‌وجوی فرمان</h2><button type="button" id="palette-close">بستن · Esc</button></div><input id="palette-search" type="search" placeholder="نام فرمان یا کاری که می‌خواهی انجام دهی…" aria-label="جست‌وجوی فرمان"><div id="palette-results"></div><p class="hint">انتخاب فرمان فقط کادر را پر می‌کند؛ برای اجرا، دکمهٔ اجرا را بزن.</p></dialog>
<div id="toast" class="toast" role="status" hidden></div>
<script nonce="<?=h($scriptNonce)?>">
(() => {
  'use strict';
  const $=id=>document.getElementById(id), editor=$('command'), form=$('command-form');
  const csrf=form.querySelector('[name=csrf]').value, prefix='harbor:'+document.body.dataset.instance+':';
  const catalog=[['pwd','مسیر فعلی'],['whoami','نام کاربر هاست'],['ls -lah','فایل‌ها و اندازه‌ها'],['php -v','نسخهٔ PHP خط فرمان'],['php -m','ماژول‌های PHP'],['command -v php','مسیر PHP خط فرمان'],['df -h .','فضای دیسک پوشه'],['du -sh .','اندازهٔ پوشه'],['find . -maxdepth 1 -type f','فایل‌های این پوشه'],['date','زمان سرور'],['uname -sr','نسخهٔ سیستم‌عامل'],['id','شناسه و گروه‌ها']].map(([command,title])=>({command,title}));
  /* HARBOR_MODEL_BEGIN */
  function keyboardAction(event,value,start,end,historyIndex){
    if(event.isComposing)return null;
    if(event.key==='Enter'&&event.shiftKey&&!event.altKey)return 'run';
    if(event.key==='Enter'&&(event.ctrlKey||event.metaKey))return 'run';
    if(event.ctrlKey||event.metaKey||event.shiftKey)return null;
    if(event.key==='ArrowUp'&&(event.altKey||historyIndex>=0||!value.slice(0,start).includes('\n')))return 'previous';
    if(event.key==='ArrowDown'&&(event.altKey||historyIndex>=0||!value.slice(end).includes('\n')))return 'next';
    return null;
  }
  function moveHistory(index,direction,entries,current,draft){
    if(!entries.length)return {index:-1,text:current,draft:current};
    if(index===-1&&direction==='next')return {index:-1,text:current,draft:current};
    if(index===-1)draft=current;
    const next=direction==='previous'?Math.min(index+1,entries.length-1):Math.max(-1,index-1);
    return {index:next,text:next<0?draft:entries[next].command,draft};
  }
  function shellQuote(value){return /^[A-Za-z0-9_./-]+$/.test(value)?value:"'"+value.replaceAll("'","'\\''")+"'";}
  /* HARBOR_MODEL_END */
  function read(key){try{const raw=localStorage.getItem(prefix+key)??sessionStorage.getItem(prefix+key);const items=JSON.parse(raw||'[]');return Array.isArray(items)?items:[];}catch{return [];}}
  function normalizeHistory(items){return items.map(x=>typeof x==='string'?{command:x,cwd:'',at:0,code:null}:x).filter(x=>x&&typeof x.command==='string'&&x.command.length<=8192&&typeof(x.cwd??'')==='string').slice(0,80);}
  let history=normalizeHistory(read('history')),favorites=read('favorites').filter(x=>typeof x==='string'&&x.length<=8192).slice(0,12),historyIndex=-1,draft='',output=$('output').textContent;
  let files=[],parentPath='',toastTimer,busy=false,job=null,runNumber=0,contextSerial=0,draftCwd='';
  const runnable=!$('run').disabled;
  function store(key,value){try{localStorage.setItem(prefix+key,JSON.stringify(value));sessionStorage.removeItem(prefix+key);}catch{try{sessionStorage.setItem(prefix+key,JSON.stringify(value));}catch{toast('مرورگر اجازهٔ نگه‌داری تاریخچه را نداد.','warning');}}}
  function toast(message,kind='success',duration=kind==='error'?7000:3600){
    const node=$('toast');node.replaceChildren();node.className='toast '+kind;const text=document.createElement('span');text.textContent=message.length>240?message.slice(0,237)+'…':message;
    const close=document.createElement('button');close.type='button';close.className='toast-close';close.textContent='×';close.setAttribute('aria-label','بستن اعلان');close.addEventListener('click',()=>node.hidden=true);node.append(text,close);node.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>node.hidden=true,duration);
  }
  async function api(action,data={}){
    const url=new URL(location.href);url.search='';url.searchParams.set('api',action);
    let response;try{response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf,...data}),credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(12000)});}catch{throw new Error('ارتباط با هاست پاسخ نداد؛ اتصال را بررسی کنید.');}
    let result;try{result=await response.json();}catch{throw new Error('پاسخ هاست معتبر نیست؛ نسخهٔ PHP، نشست و ارتقای ترمینال را بررسی کنید.');}
    if(!response.ok)throw new Error(result.error||'درخواست انجام نشد.');return result;
  }
  function select(command,cwd=''){editor.value=command;if(cwd&&cwd!==$('cwd').value){$('cwd').value=cwd;void loadContext(true);}historyIndex=-1;$('autocomplete').hidden=true;editor.focus();editor.setSelectionRange(command.length,command.length);}
  function entryButton(entry,onChoose){const button=document.createElement('button');button.type='button';button.className='commanditem';const title=document.createElement('span');title.textContent=entry.title;const code=document.createElement('code');code.textContent=entry.command;button.append(title,code);button.addEventListener('click',()=>onChoose?onChoose():select(entry.command,entry.cwd));return button;}
  function search(query){const needle=query.trim().toLocaleLowerCase();return catalog.filter(x=>(x.command+' '+x.title).toLocaleLowerCase().includes(needle));}
  function renderSuggestions(){const found=search($('suggestion-search').value);$('suggestions').replaceChildren(...found.map(x=>entryButton(x)));if(!found.length)$('suggestions').textContent='پیشنهادی پیدا نشد.';}
  function renderHistory(){const query=$('history-search').value.trim().toLocaleLowerCase();const entries=history.filter(x=>(x.command+' '+x.cwd).toLocaleLowerCase().includes(query));$('history').replaceChildren(...entries.slice(0,12).map(x=>entryButton({...x,title:[x.cwd,x.at?new Date(x.at).toLocaleString('fa-IR'):'',x.code!==null&&x.code!==undefined?'کد '+x.code:''].filter(Boolean).join(' · ')})));if(!entries.length)$('history').textContent='فرمانی پیدا نشد.';}
  function renderFavorites(){const node=$('favorites');node.replaceChildren();for(const command of favorites){const row=document.createElement('div');row.className='historyrow';row.append(entryButton({command,title:'فرمان منتخب'}));const remove=document.createElement('button');remove.type='button';remove.className='remove';remove.textContent='×';remove.setAttribute('aria-label','حذف فرمان منتخب');remove.addEventListener('click',()=>{favorites=favorites.filter(x=>x!==command);store('favorites',favorites);renderFavorites();});row.append(remove);node.append(row);}if(!favorites.length)node.textContent='فرمانت را با ☆ ذخیره کن.';}
  function browseHistory(direction){if(!history.length){toast('هنوز فرمانی در تاریخچه نیست.','warning');return;}if(historyIndex===-1&&direction==='previous')draftCwd=$('cwd').value;const state=moveHistory(historyIndex,direction,history,editor.value,draft);historyIndex=state.index;draft=state.draft;editor.value=state.text;const cwd=historyIndex<0?draftCwd:history[historyIndex].cwd;if(cwd&&cwd!==$('cwd').value){$('cwd').value=cwd;void loadContext(true);}$('autocomplete').hidden=true;editor.focus();editor.setSelectionRange(state.text.length,state.text.length);}
  function addHistory(command,cwd,code=null,duration=null){const at=Date.now();history=[{command,cwd,at,code,duration},...history.filter(x=>x.command!==command||x.cwd!==cwd)].slice(0,80);store('history',history);historyIndex=-1;renderHistory();return at;}
  $('history-up').addEventListener('click',()=>browseHistory('previous'));$('history-down').addEventListener('click',()=>browseHistory('next'));$('history-search').addEventListener('input',renderHistory);
  $('save-command').addEventListener('click',()=>{const command=editor.value.trim();if(!command){toast('ابتدا فرمان را بنویس.','warning');return;}favorites=[command,...favorites.filter(x=>x!==command)].slice(0,12);store('favorites',favorites);renderFavorites();toast('فرمان در منتخب‌ها ذخیره شد.');});
  $('clear-history').addEventListener('click',async()=>{history=[];store('history',history);historyIndex=-1;renderHistory();try{await api('audit',{clear:true});toast('تاریخچهٔ مرورگر و هاست پاک شد.');}catch{toast('تاریخچهٔ مرورگر پاک شد؛ پاک‌کردن تاریخچهٔ هاست در دسترس نبود.','warning');}});
  $('server-history').addEventListener('click',async()=>{try{const data=await api('audit');const merged=[...history,...data.items.map(x=>({...x,at:x.at*1000}))].sort((a,b)=>(b.at??0)-(a.at??0));const seen=new Set();history=normalizeHistory(merged.filter(x=>{const key=x.command+'\n'+x.cwd;if(seen.has(key))return false;seen.add(key);return true;}));store('history',history);renderHistory();toast('تاریخچهٔ هاست دریافت شد.');}catch(error){toast(error.message,'error');}});
  function completionEntries(){const text=editor.value.slice(0,editor.selectionStart),match=text.match(/([^\s;&|<>]*)$/),token=match?.[1]??'';if(!token)return [];
    const start=text.length-token.length,first=!text.slice(0,start).trim();const options=[];
    if(editor.selectionStart===editor.value.length&&!/[\n;&|<>]/.test(text))for(const item of catalog)if(item.command.startsWith(text.trimStart())&&item.command!==text.trimStart())options.push({...item,value:item.command,start:0,end:editor.value.length});
    if(!token.includes("'")&&!token.includes('"')&&!token.includes('\\')){
      const prefix=token.startsWith('./')?'./':'';const part=prefix?token.slice(2):token;
      if(!part.includes('/'))for(const file of files)if(file.name.startsWith(part)&&(!file.name.startsWith('.')||part.startsWith('.'))){const name=prefix+file.name+(file.directory?'/':'');if(shellQuote(name)===token)continue;options.push({command:name,title:file.directory?'پوشهٔ همین مسیر':'فایل همین مسیر',value:shellQuote(name),start,end:editor.selectionStart});}
    }return options.slice(0,8);
  }
  function complete(item){editor.setRangeText(item.value,item.start,item.end,'end');historyIndex=-1;$('autocomplete').hidden=true;editor.focus();}
  function renderCompletions(){const items=completionEntries();$('autocomplete').replaceChildren(...items.map(x=>entryButton(x,()=>complete(x))));$('autocomplete').hidden=!items.length;return items;}
  editor.addEventListener('input',()=>{historyIndex=-1;renderCompletions();});
  editor.addEventListener('keydown',event=>{const action=keyboardAction(event,editor.value,editor.selectionStart,editor.selectionEnd,historyIndex);if(action==='run'){event.preventDefault();if(!busy&&runnable)form.requestSubmit();return;}if(action==='previous'||action==='next'){event.preventDefault();browseHistory(action);return;}if(event.key==='Tab'&&!event.shiftKey&&!event.ctrlKey&&!event.metaKey){const items=renderCompletions();if(items.length){event.preventDefault();complete(items[0]);}}});
  document.addEventListener('click',event=>{if(!event.target.closest('.commandwrap'))$('autocomplete').hidden=true;});
  function openPalette(){$('palette-search').value='';renderPalette();$('palette').showModal();$('palette-search').focus();}
  function renderPalette(){$('palette-results').replaceChildren(...search($('palette-search').value).map(x=>entryButton(x,()=>{select(x.command);$('palette').close();editor.focus();})));}
  $('palette-open').addEventListener('click',openPalette);$('palette-close').addEventListener('click',()=>$('palette').close());$('palette-search').addEventListener('input',renderPalette);
  document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();if(!$('palette').open)openPalette();}if(event.key==='Escape')$('autocomplete').hidden=true;});
  function renderOutput(){const pre=$('output'),query=$('output-search').value;pre.replaceChildren();if(!query){pre.textContent=output;}else{let from=0,at,count=0;while(count++<1500&&(at=output.indexOf(query,from))!==-1){pre.append(document.createTextNode(output.slice(from,at)));const mark=document.createElement('mark');mark.textContent=output.slice(at,at+query.length);pre.append(mark);from=at+query.length;}pre.append(document.createTextNode(output.slice(from)));}pre.hidden=!output;$('empty-output').hidden=!!output;}
  function appendOutput(text){output+=text;$('output').hidden=false;$('empty-output').hidden=true;$('output').append(document.createTextNode(text));}
  $('output-search').addEventListener('input',renderOutput);
  $('copy-output').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(output);toast('خروجی کپی شد.');}catch{toast('متن خروجی را انتخاب و کپی کن.','warning');}});
  $('download-output').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([output],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='harbor-output-'+Date.now()+'.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  $('wrap-output').addEventListener('click',()=>{const nowrap=$('output').classList.toggle('nowrap');$('wrap-output').textContent='شکستن خط: '+(nowrap?'خاموش':'روشن');$('wrap-output').setAttribute('aria-pressed',String(!nowrap));});
  $('clear-output').addEventListener('click',()=>{output='';$('output-search').value='';renderOutput();});
  function setBusy(value){busy=value;$('run').disabled=value||!runnable;$('running').hidden=!value;$('stop-command').hidden=!value;$('stop-command').disabled=false;$('output-search').disabled=value;}
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy||!runnable)return;const command=editor.value.trim(),cwd=$('cwd').value.trim();if(!command)return;
    const serial=++runNumber,at=addHistory(command,cwd);editor.value='';draft='';job=Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,'0')).join('');setBusy(true);output='';$('output-search').value='';renderOutput();$('autocomplete').hidden=true;$('metric-exit').textContent='EXIT …';$('metric-duration').textContent='… s';$('metric-bytes').textContent='0 B';
    let done=false;const started=Date.now();const decoders={stdout:new TextDecoder(),stderr:new TextDecoder()};const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),45000);
    const waiting=setTimeout(()=>{if(busy&&serial===runNumber)toast('هنوز منتظر خروجی هستیم؛ بعضی هاست‌ها خروجی را با تأخیر می‌فرستند.','warning',5000);},5000);
    function handle(line){if(!line.trim())return;const item=JSON.parse(line);if(item.type==='start'){$('stop-command').hidden=!item.stopAvailable;}
      if(item.type==='chunk'){const text=item.encoding==='base64'?decoders[item.stream??'stdout'].decode(Uint8Array.from(atob(item.data),x=>x.charCodeAt(0)),{stream:true}):item.data;appendOutput(text);$('metric-bytes').textContent=new TextEncoder().encode(output).length+' B';}
      if(item.type==='error')throw new Error(item.message);
      if(item.type==='done'){done=true;for(const decoder of Object.values(decoders)){const rest=decoder.decode();if(rest)appendOutput(rest);}$('metric-exit').textContent='EXIT '+item.code;$('metric-duration').textContent=item.duration+' s';$('metric-bytes').textContent=item.bytes+' B';history=history.map(x=>x.at===at?{...x,code:item.code,duration:item.duration}:x);store('history',history);renderHistory();
        const reason=item.reason==='complete'?(item.code===0?'فرمان با موفقیت اجرا شد.':'فرمان با کد '+item.code+' پایان یافت.'):item.reason==='stopped'?'درخواست توقف اعمال شد؛ توقف همهٔ پردازش‌های فرزند تضمین نمی‌شود.':item.reason==='time_limit'?'مهلت اجرای فرمان به پایان رسید.':'حد خروجی یا ارتباط به پایان رسید.';
        toast(reason,item.reason==='complete'?(item.code===0?'success':'error'):'warning');}
    }
    try{
      const url=new URL(location.href);url.search='';url.searchParams.set('api','stream');
      const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf,command,cwd,job}),credentials:'same-origin',cache:'no-store',signal:controller.signal});
      if(!response.ok){let message='اجرای فرمان پذیرفته نشد.';try{message=(await response.json()).error||message;}catch{}throw new Error(message);}
      if(!response.body||!(response.headers.get('content-type')||'').includes('application/x-ndjson'))throw new Error('قابلیت اجرای زنده در این فایل فعال نیست؛ ترمینال روی هاست را ارتقا بده.');
      const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';while(true){const chunk=await reader.read();if(chunk.done){buffer+=decoder.decode();break;}buffer+=decoder.decode(chunk.value,{stream:true});let newline;while((newline=buffer.indexOf('\n'))>=0){handle(buffer.slice(0,newline));buffer=buffer.slice(newline+1);}}if(buffer.trim())handle(buffer);if(!done)throw new Error('ارتباط قبل از دریافت نتیجهٔ نهایی قطع شد؛ نتیجهٔ اجرا نامشخص است.');
    }catch(error){const message=error.name==='AbortError'?'پاسخ اجرا دریافت نشد؛ فرمان ممکن است روی هاست هنوز در حال اجرا باشد.':error.message;toast(message,'error');appendOutput((output?'\n':'')+'[Harbor] '+message+'\n');$('metric-exit').textContent='EXIT —';$('metric-bytes').textContent=new TextEncoder().encode(output).length+' B';$('metric-duration').textContent=((Date.now()-started)/1000).toFixed(2)+' s';}
    finally{clearTimeout(timer);clearTimeout(waiting);setBusy(false);job=null;renderOutput();void loadContext(true);}
  });
  $('stop-command').addEventListener('click',async()=>{if(!job)return;$('stop-command').disabled=true;try{await api('stop',{job});toast('درخواست توقف ارسال شد.','warning');}catch(error){toast(error.message,'error');$('stop-command').disabled=false;}});
  function renderFiles(){const query=$('file-search').value.toLocaleLowerCase();$('file-list').replaceChildren();for(const file of files.filter(x=>x.name.toLocaleLowerCase().includes(query))){const row=document.createElement('div');row.className='file-row';const name=document.createElement(file.directory?'button':'a');name.textContent=(file.directory?'▸ ':'')+file.name;const path=$('cwd').value.replace(/[\\/]$/,'')+'/'+file.name;if(file.directory){name.type='button';name.addEventListener('click',()=>{$('cwd').value=path;void loadContext();});}else{const url=new URL(location.href);url.search='';url.searchParams.set('api','download');url.searchParams.set('path',path);name.href=url;name.textContent+=' ↓';}const size=document.createElement('small');size.textContent=file.directory?'پوشه':new Intl.NumberFormat('fa-IR').format(file.size)+' B';row.append(name,size);$('file-list').append(row);}if(!files.length)$('file-list').textContent='پوشه خالی است.';}
  async function loadContext(quiet=false){const serial=++contextSerial,requested=$('cwd').value;try{const data=await api('context',{cwd:requested});if(serial!==contextSerial||$('cwd').value!==requested)return;files=data.items;parentPath=data.parent;$('cwd').value=data.cwd;$('files-path').textContent=data.cwd;$('parent-folder').disabled=data.parent===data.cwd;renderFiles();if(!quiet)toast(data.truncated?'فهرست به ۳۰۰ مورد محدود شد.':'پوشه خوانده شد.',data.truncated?'warning':'success');}catch(error){if(serial!==contextSerial)return;files=[];if(!quiet)toast(error.message,'error');}}
  $('refresh-files').addEventListener('click',()=>void loadContext());$('cwd').addEventListener('change',()=>void loadContext(true));$('file-search').addEventListener('input',renderFiles);$('parent-folder').addEventListener('click',()=>{if(parentPath){$('cwd').value=parentPath;void loadContext();}});
  $('upload-file').addEventListener('change',async()=>{const file=$('upload-file').files[0];if(!file)return;if(file.size>5242880){toast('حداکثر اندازهٔ آپلود ۵ مگابایت است.','error');return;}const body=new FormData();body.set('csrf',csrf);body.set('cwd',$('cwd').value);body.set('file',file,file.name);try{const url=new URL(location.href);url.search='';url.searchParams.set('api','upload');const response=await fetch(url,{method:'POST',body,credentials:'same-origin',signal:AbortSignal.timeout(30000)});const data=await response.json();if(!response.ok)throw new Error(data.error||'آپلود انجام نشد.');toast('فایل آپلود شد.');await loadContext(true);}catch(error){toast(error.message,'error');}finally{$('upload-file').value='';}});
  $('show-sessions').addEventListener('click',async()=>{try{const data=await api('sessions');$('sessions-list').replaceChildren();for(const entry of data.items){const row=document.createElement('div');row.className='session-row';const description=document.createElement('span');description.textContent=(entry.current?'این مرورگر · ':'')+entry.ip+' · '+new Date(entry.last*1000).toLocaleString('fa-IR');const button=document.createElement('button');button.type='button';button.textContent='پایان نشست';button.disabled=entry.current;button.addEventListener('click',async()=>{try{await api('revoke',{target:entry.id});row.remove();toast('نشست پایان یافت.');}catch(error){toast(error.message,'error');}});row.append(description,button);$('sessions-list').append(row);}$('sessions-panel').hidden=false;}catch(error){toast(error.message,'error');}});
  $('revoke-others').addEventListener('click',async()=>{try{await api('revoke',{target:'others'});$('show-sessions').click();toast('ورودهای دیگر باطل شدند.');}catch(error){toast(error.message,'error');}});
  $('host-diagnostics').addEventListener('click',async()=>{try{const url=new URL(location.href);url.search='';url.searchParams.set('api','info');const data=await(await fetch(url,{cache:'no-store',credentials:'same-origin'})).json();$('host-health').textContent='PHP '+data.php+' · ترمینال '+data.version+' · اجرای فرمان '+(data.commands?'فعال':'بسته')+' · ذخیرهٔ خصوصی '+(data.features?.privateStorage?'فعال':'در دسترس نیست');toast('وضعیت هاست بررسی شد.');}catch{toast('پاسخ معتبر از هاست دریافت نشد.','error');}});
  renderSuggestions();renderFavorites();renderHistory();store('history',history);void loadContext(true);
  if(document.body.dataset.message)toast(document.body.dataset.message,document.body.dataset.messageKind||'success');
})();

</script>
<?php endif; ?>
<footer><span dir="ltr">HARBOR / YOUR PERSONAL HOST CONSOLE</span><span>انقضای نشست: ۱۵ دقیقه بی‌کاری · مدیریت رمز و اتصال از تنظیمات افزونه</span></footer></div></body></html>

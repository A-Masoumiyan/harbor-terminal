<?php
declare(strict_types=1);
// Harbor Terminal 1.0.1 | PHP 8.1+ | Deploy only on your own hosting account.
const INSTANCE_ID = '__INSTANCE_ID__';
// HARBOR_AUTH_BEGIN
const AUTH_SALT = '__AUTH_SALT__';
const AUTH_VERIFIER = '__AUTH_VERIFIER__';
// HARBOR_AUTH_END
const AUTH_ITERATIONS = 600000;
const ALLOWED_IP = ''; // Optional fixed public IP; no proxy headers are trusted.

ini_set('display_errors', '0');
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
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
// A public identity probe contains no password, hash, account path or session information.
$api = isset($_GET['api']) && is_string($_GET['api']) ? $_GET['api'] : '';
if ($api === 'info' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    jsonReply(200, ['product' => 'harbor-terminal', 'id' => INSTANCE_ID, 'version' => '1.0.1', 'commands' => commandsAvailable()]);
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
    if (!hash_equals(INSTANCE_ID, $input['id']) || !validPassword($input['current_password'])) {
        usleep(800000); jsonReply(403, ['error' => 'رمز فعلی اشتباه است.']);
    }
    $new = $input['new_password'];
    if (!preg_match('//u', $new) || preg_match_all('/./us', $new) < 16 || strlen($new) > 256) {
        jsonReply(400, ['error' => 'رمز جدید باید حداقل ۱۶ نویسه و حداکثر ۲۵۶ بایت باشد.']);
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
if ($api !== '') jsonReply(404, ['error' => 'Unknown endpoint.']);
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
$message = ''; $output = ''; $command = ''; $cwd = $_SESSION['cwd'] ?? __DIR__;
$available = commandsAvailable();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], field('csrf'))) { http_response_code(403); exit('درخواست نامعتبر است. صفحه را دوباره باز کنید.'); }
    $action = field('action');
    if ($action === 'login') {
        if (validPassword(field('password'))) {
            session_regenerate_id(true); $_SESSION['authenticated'] = true;
            $_SESSION['fingerprint'] = authConfig()['verifier']; $_SESSION['csrf'] = bin2hex(random_bytes(32));
        } else { usleep(800000); $message = 'رمز ورود اشتباه است.'; }
    } elseif (!empty($_SESSION['authenticated']) && $action === 'logout') {
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
                $closed = proc_close($process); $code = $state['exitcode'] >= 0 ? $state['exitcode'] : $closed;
                $message = $stopped ? 'حد زمان یا خروجی رسید؛ توقف تمام پردازش‌های فرزند تضمین نمی‌شود.' : 'کد پایان: ' . $code;
            }
        }
    }
}
if (!empty($_SESSION['authenticated'])) $_SESSION['last'] = time();
?>
<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbor Terminal</title>
<style>body{background:#111820;color:#f0f2ec;font:15px/1.9 Tahoma,sans-serif;max-width:980px;margin:40px auto;padding:24px}h1{color:#bde989}input,textarea,button{box-sizing:border-box;font:inherit;padding:12px;border-radius:8px;border:1px solid #506470}input,textarea{width:100%;background:#19242e;color:#fff;margin:10px 0 20px}button{cursor:pointer;background:#bde989;color:#192b15}pre{direction:ltr;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;background:#080e13;padding:20px;min-height:120px}.message{color:#ffd58a}label{display:block}small{color:#b0c0c7}</style>
<h1 dir="ltr">Harbor Terminal</h1>
<?php if ($message !== ''): ?><p class="message"><?=h($message)?></p><?php endif; ?>
<?php if (empty($_SESSION['authenticated'])): ?>
<form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="login">
<label>رمز ورود<input type="password" name="password" required autocomplete="current-password"></label><button>ورود</button></form>
<?php else: ?>
<p>هر فرمان در شِل تازه اجرا می‌شود؛ پوشه را از فیلد مسیر تغییر دهید. برنامه‌های تعاملی و سرویس‌های طولانی پشتیبانی نمی‌شوند.</p>
<?php if (!$available): ?><p class="message">هاست توابع اجرای فرمان را غیرفعال کرده است.</p><?php endif; ?>
<form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="run">
<label>مسیر پوشه<input name="cwd" dir="ltr" value="<?=h($cwd)?>" required></label>
<label>فرمان<textarea name="command" dir="ltr" rows="3" required placeholder="pwd &amp;&amp; whoami &amp;&amp; ls -la"><?=h($command)?></textarea></label>
<button <?=!$available ? 'disabled' : ''?>>اجرای فرمان</button></form><pre><?=h($output)?></pre>
<form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="logout"><button>خروج</button></form>
<?php endif; ?><p><small>برای مدیریت اتصال و تغییر رمز، روی آیکون افزونه راست‌کلیک و Options / گزینه‌ها را باز کنید.</small></p></html>

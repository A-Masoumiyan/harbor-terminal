<?php
declare(strict_types=1);
// Harbor Terminal 1.0.2 | PHP 8.1+ | Deploy only on your own hosting account.
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
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$scriptNonce'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
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
    jsonReply(200, ['product' => 'harbor-terminal', 'id' => INSTANCE_ID, 'version' => '1.0.2', 'minimum_password_characters' => 4, 'commands' => commandsAvailable()]);
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
$code = null; $elapsed = null;
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
                $closed = proc_close($process); $elapsed = microtime(true) - $started; $code = $state['exitcode'] >= 0 ? $state['exitcode'] : $closed;
                $message = $stopped ? 'حد زمان یا خروجی رسید؛ توقف تمام پردازش‌های فرزند تضمین نمی‌شود.' : 'کد پایان: ' . $code;
            }
        }
    }
}
if (!empty($_SESSION['authenticated'])) $_SESSION['last'] = time();
?>
<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Harbor Terminal</title>
<style>
:root{color-scheme:dark;--bg:#0c1117;--panel:#121c25;--line:#273742;--muted:#9bacba;--text:#e7eef4;--mint:#b5ed89;--blue:#8fc9ff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.9 Tahoma,Arial,sans-serif}button,input,textarea{font:inherit}button,a{touch-action:manipulation}button{cursor:pointer;border:1px solid var(--line);background:#1b2a36;color:var(--text);border-radius:9px;padding:9px 14px}button:hover{border-color:#6c8190;background:#233847}button:disabled{opacity:.45;cursor:wait}.primary{background:var(--mint);color:#152717;border-color:var(--mint);font-weight:bold}.primary:hover{background:#cef9aa}input,textarea{width:100%;background:#0b131b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:12px}input:focus,textarea:focus,button:focus-visible{outline:2px solid var(--mint);outline-offset:3px}input[type=checkbox]{width:auto}label{display:block;color:var(--muted);font-size:12px}h1,h2,p{margin:0}h2{font-size:17px}small{color:var(--muted)}a{color:var(--mint)}[hidden]{display:none!important}.shell{max-width:1480px;margin:auto;padding:28px 36px 18px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line);padding-bottom:24px}.brand{display:flex;align-items:center;gap:14px}.logo{width:48px;height:48px;border-radius:13px;background:var(--mint);color:#162419;display:grid;place-items:center;font:25px monospace}.brand h1{font:600 19px/1.5 monospace;letter-spacing:1px}.brand p{font-size:11px;color:var(--muted)}.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.pill{border:1px solid var(--line);padding:4px 12px;border-radius:99px;color:var(--muted);font:11px/1.8 monospace}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--mint);margin-left:7px;box-shadow:0 0 12px #b5ed8955}.intro{display:flex;justify-content:space-between;align-items:center;padding:28px 0 24px;gap:16px}.intro h2{font-size:24px}.intro p{color:var(--muted);font-size:12px;margin-top:6px}.workspace{display:grid;grid-template-columns:1fr 280px;gap:22px;align-items:start;direction:ltr}.main,.sidebar{direction:rtl;min-width:0}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;margin-bottom:20px}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 20px;border-bottom:1px solid var(--line)}.panelhead strong{font-size:13px}.eyebrow{font:10px monospace;color:var(--mint);letter-spacing:2px}.editor{padding:20px}.pathline{display:flex;align-items:center;gap:12px;margin-bottom:16px}.pathline label{white-space:nowrap}.pathline input{font:12px/1.8 monospace}.commandwrap{position:relative}.prompt{position:absolute;left:16px;top:11px;font:18px monospace;color:var(--mint)}#command{direction:ltr;text-align:left;resize:vertical;min-height:145px;font:14px/1.8 Consolas,monospace;padding-left:40px;tab-size:2}.editorfoot{display:flex;align-items:center;justify-content:space-between;margin-top:16px;gap:14px}.keys{font:10px/2 monospace;color:var(--muted);direction:ltr}kbd{font:inherit;border:1px solid #3d4a54;border-radius:4px;padding:2px 5px}.message{padding:12px 18px;border:1px solid #695032;background:#302617;color:#ffd79c;border-radius:10px;margin-bottom:20px}.outputtools{display:flex;flex-wrap:wrap;gap:8px;padding:12px 20px;border-bottom:1px solid var(--line)}.outputtools button{font-size:11px;padding:5px 10px}.outputtools input{font-size:11px;flex:1;min-width:120px;padding:7px 10px}.outputarea{background:#080e14;min-height:240px;max-height:65vh;overflow:auto}.outputarea pre{direction:ltr;text-align:left;font:13px/1.8 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin:0;padding:22px;color:#d6e7dd}.outputarea pre.nowrap{white-space:pre;overflow-wrap:normal}mark{background:#d8ed85;color:#102219}.empty{padding:50px 24px;text-align:center;color:var(--muted);font-size:12px}.empty b{display:block;color:#657787;font:28px monospace;margin-bottom:12px}.metrics{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font:10px/2 monospace;direction:ltr}.sidebar .panelhead{padding:15px}.sidebody{padding:12px}.sidebody input{font-size:11px;margin-bottom:10px}.commanditem{display:block;width:100%;text-align:right;padding:10px 11px;margin-bottom:6px;background:transparent;border-color:transparent}.commanditem:hover{background:#1b2a36;border-color:var(--line)}.commanditem span{display:block;color:var(--muted);font-size:10px}.commanditem code{display:block;direction:ltr;text-align:left;font:11px/1.8 Consolas,monospace;color:var(--blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sidetitle{font-size:11px;color:var(--muted);margin:10px 8px}.hint{font-size:11px;color:var(--muted);padding:0 6px;line-height:1.9}.autocomplete{position:absolute;left:0;right:0;top:100%;z-index:3;background:#172530;border:1px solid #516d7c;box-shadow:0 16px 32px #0008;border-radius:10px;padding:8px;max-height:260px;overflow:auto}.autocomplete button{width:100%;text-align:left;direction:ltr;display:flex;justify-content:space-between;gap:12px;border-color:transparent;background:transparent;font:12px monospace}.autocomplete small{font:10px Tahoma;direction:rtl}.historyrow{display:flex;gap:4px;align-items:center}.historyrow .commanditem{flex:1;min-width:0}.remove{padding:4px 8px;font:14px monospace;background:transparent}footer{border-top:1px solid var(--line);padding-top:18px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:10px}.login{max-width:420px;margin:10vh auto 14vh;padding:30px}.login h2{font-size:26px;margin-bottom:8px}.login p{font-size:12px;color:var(--muted);margin-bottom:28px}.login input{margin:10px 0 20px}.login button{width:100%}.toast{position:fixed;bottom:24px;left:24px;max-width:360px;padding:12px 20px;background:#233d2b;color:#d7f5c0;border:1px solid #688958;border-radius:10px;z-index:10}dialog{background:var(--panel);color:var(--text);border:1px solid #536d7d;border-radius:16px;width:min(560px,90vw);padding:24px}dialog::backdrop{background:#000b;backdrop-filter:blur(4px)}dialog input{margin:18px 0 10px}#palette-results{max-height:50vh;overflow:auto}.loading{color:var(--mint);font-size:12px}.mini{font-size:10px}.soft{color:var(--muted)}@media(max-width:1000px){.workspace{grid-template-columns:1fr 240px}.shell{padding:22px}.keys{display:none}}@media(max-width:740px){.shell{padding:16px}.workspace{display:flex;flex-direction:column}.main,.sidebar{width:100%}.top,.intro{align-items:flex-start}.intro h2{font-size:20px}.top .pill{display:none}.editor{padding:16px}.panelhead{padding:14px}.editorfoot{flex-wrap:wrap}.pathline{display:block}.pathline label{margin-bottom:6px}.brand h1{font-size:16px}.outputarea{max-height:50vh}.sidebar{display:grid;grid-template-columns:1fr}.login{margin:7vh auto}footer span{font-size:9px}}

.logo{direction:ltr}#suggestions{max-height:380px;overflow:auto;scrollbar-width:thin;scrollbar-color:#425b69 transparent}
</style></head>
<body data-instance="<?=h(INSTANCE_ID)?>"><div class="shell">
<header class="top"><div class="brand"><div class="logo" aria-hidden="true">›_</div><div><h1 dir="ltr">HARBOR TERMINAL</h1><p>کنسول شخصی هاست · نسخهٔ ۱٫۰٫۲</p></div></div><div class="row"><span class="pill"><span class="dot"></span>HTTPS / ENCRYPTED</span><?php if (!empty($_SESSION['authenticated'])): ?><form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="logout"><button>خروج از نشست ↗</button></form><?php endif; ?></div></header>
<?php if (empty($_SESSION['authenticated'])): ?>
<main class="panel login"><p class="eyebrow">YOUR HOST. YOUR CONSOLE.</p><h2>به کنسولت وصل شو.</h2><p>رمز ترمینال را وارد کن تا فرمان‌ها با دسترسی حساب هاستت اجرا شوند.</p>
<?php if ($message !== ''): ?><div class="message" role="status"><?=h($message)?></div><?php endif; ?>
<form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="login"><label for="password">رمز ورود</label><input id="password" type="password" name="password" dir="ltr" required autocomplete="current-password" autofocus><button class="primary">ورود به ترمینال ←</button></form></main>
<?php else: ?>
<div class="intro"><div><p class="eyebrow">WORKSPACE / LIVE SESSION</p><h2>فرمان بعدی، دست توست.</h2><p>مسیر را انتخاب کن، فرمان را بنویس و نتیجه را همین‌جا ببین.</p></div><button type="button" id="palette-open">جست‌وجوی فرمان <kbd>Ctrl K</kbd></button></div>
<?php if ($message !== ''): ?><div class="message" role="status"><?=h($message)?></div><?php endif; ?>
<?php if (!$available): ?><div class="message">هاست توابع اجرای فرمان را غیرفعال کرده است.</div><?php endif; ?>
<div class="workspace"><main class="main">
<section class="panel"><div class="panelhead"><strong>ویرایشگر فرمان</strong><span class="eyebrow">COMMAND INPUT</span></div>
<form method="post" id="command-form" class="editor"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><input type="hidden" name="action" value="run">
<div class="pathline"><label for="cwd">پوشهٔ کاری</label><input id="cwd" name="cwd" dir="ltr" value="<?=h($cwd)?>" required spellcheck="false"></div>
<label for="command" class="mini">فرمان · پیشنهادها با کلیک فقط در کادر قرار می‌گیرند</label>
<div class="commandwrap"><span class="prompt" aria-hidden="true">$</span><textarea id="command" name="command" dir="ltr" rows="4" maxlength="8192" required spellcheck="false" autocomplete="off" placeholder="pwd &amp;&amp; whoami &amp;&amp; ls -la"><?=h($command)?></textarea><div id="autocomplete" class="autocomplete" aria-label="پیشنهاد فرمان" hidden></div></div>
<div class="editorfoot"><div class="row"><button class="primary" id="run" <?=!$available ? 'disabled' : ''?>>اجرای فرمان ←</button><button type="button" id="save-command" title="افزودن فرمان به منتخب‌های همین تب">☆ ذخیرهٔ فرمان</button><span id="running" class="loading" role="status" hidden>در حال اجرای فرمان…</span></div><span class="keys"><kbd>Ctrl Enter</kbd> RUN · <kbd>Alt ↑ / ↓</kbd> HISTORY</span></div></form></section>
<section class="panel"><div class="panelhead"><strong>خروجی ترمینال</strong><div class="metrics"><span>EXIT <?=isset($code) ? h((string)$code) : '—'?></span><span><?=isset($elapsed) ? h(number_format($elapsed, 2)) . ' s' : '— s'?></span><span><?=h((string)strlen($output))?> B</span></div></div>
<div class="outputtools"><input id="output-search" type="search" placeholder="جست‌وجو در خروجی…" aria-label="جست‌وجو در خروجی"><button type="button" id="copy-output">کپی</button><button type="button" id="download-output">ذخیرهٔ TXT</button><button type="button" id="wrap-output" aria-pressed="true">شکستن خط: روشن</button><button type="button" id="clear-output">پاک‌کردن نما</button></div>
<div class="outputarea"><pre id="output" <?= $output === '' ? 'hidden' : '' ?>><?=h($output)?></pre><div id="empty-output" class="empty" <?= $output !== '' ? 'hidden' : '' ?>><b>›_</b>خروجی فرمان اینجا نمایش داده می‌شود.<br>برای شروع از پیشنهادهای کنار صفحه استفاده کن.</div></div></section>
<p class="hint">هر اجرا یک شِل تازه است؛ برای تغییر پوشه، مسیر بالا را عوض کن. برنامه‌های تعاملی پشتیبانی نمی‌شوند. خروجی تا ۲۵۶ کیلوبایت و زمان هدف تا ۱۰ ثانیه است؛ توقف پردازش‌های فرزند تضمین نمی‌شود.</p>
</main><aside class="sidebar">
<section class="panel"><div class="panelhead"><strong>پیشنهاد فرمان</strong><span class="eyebrow">QUICK START</span></div><div class="sidebody"><input id="suggestion-search" type="search" placeholder="جست‌وجوی فرمان یا کاربرد…" aria-label="جست‌وجوی پیشنهادها"><div id="suggestions"></div></div></section>
<section class="panel"><div class="panelhead"><strong>منتخب‌های من</strong><span class="soft">☆</span></div><div id="favorites" class="sidebody"></div></section>
<section class="panel"><div class="panelhead"><strong>تاریخچهٔ این تب</strong><button type="button" id="clear-history" class="remove" aria-label="پاک‌کردن تاریخچه">×</button></div><div id="history" class="sidebody"></div></section>
<p class="hint">تاریخچه و منتخب‌ها فقط در همین تب مرورگر نگه داشته می‌شوند. رمز ورود در آن‌ها ذخیره نمی‌شود.</p>
</aside></div>
<dialog id="palette"><div class="row"><h2>جست‌وجوی فرمان</h2><button type="button" id="palette-close">بستن · Esc</button></div><input id="palette-search" type="search" placeholder="نام فرمان یا کاری که می‌خواهی انجام دهی…" aria-label="جست‌وجوی فرمان"><div id="palette-results"></div><p class="hint">انتخاب فرمان فقط کادر را پر می‌کند؛ برای اجرا، دکمهٔ اجرا را بزن.</p></dialog>
<div id="toast" class="toast" role="status" hidden></div>
<script nonce="<?=h($scriptNonce)?>">
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const catalog = [
    ['pwd','مسیر فعلی','فایل‌ها'],['whoami','نام کاربر هاست','حساب'],['ls -lah','فهرست فایل‌ها و اندازه‌ها','فایل‌ها'],
    ['php -v','نسخهٔ PHP خط فرمان','PHP'],['php -m','ماژول‌های PHP خط فرمان','PHP'],['command -v php','مسیر PHP خط فرمان','PHP'],
    ['df -h .','فضای دیسک این پوشه','فضا'],['du -sh .','اندازهٔ پوشهٔ فعلی','فضا'],['find . -maxdepth 1 -type f','فایل‌های سطح اول پوشه','فایل‌ها'],
    ['date','زمان سرور','سرور'],['uname -sr','نام و نسخهٔ سیستم‌عامل','سرور'],['id','شناسه و گروه‌های کاربر','حساب']
  ].map(([command,title,group])=>({command,title,group}));
  const prefix = 'harbor:' + document.body.dataset.instance + ':';
  const read = key => { try { const data=JSON.parse(sessionStorage.getItem(prefix+key)||'[]'); return Array.isArray(data)?data.filter(x=>typeof x==='string'&&x.length<=8192).slice(0,40):[]; } catch { return []; } };
  let history=read('history'), favorites=read('favorites'), historyIndex=-1, draft='', output=$('output').textContent, toastTimer;
  function store(key,value){try{sessionStorage.setItem(prefix+key,JSON.stringify(value));}catch{toast('مرورگر ذخیرهٔ تاریخچهٔ این تب را اجازه نداد.');}}
  function toast(text){$('toast').textContent=text;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,3500);}
  function select(command){$('command').value=command;$('autocomplete').hidden=true;historyIndex=-1;$('command').focus();$('command').setSelectionRange(command.length,command.length);}
  function item(entry, closePalette=false){const button=document.createElement('button');button.type='button';button.className='commanditem';const title=document.createElement('span');title.textContent=entry.title;const code=document.createElement('code');code.textContent=entry.command;button.append(title,code);button.addEventListener('click',()=>{select(entry.command);if(closePalette)$('palette').close();});return button;}
  function search(query){const needle=query.trim().toLocaleLowerCase();return catalog.filter(x=>(x.command+' '+x.title+' '+x.group).toLocaleLowerCase().includes(needle));}
  function renderSuggestions(){const found=search($('suggestion-search').value);$('suggestions').replaceChildren(...found.map(x=>item(x)));if(!found.length)$('suggestions').textContent='فرمانی پیدا نشد.';}
  function renderList(name,values){const container=$(name);container.replaceChildren();if(!values.length){const hint=document.createElement('p');hint.className='hint';hint.textContent=name==='history'?'هنوز فرمانی ارسال نشده است.':'فرمانت را با ☆ ذخیره کن.';container.append(hint);return;}values.slice(0,name==='history'?8:12).forEach((command,index)=>{const row=document.createElement('div');row.className='historyrow';row.append(item({command,title:name==='history'?'فرمان قبلی':'فرمان منتخب'}));if(name==='favorites'){const remove=document.createElement('button');remove.type='button';remove.className='remove';remove.textContent='×';remove.setAttribute('aria-label','حذف فرمان منتخب');remove.addEventListener('click',()=>{favorites.splice(index,1);store('favorites',favorites);renderList('favorites',favorites);});row.append(remove);}container.append(row);});}
  $('suggestion-search').addEventListener('input',renderSuggestions);
  $('save-command').addEventListener('click',()=>{const command=$('command').value.trim();if(!command){toast('ابتدا فرمان را بنویس.');return;}favorites=[command,...favorites.filter(x=>x!==command)].slice(0,12);store('favorites',favorites);renderList('favorites',favorites);toast('فرمان در منتخب‌های همین تب ذخیره شد.');});
  $('clear-history').addEventListener('click',()=>{history=[];store('history',history);historyIndex=-1;renderList('history',history);});
  $('command-form').addEventListener('submit',()=>{const command=$('command').value.trim();if(command){history=[command,...history.filter(x=>x!==command)].slice(0,40);store('history',history);}$('run').disabled=true;$('running').hidden=false;$('autocomplete').hidden=true;});
  window.addEventListener('pageshow',()=>{$('run').disabled=<?= $available ? 'false' : 'true' ?>;$('running').hidden=true;});
  $('command').addEventListener('input',()=>{historyIndex=-1;const value=$('command').value.trim();const found=value.length>=2&&!value.includes('\n')?catalog.filter(x=>x.command.startsWith(value)&&x.command!==value).slice(0,5):[];$('autocomplete').replaceChildren(...found.map(entry=>{const button=document.createElement('button');button.type='button';const code=document.createElement('span');code.textContent=entry.command;const title=document.createElement('small');title.textContent=entry.title;button.append(code,title);button.addEventListener('click',()=>select(entry.command));return button;}));$('autocomplete').hidden=!found.length;});
  document.addEventListener('click',event=>{if(!event.target.closest('.commandwrap'))$('autocomplete').hidden=true;});
  function openPalette(){$('palette-search').value='';renderPalette();$('palette').showModal();$('palette-search').focus();}
  function renderPalette(){$('palette-results').replaceChildren(...search($('palette-search').value).map(x=>item(x,true)));}
  $('palette-open').addEventListener('click',openPalette);$('palette-close').addEventListener('click',()=>$('palette').close());$('palette-search').addEventListener('input',renderPalette);
  document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();if(!$('palette').open)openPalette();}if(event.key==='Escape')$('autocomplete').hidden=true;});
  $('command').addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();if(!$('run').disabled)$('command-form').requestSubmit();}if(event.altKey&&(event.key==='ArrowUp'||event.key==='ArrowDown')){event.preventDefault();if(historyIndex===-1)draft=$('command').value;historyIndex=event.key==='ArrowUp'?Math.min(historyIndex+1,history.length-1):Math.max(-1,historyIndex-1);$('command').value=historyIndex<0?draft:history[historyIndex];$('autocomplete').hidden=true;}});
  function renderOutput(){const pre=$('output'),query=$('output-search').value;pre.replaceChildren();if(!query){pre.textContent=output;}else{let from=0,at;while((at=output.indexOf(query,from))!==-1){pre.append(document.createTextNode(output.slice(from,at)));const mark=document.createElement('mark');mark.textContent=output.slice(at,at+query.length);pre.append(mark);from=at+query.length;}pre.append(document.createTextNode(output.slice(from)));}pre.hidden=!output;$('empty-output').hidden=!!output;}
  $('output-search').addEventListener('input',renderOutput);
  $('copy-output').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(output);toast('خروجی کپی شد.');}catch{toast('کپی خودکار مجاز نیست؛ متن خروجی را انتخاب و کپی کن.');}});
  $('download-output').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([output],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='harbor-output-'+new Date().toISOString().replace(/[:.]/g,'-')+'.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  $('wrap-output').addEventListener('click',()=>{const nowrap=$('output').classList.toggle('nowrap');$('wrap-output').textContent='شکستن خط: '+(nowrap?'خاموش':'روشن');$('wrap-output').setAttribute('aria-pressed',String(!nowrap));});
  $('clear-output').addEventListener('click',()=>{output='';$('output-search').value='';renderOutput();});
  renderSuggestions();renderList('favorites',favorites);renderList('history',history);
})();
</script>
<?php endif; ?>
<footer><span dir="ltr">HARBOR / YOUR PERSONAL HOST CONSOLE</span><span>انقضای نشست: ۱۵ دقیقه بی‌کاری · مدیریت رمز و اتصال از تنظیمات افزونه</span></footer></div></body></html>

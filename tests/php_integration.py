"""Local-only HTTP tests; HTTPS is simulated by the test router, never by production PHP."""
from pathlib import Path
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'local-test-current-password-123456'
NEW_PASSWORD = 't4st'

def run():
    with tempfile.TemporaryDirectory(prefix='harbor-test-', dir=os.environ.get('HARBOR_TEST_TEMP')) as folder:
        path = Path(folder)
        source = (ROOT / 'extension/terminal.template.php').read_text(encoding='utf-8')
        salt = 'a' * 32
        verifier = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), salt.encode(), 600000).hex()
        source = source.replace('__INSTANCE_ID__', '1234567890abcdef').replace('__AUTH_SALT__', salt).replace('__AUTH_VERIFIER__', verifier)
        (path / 'terminal.php').write_text(source, encoding='utf-8')
        (path / 'router.php').write_text("<?php if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) !== '/insecure.php') $_SERVER['HTTPS']='on'; require __DIR__.'/terminal.php';", encoding='utf-8')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        with (path / 'server.log').open('w') as log:
            server = subprocess.Popen(['php', '-S', f'127.0.0.1:{port}', '-t', folder, str(path / 'router.php')], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                    except OSError: time.sleep(.05)
                def request(url='/terminal.php', data=None, cookie=None, content_type='application/x-www-form-urlencoded'):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
                    headers = {}
                    if cookie: headers['Cookie'] = cookie
                    if data is not None: headers['Content-Type'] = content_type
                    connection.request('POST' if data is not None else 'GET', url, body=data, headers=headers)
                    response = connection.getresponse()
                    body = response.read().decode('utf-8')
                    cookies = [value.split(';', 1)[0] for key, value in response.getheaders() if key.lower() == 'set-cookie']
                    result = response.status, body, cookies[-1] if cookies else cookie
                    connection.close()
                    return result
                from urllib.parse import urlencode
                def login(password):
                    _, body, cookie = request()
                    token = re.search(r'name="csrf" value="([a-f0-9]+)"', body)[1]
                    return request(data=urlencode({'action': 'login', 'password': password, 'csrf': token}), cookie=cookie)
                assert request('/insecure.php')[0] == 403
                code, body, _ = request('/terminal.php?api=info')
                assert code == 200 and json.loads(body)['id'] == '1234567890abcdef'
                assert json.loads(body)['minimum_password_characters'] == 4
                assert PASSWORD not in body and verifier not in body and folder not in body
                assert request(data='action=run&command=whoami&csrf=invalid')[0] == 403
                assert 'name="command"' not in login('wrong-password')[1]
                code, body, cookie = login(PASSWORD)
                assert code == 200 and 'name="command"' in body
                token = re.search(r'name="csrf" value="([a-f0-9]+)"', body)[1]
                assert request(data=urlencode({'action': 'run', 'command': 'pwd', 'cwd': '/no-such-harbor-directory', 'csrf': token}), cookie=cookie)[0] == 200
                if os.name != 'nt':
                    _, body, cookie = request(data=urlencode({'action': 'run', 'command': "printf '<test-output>'", 'cwd': folder, 'csrf': token}), cookie=cookie)
                    assert '&lt;test-output&gt;' in body
                rotate_url = '/terminal.php?api=rotate'
                assert request(rotate_url)[0] == 405
                assert request(rotate_url, data='{}')[0] == 415
                def rotate(current, new):
                    return request(rotate_url, data=json.dumps({'id': '1234567890abcdef', 'current_password': current, 'new_password': new}), content_type='application/json')
                assert rotate('wrong', NEW_PASSWORD)[0] == 403
                assert rotate(PASSWORD, 'abc')[0] == 400
                assert rotate(PASSWORD, PASSWORD)[0] == 400
                assert rotate(PASSWORD, NEW_PASSWORD)[0] == 200
                assert 'name="command"' not in request(cookie=cookie)[1], 'Old login must be revoked'
                assert 'name="command"' not in login(PASSWORD)[1], 'Old password must fail'
                assert 'name="command"' in login(NEW_PASSWORD)[1], 'New password must succeed'
                assert NEW_PASSWORD not in (path / 'terminal.php').read_text(encoding='utf-8')
                assert rotate(NEW_PASSWORD, 'رمزن')[0] == 200
                assert 'name="command"' in login('رمزن')[1], 'Four Persian characters must work'
                assert 'name="command"' not in login(NEW_PASSWORD)[1]
                assert not list(path.glob('.harbor-write-*')), 'No temporary credential files may remain'
                print('PASS: HTTPS, identity probe, CSRF, login, rotation, old-password rejection, session revocation.' + (' Command execution checked.' if os.name != 'nt' else ' Linux command execution skipped on Windows.'))
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()

if __name__ == '__main__': run()

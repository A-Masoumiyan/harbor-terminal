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
import base64
import threading
import signal

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
            environment=os.environ.copy()
            if os.name!='nt': environment['PHP_CLI_SERVER_WORKERS']='2'
            server = subprocess.Popen(['php', '-S', f'127.0.0.1:{port}', '-t', folder, str(path / 'router.php')], stdout=log, stderr=log,env=environment,start_new_session=os.name!='nt')
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
                from urllib.parse import urlencode, quote
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
                def api(action,data=None,client_cookie=None):
                    return request('/terminal.php?api='+action,data=json.dumps({'csrf':token,**(data or {})}),cookie=client_cookie or cookie,content_type='application/json')
                assert request('/terminal.php?api=files')[0]==401
                assert request('/terminal.php?api=files',data='{"csrf":"bad"}',cookie=cookie,content_type='application/json')[0]==403
                status,body,_=api('context',{'cwd':folder})
                assert status==200 and 'terminal.php' in [x['name'] for x in json.loads(body)['items']]
                (path/'example folder').mkdir()
                assert api('files',{'cwd':str(path/'example folder')})[0]==200
                def upload():
                    boundary='harbor-test-boundary'
                    fields=[('csrf',token),('cwd',folder)]
                    parts=['--'+boundary+'\r\nContent-Disposition: form-data; name="'+key+'"\r\n\r\n'+value+'\r\n' for key,value in fields]
                    parts.append('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="note.txt"\r\nContent-Type: text/plain\r\n\r\nhello from upload\r\n--'+boundary+'--\r\n')
                    return request('/terminal.php?api=upload',data=''.join(parts).encode(),cookie=cookie,content_type='multipart/form-data; boundary='+boundary)
                assert upload()[0]==200
                assert upload()[0]==409 and (path/'note.txt').read_text()=='hello from upload'
                assert request('/terminal.php?api=download&path='+quote(str(path/'note.txt')),cookie=cookie)[1]=='hello from upload'
                assert request('/terminal.php?api=download&path='+quote(folder),cookie=cookie)[0]==404
                _,_,other_cookie=login(PASSWORD)
                sessions=json.loads(api('sessions')[1])['items']
                assert len(sessions)>=2 and sum(x['current'] for x in sessions)==1
                assert api('revoke',{'target':'others'})[0]==200
                assert 'name="command"' not in request(cookie=other_cookie)[1]
                assert 'name="command"' in request(cookie=cookie)[1]
                assert request(data=urlencode({'action': 'run', 'command': 'pwd', 'cwd': '/no-such-harbor-directory', 'csrf': token}), cookie=cookie)[0] == 200
                if os.name != 'nt':
                    _, body, cookie = request(data=urlencode({'action': 'run', 'command': "printf '<test-output>'", 'cwd': folder, 'csrf': token}), cookie=cookie)
                    assert '&lt;test-output&gt;' in body
                    status,body,_=api('stream',{'cwd':folder,'command':"printf 'سلام'; printf ' error' >&2",'job':'1'*32})
                    assert status==200
                    events=[json.loads(line) for line in body.splitlines()]
                    raw=b''.join(base64.b64decode(event['data']) for event in events if event['type']=='chunk')
                    assert 'سلام'.encode() in raw and b' error' in raw
                    assert events[-1]['type']=='done' and events[-1]['code']==0
                    assert json.loads(api('audit')[1])['items'][0]['command'].startswith('printf')
                    started=threading.Event();stream_result=[];stream_errors=[]
                    def slow_command():
                        try:
                            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
                            connection.request('POST','/terminal.php?api=stream',body=json.dumps({'csrf':token,'cwd':folder,'command':'exec sleep 5','job':'2'*32}),headers={'Cookie':cookie,'Content-Type':'application/json'})
                            response=connection.getresponse()
                            first=json.loads(response.readline());assert first['type']=='start';started.set()
                            stream_result.extend(json.loads(line) for line in response.read().decode().splitlines())
                            connection.close()
                        except BaseException as error:stream_errors.append(error);started.set()
                    thread=threading.Thread(target=slow_command);begin=time.monotonic();thread.start();assert started.wait(4)
                    assert api('stop',{'job':'2'*32})[0]==200
                    thread.join(6);assert not thread.is_alive() and not stream_errors,stream_errors
                    assert stream_result[-1]['reason']=='stopped' and time.monotonic()-begin<4.5
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
                # Successful login resets prior failures, then five failures trigger shared cooldown.
                assert 'name="command"' in login('رمزن')[1]
                for _ in range(5):login('incorrect')
                assert login('رمزن')[0]==429
                print('PASS: HTTPS, CSRF, files, upload/download, session revocation, four-character passwords, shared login cooldown.' + (' Live execution, UTF-8 and concurrent stop checked.' if os.name != 'nt' else ' Linux process tests skipped on Windows.'))
            finally:
                if os.name!='nt':os.killpg(server.pid,signal.SIGTERM)
                else:server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()

if __name__ == '__main__': run()

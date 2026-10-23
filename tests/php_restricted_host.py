"""Check authentication when optional private-storage functions are disabled."""
from pathlib import Path
import hashlib, http.client, json, os, re, socket, subprocess, tempfile, time
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='harbor-restricted-',dir=os.environ.get('HARBOR_TEST_TEMP')) as folder:
    path=Path(folder);password='test-current-only';salt='a'*32;identity='1234567890abcdef'
    source=(ROOT/'extension/terminal.template.php').read_text(encoding='utf-8').replace('__INSTANCE_ID__',identity).replace('__AUTH_SALT__',salt).replace('__AUTH_VERIFIER__',hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),600000).hex())
    (path/'terminal.php').write_text(source,encoding='utf-8')
    (path/'router.php').write_text("<?php $_SERVER['HTTPS']='on';require __DIR__.'/terminal.php';",encoding='utf-8')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    with (path/'server.log').open('w') as log:
        server=subprocess.Popen(['php','-d','disable_functions=getmyuid,fileowner,chmod','-S',f'127.0.0.1:{port}','-t',folder,str(path/'router.php')],stdout=log,stderr=log)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.05)
            def request(route='',body=None,cookie=None,json_body=False):
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=20)
                headers={'Content-Type':'application/json' if json_body else 'application/x-www-form-urlencoded'}
                if cookie:headers['Cookie']=cookie
                conn.request('POST' if body is not None else 'GET','/terminal.php'+route,body=body,headers=headers)
                response=conn.getresponse();text=response.read().decode('utf-8');cookies=[v.split(';')[0] for k,v in response.getheaders() if k.lower()=='set-cookie'];status=response.status;conn.close()
                return status,text,cookies[-1] if cookies else cookie
            status,body,_=request('?api=info')
            assert status==200,(status,body)
            assert json.loads(body)['features']['privateStorage'] is False
            def login(value):
                status,body,cookie=request();token=re.search(r'name="csrf" value="([a-f0-9]+)"',body)[1]
                return request(body=urlencode({'action':'login','password':value,'csrf':token}),cookie=cookie)
            status,body,cookie=login(password)
            assert status==200 and 'name="command"' in body,(status,body[:100])
            payload=json.dumps({'id':identity,'current_password':password,'new_password':'t4st'})
            status,body,_=request('?api=rotate',payload,json_body=True)
            assert status==200 and json.loads(body)['ok'],(status,body)
            assert 'name="command"' in login('t4st')[1]
            assert 'name="command"' not in login(password)[1]
            assert 'name="command"' not in request(cookie=cookie)[1]
            print('Restricted host: identity probe, login, four-character rotation and revocation passed.')
        finally:
            server.terminate();server.wait(timeout=5)

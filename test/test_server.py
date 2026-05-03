import os, sys, time, json, pathlib, subprocess, shutil

import pytest, requests

from libden.pk.helpers import wb64_from_bytes


# Note regarding .pem files: All test .pem files were created using:
# openssl ecparam -genkey -name prime256v1 -out FILENAME

####################
# Setup / Teardown #
####################

def _get_server_scope(fixture_name, config):
    return {
        'each': 'function',
        'once': 'module',
    }[config.getoption('--server')]

class Server:
    def __init__(self):
        self.port = 8000
        self.toml = 'pkserver-test.toml'
        self.proc = None
    
    def start(self):
        args = [sys.executable, '-m', 'uvicorn', 'libden.pk.server:app']
        env = {}
        
        if self.port is not None:
            args += ['--port', str(self.port)]
        
        if self.toml is not None:
            env['PKSERVER_TOML'] = self.toml
        
        self.proc = subprocess.Popen(args, env=env)
        
        for _ in range(100):
            try:
                get('/', port=self.port, timeout=0.1)
                break
            except requests.exceptions.ConnectionError:
                time.sleep(0.01)
        else:
            self.proc.terminate()
            raise Exception(f'Port {self.port} not responding. Did the server '
                'fail to start?')
    
    def stop(self):
        self.proc.send_signal(subprocess.signal.SIGINT)
        self.proc.wait(timeout=5)
        assert self.proc.returncode == 0

@pytest.fixture(scope=_get_server_scope)
def server(request):
    server = Server()
    
    if request.scope == 'module':
        server.toml = 'pkserver-test-once.toml'
    
    if 'fixture_args' in request.keywords:
        for key, value in request.keywords['fixture_args'].kwargs.items():
            setattr(server, key, value)
    
    try:
        server.start()
        yield server
    finally:
        server.stop()

#########
# Tests #
#########

@pytest.mark.quick
def test_server_is_running(server):
    resp = get('/')

@pytest.mark.quick
def test_login_sunny_day(server):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    _, obj = post('/api/login', json=payload)
    get('/verify', cookies={ 'token': obj['token'] })

@pytest.mark.quick
def test_login_japanese(server):
    _, obj = post('/api/challenge', json={ 'username': '初音ミク' })
    payload = pk_client_login(obj['challenge'], '初音ミク.pem',
        'localhost', 'http://localhost:8000', 'LEFCTt01JRE6vr9UnISq2w')
    
    _, obj = post('/api/login', json=payload)
    get('/verify', cookies={ 'token': obj['token'] })

@pytest.mark.quick
def test_login_cyrillic(server):
    _, obj = post('/api/challenge', json={ 'username': 'Слава Україні!' })
    payload = pk_client_login(obj['challenge'], 'Слава Україні!.pem',
        'localhost', 'http://localhost:8000', 'P9KJ4_AJMAnlnjTrKPJVPA')
    
    _, obj = post('/api/login', json=payload)
    get('/verify', cookies={ 'token': obj['token'] })

@pytest.mark.quick
def test_cc_sunny_day(server):
    _, obj = post('/api/challenge', json={ 'username': 'cc-test' })
    payload = pk_client_cc(obj['challenge'], 'unregistered.pem',
        'localhost', 'http://localhost:8000')
    
    _, obj = post('/api/create-credential', json=payload)
    assert 'id' in obj
    assert 'public_key' in obj

@pytest.mark.quick
@pytest.mark.parametrize('endpoint', [
    '/api/challenge',
    '/api/login',
    '/api/create-credential',
])
def test_malformed_json(server, endpoint: str):
    post(endpoint, data='{', expected_status=422)

@pytest.mark.quick
def test_challenge_missing_field(server):
    # There's only one expected field, so use an empty JSON for the missing
    # field test
    post('/api/challenge', json={}, expected_status=422)

@pytest.mark.quick
@pytest.mark.parametrize('field', [
    'id',
    'rawId',
    'response',
    'response.attestationObject',
    'response.clientDataJSON',
])
def test_cc_missing_field(server, field: str):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_cc(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000')
    
    if '.' in field:
        key_1, key_2 = field.split('.')
        del payload[key_1][key_2]
    else:
        del payload[field]
    
    post('/api/create-credential', json=payload, expected_status=422)

@pytest.mark.quick
@pytest.mark.parametrize('field', [
    'id',
    'rawId',
    'response',
    'response.authenticatorData',
    'response.clientDataJSON',
    'response.signature',
])
def test_login_missing_field(server, field: str):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', obj['allowCredentials'][0])
    
    if '.' in field:
        key_1, key_2 = field.split('.')
        del payload[key_1][key_2]
    else:
        del payload[field]
    
    post('/api/login', json=payload, expected_status=422)

@pytest.mark.quick
@pytest.mark.parametrize('value', [
    '',
    17*'a',
])
def test_challenge_bad_field(server, value: str):
    # There's only one field to test
    post('/api/challenge', json={ 'username': value }, expected_status=422)

@pytest.mark.quick
@pytest.mark.parametrize('field,value,expected_status', [
    pytest.param('id', 'notarealid', 401, id='id'),
    pytest.param('rawId', 'notarealid', 401, id='rawId'),
    pytest.param('response', 'not-even-json', 422, id='response'),
    pytest.param('response.attestationObject', 'multipleoffourplusone', 422,
        id='attestationObject-bad-base64'),
    pytest.param('response.attestationObject', 'base64butnotjson', 422,
        id='attestationObject-bad-json'),
    pytest.param('response.clientDataJSON', 'multipleoffourplusone', 422,
        id='clientDataJSON-bad-base64'),
    pytest.param('response.clientDataJSON', 'base64butnotjson', 422,
        id='clientDataJSON-bad-json'),
])
def test_cc_bad_field(server, field: str, value: str,
expected_status: int):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_cc(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000')
    
    if '.' in field:
        key_1, key_2 = field.split('.')
        payload[key_1][key_2] = value
    else:
        payload[field] = value
    
    post('/api/create-credential', json=payload,
        expected_status=expected_status)

@pytest.mark.quick
@pytest.mark.parametrize('field,value,expected_status', [
    pytest.param('id', 'notarealid', 401, id='id'),
    pytest.param('rawId', 'notarealid', 401, id='rawId'),
    pytest.param('response', 'not-even-json', 422, id='response'),
    pytest.param('response.authenticatorData', 'multipleoffourplusone', 422,
        id='authenticatorData-bad-base64'),
    pytest.param('response.authenticatorData', 'base64butshort', 422,
        id='authenticatorData-short'),
    pytest.param('response.authenticatorData',
        'looooooooooooooooooooooooooooooooongenoughbutnotjson', 422,
        id='authenticatorData-bad-json'),
    pytest.param('response.clientDataJSON', 'multipleoffourplusone', 422,
        id='clientDataJSON-bad-base6'),
    pytest.param('response.clientDataJSON', 'base64butnotjson', 422,
        id='clientDataJSON-bad-json'),
    pytest.param('response.signature', 'multipleoffourplusone', 422,
        id='signature-bad-base64'),
    pytest.param('response.signature', 'badsignature', 401,
        id='signature-bad-json'),
])
def test_login_bad_field(server, field: str, value: str,
expected_status: int):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', obj['allowCredentials'][0])
    
    if '.' in field:
        key_1, key_2 = field.split('.')
        payload[key_1][key_2] = value
    else:
        payload[field] = value
    
    post('/api/login', json=payload, expected_status=expected_status)

@pytest.mark.quick
def test_cc_no_challenge(server):
    payload = pk_client_cc(wb64_from_bytes(os.urandom(16)), 'unregistered.pem',
        'localhost', 'http://localhost:8000')
    
    post('/api/create-credential', json=payload, expected_status=422)

@pytest.mark.quick
def test_login_no_challenge(server):
    payload = pk_client_login(wb64_from_bytes(os.urandom(16)), 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    post('/api/login', json=payload, expected_status=422)

@pytest.mark.quick
def test_cc_wrong_challenge(server):
    post('/api/challenge', json={ 'username': 'cc-test' })
    payload = pk_client_cc(wb64_from_bytes(os.urandom(16)), 'unregistered.pem',
        'localhost', 'http://localhost:8000')
    
    post('/api/create-credential', json=payload, expected_status=422)

@pytest.mark.quick
def test_login_wrong_challenge(server):
    post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_login(wb64_from_bytes(os.urandom(16)), 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    post('/api/login', json=payload, expected_status=422)

@pytest.mark.quick
def test_cc_reused_challenge(server):
    _, obj = post('/api/challenge', json={ 'username': 'cc-test' })
    payload = pk_client_cc(obj['challenge'], 'unregistered.pem',
        'localhost', 'http://localhost:8000')
    
    post('/api/create-credential', json=payload)
    
    payload = pk_client_cc(obj['challenge'], 'unregistered-2.pem',
        'localhost', 'http://localhost:8000')
    
    post('/api/create-credential', json=payload, expected_status=422)

@pytest.mark.quick
def test_login_reused_challenge(server):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    post('/api/login', json=payload)
    
    payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    post('/api/login', json=payload, expected_status=422)

@pytest.mark.quick
def test_cc_double_challenge(server):
    post('/api/challenge', json={ 'username': 'cc-test' })
    
    _, obj = post('/api/challenge', json={ 'username': 'cc-test' })
    payload = pk_client_cc(obj['challenge'], 'unregistered.pem',
        'localhost', 'http://localhost:8000')
    
    _, obj = post('/api/create-credential', json=payload)
    assert 'id' in obj
    assert 'public_key' in obj

@pytest.mark.quick
def test_login_double_challenge(server):
    post('/api/challenge', json={ 'username': 'test-user' })
    
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    _, obj = post('/api/login', json=payload)
    get('/verify', cookies={ 'token': obj['token'] })

# CC w/ expired challenge
# Login w/ expired challenge
# CC w/ almost expired challenge                   <--- Sunny day
# Login w/ almost expired challenge                <--- Sunny day
# Challenge w/ too many challenges (global)
# Challenge w/ too many challenges (per user)
# Challenge w/ almost too many challenges (global) <--- Sunny day
# Challenge w/ almost too many challenges (per user)<-- Sunny day
# Login w/ too many challenges on separate user    <--- Sunny day
# CC with recovered challenge                      <--- Sunny day
# Login with recovered challenge                   <--- Sunny day
# Simultaneous CC                                  <--- Sunny day
# Simultaneous login                               <--- Sunny day

# Logout sunny day
# Logout w/o cookie
# Logout w/ missing cookie fields
# Logout w/ malformed cookie
# Logout w/ malformed cookie fields
# Logout w/ bad token
# Logout different token

# Logout all sunny day single token
# Logout all w/o cookie
# Logout all w/ missing cookie fields
# Logout all w/ malformed cookie
# Logout all w/ malformed cookie fields
# Logout all w/ bad token
# Logout all sunny day multiple tokens

# Verify sunny day
# Verify w/o cookie
# Verify w/ missing cookie fields
# Verify w/ malformed cookie
# Verify w/ malformed cookie fields
# Verify w/ bad token
# Verify sunny day multiple tokens

def test_registration_sunny_day(server):
    username = 'register-test'
    key_path = 'unregistered.pem'
    
    _, obj = post('/api/challenge', json={ 'username': username })
    login_payload = pk_client_cc(obj['challenge'], key_path,
        'localhost', 'http://localhost:8000')
    
    _, obj = post('/api/create-credential', json=login_payload)
    cred_id = obj['id']
    public_key = obj['public_key']
    
    shutil.copy2('pkserver-empty.toml', 'temp/test_registration_sunny_day.toml')
    with open('temp/test_registration_sunny_day.toml', 'a') as f:
        f.write(f'\n[users."{username}"]\n'
            f'credentials = [{{ id = "{cred_id}",'
            f' public_key = "{public_key}" }}]\n')
    
    server.stop()
    server.toml = 'temp/test_registration_sunny_day.toml'
    server.start()
    
    _, obj = post('/api/challenge', json={ 'username': username })
    login_payload = pk_client_login(obj['challenge'], key_path,
        'localhost', 'http://localhost:8000', cred_id)
    
    _, obj = post('/api/login', json=login_payload)
    get('/verify', cookies={ 'token': obj['token'] })

@pytest.mark.manual
def test_real_yubikey(server):
    # Must use localhost and not 127.0.0.1 so browser accepts RP ID
    print('Open http://localhost:8000/ in Chromium and begin registration. '
        'Paste data here using Ctrl+Shift+V followed by Ctrl+D.')
    snippet = sys.stdin.readlines()
    
    shutil.copy2('pkserver-empty.toml', 'temp/test_real_yubikey.toml')
    with open('temp/test_real_yubikey.toml', 'a') as f:
        f.writelines(snippet)
    
    server.stop()
    server.toml = 'temp/test_real_yubikey.toml'
    server.start()
    
    result = input('Try logging in! Does it work y/n?\n')
    assert result == 'y'

@pytest.mark.quick
def test_create_credential_curl(server):
    proc = subprocess.run(['sh', 'pk-create-credential.sh'], check=True)

@pytest.mark.quick
def test_login_curl(server):
    proc = subprocess.run(['sh', 'pk-login.sh'], check=True)

@pytest.mark.fixture_args(port=8001)
def test_uvicorn_argument(server):
    resp = get('/', port=8001)

###########
# Helpers #
###########

def get(path: str | bytes, port: int = 8000, expected_status: int = 200, *args,
**kwargs) -> requests.Response:
    # Use 127.0.0.1 and not localhost to avoid IPv6 headaches
    res = requests.get(f'http://127.0.0.1:{port}{path}',
        verify=False, *args, **kwargs)
    
    assert res.status_code == expected_status, res.text
    
    if path == '/' or path.startswith('/index.html'):
        obj = res.text
    else:
        obj = res.json()
    
    return res, obj

def post(path: str | bytes, port: int = 8000, expected_status: int = 200, *args,
**kwargs) -> requests.Response:
    # Use 127.0.0.1 and not localhost to avoid IPv6 headaches
    res = requests.post(f'http://127.0.0.1:{port}{path}',
        verify=False, *args, **kwargs)
    
    assert res.status_code == expected_status, res.text
    
    if path.startswith('/api/login') and expected_status == 200:
        assert res.json()['token'] == res.cookies['token']
    
    return res, res.json()

def pk_client_cc(challenge: str, private_key: pathlib.Path, rp_id: str,
origin: str) -> {}:
    proc = subprocess.run([sys.executable, '-m', 'libden.pk.client',
        'create-credential',
        '--challenge', f"'{challenge}'",
        '--private-key', private_key,
        '--rp-id', rp_id,
        '--origin', origin
    ], capture_output=True, text=True)
    
    print('python -m libden.pk.client returned exit code '
        f'{proc.returncode}')
    assert proc.returncode == 0, 'python -m libden.pk.client returned ' \
        f'exit code {proc.returncode}'
    
    return json.loads(proc.stdout)

def pk_client_login(challenge: str, private_key: pathlib.Path, rp_id: str,
origin: str, cred_id: str) -> {}:
    proc = subprocess.run([sys.executable, '-m', 'libden.pk.client',
        'login',
        '--challenge', f"'{challenge}'",
        '--credential-id', cred_id,
        '--private-key', private_key,
        '--rp-id', rp_id,
        '--origin', origin
    ], capture_output=True, text=True)
    
    print('python -m libden.pk.client returned exit code '
        f'{proc.returncode}')
    assert proc.returncode == 0, 'python -m libden.pk.client returned ' \
        f'exit code {proc.returncode}'
    
    return json.loads(proc.stdout)

import os, sys, time, json, pathlib, subprocess
import pytest, requests


TEST_KEY_PATH = pathlib.Path(__file__).parent.parent / 'passkey.pem' 
TEST_KEY_PATH_2 = pathlib.Path(__file__).parent.parent / 'passkey-2.pem' 

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
        self.keylist = 'keylist-test.toml'
        self.proc = None
    
    def start(self):
        args = [sys.executable, '-m', 'uvicorn', 'libden.pk.server:app']
        env = {}
        
        if self.port is not None:
            args += ['--port', str(self.port)]
        
        if self.keylist is not None:
            env['LIBDEN_KEYLIST'] = self.keylist
        
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
def server(request, pytestconfig):
    server = Server()
    
    if 'fixture_args' in request.keywords:
        for key, value in request.keywords['fixture_args'].kwargs.items():
            server.__setattr__(key, value)
    
    server.start()
    
    yield server
    
    server.stop()

#########
# Tests #
#########

import warnings
@pytest.mark.quick
def test_login_sunny_day(server):
    username = "den-antares"
    origin = "localhost"
    rp_id = "localhost"
    
    # Use the pre-registered scratch key
    credential_id = "Nn20CDS45AgdiAN0b_v7SQ"
    
    res = post('/api/challenge', json={ 'username': username })
    assert res.status_code == 200
    challenge_json = res.json()
    challenge = challenge_json['challenge']
    print(f'Server sent challenge `{challenge}` for user `{username}`')
    assert credential_id in challenge_json['allowCredentials']
    
    login_payload = webauthn_tool_authenticate(challenge, username, TEST_KEY_PATH, origin, credential_id)
    
    res = post('/api/login', json=login_payload)
    assert res.status_code == 200
    assert 'token' in res.cookies
    assert res.cookies['token'] == res.text
    token = res.text
    print(f'Server authorized login with token `{token}`')
    
    res = get('/verify', cookies={ 'token': token })
    assert res.status_code == 200

def test_registration_sunny_day(server):
    username = "den-antares"
    origin = "localhost"
    rp_id = "localhost"
    
    res = post('/api/challenge', json={ 'username': username })
    assert res.status_code == 200
    challenge_json = res.json()
    challenge = challenge_json['challenge']
    print(f'Server sent challenge `{challenge}` for user `{username}`')
    
    login_payload = webauthn_tool_register(challenge, username, TEST_KEY_PATH_2, origin)
    
    res = post('/api/register-key', json=login_payload)
    assert res.status_code == 200
    res_json = res.json()
    assert 'id' in res_json
    assert 'public_key' in res_json
    print(f'Server authorized registration with id `{res_json['id']}`')
    
    toml = f'''
[users."{username}"]
keys = [{{ id = '{res_json['id']}', public_key = '{res_json['public_key']}' }}]
'''
    with open('temp/test_registration_sunny_day.toml', 'w') as f:
        f.write(toml)
    
    server.stop()
    server.keylist = 'temp/test_registration_sunny_day.toml'
    server.start()
    
    res = post('/api/challenge', json={ 'username': username })
    assert res.status_code == 200
    challenge_json = res.json()
    challenge = challenge_json['challenge']
    print(f'Server sent challenge `{challenge}` for user `{username}`')
    
    login_payload = webauthn_tool_authenticate(challenge, username, TEST_KEY_PATH_2, origin, res_json['id'])
    
    res = post('/api/login', json=login_payload)
    assert res.status_code == 200
    assert 'token' in res.cookies
    assert res.cookies['token'] == res.text
    token = res.text
    print(f'Server authorized login with token `{token}`')
    
    res = get('/verify', cookies={ 'token': token })
    assert res.status_code == 200

@pytest.mark.quick
def test_server_is_running(server):
    resp = get('/')
    assert resp.status_code == 200

@pytest.mark.fixture_args(port=8001)
def test_uvicorn_argument(server):
    resp = get('/', port=8001)
    assert resp.status_code == 200

@pytest.mark.quick
@pytest.mark.parametrize("run", range(10))
def test_stress_reuse(server, run):
    resp = get('/')
    assert resp.status_code == 200
    assert f"run {run}" == f"run {run}"  # Use run to avoid unused warning

###########
# Helpers #
###########

def get(path: str | bytes, port: int = 8000, *args, **kwargs
    ) -> requests.Response:
    return requests.get('http://127.0.0.1:{}{}'.format(port, path),
        verify=False, *args, **kwargs)

def post(path: str | bytes, port: int = 8000, *args, **kwargs
    ) -> requests.Response:
    return requests.post('http://127.0.0.1:{}{}'.format(port, path),
        verify=False, *args, **kwargs)

def webauthn_tool_register(challenge: str, username: str,
private_key: pathlib.Path, origin: str) -> {}:
    proc = subprocess.run([sys.executable, '-m', 
        'libden.pk.webauthn_tool', 'register',
        '--challenge', f"'{challenge}'",
        '--user-id', username,
        '--private-key', private_key,
        '--origin', origin
    ], capture_output=True, text=True)
    print('python -m libden.pk.webauthn_tool returned exit code '
        f'{proc.returncode}')
    if proc.returncode:
        print(f'Captured stdout: {proc.stdout}')
        print(f'Captured stderr: {proc.stderr}')
        raise Exception('python -m libden.pk.webauthn_tool returned non-zero '
            'exit code. See logs for details.')
    
    res = json.loads(proc.stdout)
    warnings.warn('The CLI tool *really* should include these keys')
    res['rpId'] = origin
    res['origin'] = origin
    res['username'] = username
    
    return res

def webauthn_tool_authenticate(challenge: str, username: str,
private_key: pathlib.Path, origin: str, credential_id: str) -> {}:
    proc = subprocess.run([sys.executable, '-m', 
        'libden.pk.webauthn_tool', 'authenticate',
        '--challenge', f"'{challenge}'",
        '--credential-id', credential_id,
        '--private-key', private_key,
        '--origin', origin
    ], capture_output=True, text=True)
    print('python -m libden.pk.webauthn_tool returned exit code '
        f'{proc.returncode}')
    if proc.returncode:
        print(f'Captured stdout: {proc.stdout}')
        print(f'Captured stderr: {proc.stderr}')
        raise Exception('python -m libden.pk.webauthn_tool returned non-zero '
            'exit code. See logs for details.')
    
    res = json.loads(proc.stdout)
    warnings.warn('The CLI tool *really* should include these keys')
    res['rpId'] = origin
    res['origin'] = origin
    res['username'] = username
    
    return res

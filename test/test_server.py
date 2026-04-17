import os, sys, time, json, pathlib, subprocess, shutil
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
                get('/', port=self.port, expected_status=200, timeout=0.1)
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
    credential_id = "Nn20CDS45AgdiAN0b_v7SQ"
    
    res = post('/api/challenge', json={ 'username': username },
        expected_status=200)
    challenge = res.json()['challenge']
    print(f'Server sent challenge `{challenge}` for user `{username}`')
    
    login_payload = webauthn_tool_authenticate(challenge, username,
        TEST_KEY_PATH, origin, credential_id)
    
    res = post('/api/login', json=login_payload, expected_status=200)
    token = res.text
    assert token == res.cookies['token']
    print(f'Server authorized login with token `{token}`')
    
    res = get('/verify', cookies={ 'token': token }, expected_status=200)

def test_registration_sunny_day(server):
    username = "den-antares"
    origin = "localhost"
    rp_id = "localhost"
    
    res = post('/api/challenge', json={ 'username': username },
        expected_status=200)
    challenge = res.json()['challenge']
    print(f'Server sent challenge `{challenge}` for user `{username}`')
    
    login_payload = webauthn_tool_register(challenge, username,
        TEST_KEY_PATH_2, origin)
    
    res = post('/api/register-key', json=login_payload, expected_status=200)
    res_json = res.json()
    cred_id = res_json['id']
    public_key = res_json['public_key']
    print(f'Server authorized registration with id `{cred_id}`')
    
    shutil.copy2('pkserver-empty.toml', 'temp/test_registration_sunny_day.toml')
    with open('temp/test_registration_sunny_day.toml', 'a') as f:
        f.write(f'\n[users."{username}"]\n'
            f'keys = [{{ id = "{cred_id}", public_key = "{public_key}" }}]\n')
    
    server.stop()
    server.toml = 'temp/test_registration_sunny_day.toml'
    server.start()
    
    res = post('/api/challenge', json={ 'username': username },
        expected_status=200)
    challenge = res.json()['challenge']
    print(f'Server sent challenge `{challenge}` for user `{username}`')
    
    login_payload = webauthn_tool_authenticate(challenge, username,
        TEST_KEY_PATH_2, origin, cred_id)
    
    res = post('/api/login', json=login_payload, expected_status=200)
    token = res.text
    assert token == res.cookies['token']
    print(f'Server authorized login with token `{token}`')
    
    res = get('/verify', cookies={ 'token': token }, expected_status=200)

@pytest.mark.manual
def test_real_yubikey(server):
    # Must use localhost and not 127.0.0.1 so browser accepts RP ID
    print('Open http://localhost:8000/ in Chromium and register key. '
        'Paste data here using Ctrl+Shift+V follwed by Ctrl+D.')
    snippet = sys.stdin.readlines()
    
    shutil.copy2('pkserver-empty.toml', 'temp/test_registration_curl.toml')
    with open('temp/test_registration_curl.toml', 'a') as f:
        f.writelines(snippet)
    
    server.stop()
    server.toml = 'temp/test_registration_curl.toml'
    server.start()
    
    result = input('Try logging in! Does it work y/n?\n')
    assert result == 'y'

@pytest.mark.quick
def test_register_curl(server):
    proc = subprocess.run(['sh', 'pk-register.sh'], check=True)

@pytest.mark.quick
def test_login_curl(server):
    proc = subprocess.run(['sh', 'pk-login.sh'], check=True)

@pytest.mark.quick
def test_server_is_running(server):
    resp = get('/', expected_status=200)

@pytest.mark.fixture_args(port=8001)
def test_uvicorn_argument(server):
    resp = get('/', port=8001, expected_status=200)

@pytest.mark.quick
@pytest.mark.parametrize("run", range(10))
def test_stress_reuse(server, run):
    resp = get('/', expected_status=200)
    assert f"run {run}" == f"run {run}"  # Use run to avoid unused warning

###########
# Helpers #
###########

def get(path: str | bytes, expected_status: int, port: int = 8000, *args,
**kwargs) -> requests.Response:
    # Use 127.0.0.1 and not localhost to avoid IPv6 headaches
    res = requests.get('http://127.0.0.1:{}{}'.format(port, path),
        verify=False, *args, **kwargs)
    
    assert res.status_code == expected_status, res.text
    
    return res

def post(path: str | bytes, expected_status: int, port: int = 8000, *args,
**kwargs) -> requests.Response:
    # Use 127.0.0.1 and not localhost to avoid IPv6 headaches
    res = requests.post('http://127.0.0.1:{}{}'.format(port, path),
        verify=False, *args, **kwargs)
    
    assert res.status_code == expected_status, res.text
    
    return res

def webauthn_tool_register(challenge: str, username: str,
private_key: pathlib.Path, origin: str) -> {}:
    proc = subprocess.run([sys.executable, '-m', 'libden.pk.webauthn_tool',
        'register',
        '--challenge', f"'{challenge}'",
        '--user-id', username,
        '--private-key', private_key,
        '--origin', origin
    ], capture_output=True, text=True)
    
    print('python -m libden.pk.webauthn_tool returned exit code '
        f'{proc.returncode}')
    assert proc.returncode == 0, 'python -m libden.pk.webauthn_tool returned ' \
        f'exit code {proc.returncode}'
    
    res = json.loads(proc.stdout)
    warnings.warn('The CLI tool *really* should include these keys')
    res['username'] = username
    
    return res

def webauthn_tool_authenticate(challenge: str, username: str,
private_key: pathlib.Path, origin: str, credential_id: str) -> {}:
    proc = subprocess.run([sys.executable, '-m', 'libden.pk.webauthn_tool',
        'authenticate',
        '--challenge', f"'{challenge}'",
        '--credential-id', credential_id,
        '--private-key', private_key,
        '--origin', origin
    ], capture_output=True, text=True)
    
    print('python -m libden.pk.webauthn_tool returned exit code '
        f'{proc.returncode}')
    assert proc.returncode == 0, 'python -m libden.pk.webauthn_tool returned ' \
        f'exit code {proc.returncode}'
    
    res = json.loads(proc.stdout)
    warnings.warn('The CLI tool *really* should include these keys')
    res['username'] = username
    
    return res

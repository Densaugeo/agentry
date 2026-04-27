import os, sys, time, json, pathlib, subprocess, shutil
import pytest, requests


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
def server(request, pytestconfig):
    server = Server()
    
    if 'fixture_args' in request.keywords:
        for key, value in request.keywords['fixture_args'].kwargs.items():
            server.__setattr__(key, value)
    
    try:
        server.start()
        yield server
    finally:
        server.stop()

#########
# Tests #
#########

@pytest.mark.quick
def test_login_sunny_day(server):
    _, obj = post('/api/challenge', json={ 'username': 'test-user' })
    login_payload = pk_client_login(obj['challenge'], 'test-user.pem',
        'localhost', 'http://localhost:8000', 'Nn20CDS45AgdiAN0b_v7SQ')
    
    _, obj = post('/api/login', json=login_payload)
    get('/verify', cookies={ 'token': obj['token'] })

@pytest.mark.quick
def test_login_japanese(server):
    _, obj = post('/api/challenge', json={ 'username': '初音ミク' })
    login_payload = pk_client_login(obj['challenge'], '初音ミク.pem',
        'localhost', 'http://localhost:8000', 'LEFCTt01JRE6vr9UnISq2w')
    
    _, obj = post('/api/login', json=login_payload)
    get('/verify', cookies={ 'token': obj['token'] })

@pytest.mark.quick
def test_login_cyrillic(server):
    _, obj = post('/api/challenge', json={ 'username': 'Слава Україні!' })
    login_payload = pk_client_login(obj['challenge'], 'Слава Україні!.pem',
        'localhost', 'http://localhost:8000', 'P9KJ4_AJMAnlnjTrKPJVPA')
    
    _, obj = post('/api/login', json=login_payload)
    get('/verify', cookies={ 'token': obj['token'] })

def test_registration_sunny_day(server):
    username = 'register-test'
    key_path = 'unregistered.pem'
    
    _, obj = post('/api/challenge', json={ 'username': username })
    login_payload = pk_client_create_credential(obj['challenge'], key_path,
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
        'Paste data here using Ctrl+Shift+V follwed by Ctrl+D.')
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

@pytest.mark.quick
def test_server_is_running(server):
    resp = get('/')

@pytest.mark.fixture_args(port=8001)
def test_uvicorn_argument(server):
    resp = get('/', port=8001)

@pytest.mark.quick
@pytest.mark.parametrize('run', range(10))
def test_stress_reuse(server, run):
    resp = get('/')
    assert f'run {run}' == f'run {run}'  # Use run to avoid unused warning

###########
# Helpers #
###########

def get(path: str | bytes, port: int = 8000, expected_status: int = 200, *args,
**kwargs) -> requests.Response:
    # Use 127.0.0.1 and not localhost to avoid IPv6 headaches
    res = requests.get('http://127.0.0.1:{}{}'.format(port, path),
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
    res = requests.post('http://127.0.0.1:{}{}'.format(port, path),
        verify=False, *args, **kwargs)
    
    assert res.status_code == expected_status, res.text
    
    if path.startswith('/api/login'):
        assert res.json()['token'] == res.cookies['token']
    
    return res, res.json()

def pk_client_create_credential(challenge: str,
private_key: pathlib.Path, rp_id: str, origin: str) -> {}:
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

def pk_client_login(challenge: str,
private_key: pathlib.Path, rp_id: str, origin: str, cred_id: str) -> {}:
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

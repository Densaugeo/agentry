import collections, secrets, json, pathlib, os, base64, dataclasses, http
import setproctitle, re, logging, tomllib
from typing import List, Annotated

import fastapi, fastapi.staticfiles, starlette, pydantic, fastapi_utils.tasks
from fastapi import FastAPI, HTTPException, Request, Cookie, Header
import fastapi.responses as fr
import webauthn

MAX_GLOBAL_CHALLENGES = 10
MAX_USER_CHALLENGES = 3
LOGIN_ATTEMPT_RECOVERY_TIME = 60 # mins
CHALLENGE_EXPIRATION_TIME = 5 # mins

@dataclasses.dataclass
class Config:
    rpid: str
    origins: [str]

@dataclasses.dataclass
class RegisteredKey:
    id: str
    public_key: str

@dataclasses.dataclass
class User:
    challenges_remaining: int = MAX_USER_CHALLENGES
    keys: list[RegisteredKey] = dataclasses.field(default_factory=list)

@dataclasses.dataclass
class Challenge:
    username: str | None = None
    mins_remaining: int = CHALLENGE_EXPIRATION_TIME

#################
# General Setup #
#################

setproctitle.setproctitle('tir-na-nog')

logger = logging.getLogger('uvicorn')

app = FastAPI()

with open(os.environ['PKSERVER_TOML'], 'rb') as f:
    toml = tomllib.load(f)

config = Config(**toml['config'])

null_user = User(challenges_remaining=MAX_GLOBAL_CHALLENGES)

users: dict[str, User] = {}
if 'users' in toml:
    for user, data in toml['users'].items():
        users[user] = User(keys=[RegisteredKey(**key) for key in data['keys']])

challenges: dict[bytes, Challenge] = {}

tokens = []

error_template = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="color-scheme" content="dark">
<meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1">

<title>Tir na Nog</title>
</head>

<body>
<h1>{status_code} {status}</h1>
{message}
</body>
</html>'''

def wb64_from_bytes(bytes_: bytes) -> str:
    '''
    Encode bytes to URL-safe base 64 with no padding, as in WebAuthn spec
    '''
    return str(base64.urlsafe_b64encode(bytes_).replace(b'=', b''), 'ascii')

def bytes_from_wb64(b64: str) -> bytes:
    '''
    Decode bytes from URL-safe base 64 with no padding, as in WebAuthn spec
    '''
    return base64.urlsafe_b64decode(b64 + '==')

# FastAPI docs advise intercepting the Starlette HTTP exception, not the FastAPI
# one
@app.exception_handler(starlette.exceptions.HTTPException)
async def http_exception_handler(request: Request,
err: starlette.exceptions.HTTPException):
    if request.headers.get('Sec-Fetch-Mode') == 'navigate':
        message = err.detail
        
        if err.status_code in [401, 403]:
            message += '<br /><a href="/static/login.html">Login here</a>'
        
        html = error_template.format(
            status_code=err.status_code,
            status=http.client.responses[err.status_code],
            message=message,
        )
        
        return fr.HTMLResponse(status_code=err.status_code, content=html)
    
    return await fastapi.exception_handlers.http_exception_handler(request, err)

@app.on_event('startup')
@fastapi_utils.tasks.repeat_every(seconds=60, raise_exceptions=True)
def tick_challenges():
    # Iterate over a copy of challenges.keys(), because keys will be removed
    # during iteration
    for key in list(challenges.keys()):
        if challenges[key].mins_remaining == 0:
            challenges.pop(key)
    
    for challenge in challenges.values():
        challenge.mins_remaining -= 1

@app.on_event('startup')
@fastapi_utils.tasks.repeat_every(seconds=60*LOGIN_ATTEMPT_RECOVERY_TIME,
    raise_exceptions=True)
def tick_users():
    if null_user.challenges_remaining < MAX_GLOBAL_CHALLENGES:
        null_user.challenges_remaining += 1
    
    for user in users.values():
        if user.challenges_remaining < MAX_USER_CHALLENGES:
            user.challenges_remaining += 1

#############
# Endpoints #
#############

@app.get('/')
@app.get('/index.html')
async def static_index_html():
    return fr.FileResponse(path=pathlib.Path(__file__).parent / 'index.html')

class ChallengeBody(pydantic.BaseModel):
    username: Annotated[str, pydantic.StringConstraints(max_length=16)]

@app.post('/api/challenge')
async def post_api_challenge(body: ChallengeBody):
    username = body.username if body.username in users else None
    user = null_user if username is None else users[body.username]
    
    if not user.challenges_remaining:
        raise HTTPException(429, 'Too Many Requests')
    
    user.challenges_remaining -= 1
    # MDN states the challenge should be at least 16 bytes
    # https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
    new_challenge = os.urandom(16)
    challenges[new_challenge] = Challenge(username=username)
    
    return fr.JSONResponse({
        'challenge': wb64_from_bytes(new_challenge),
        'allowCredentials': [v.id for v in user.keys],
    })

@app.post('/api/register-key')
async def post_api_register_key(request: Request):
    try:
        body = json.loads(await request.body())
    except json.decoder.JSONDecodeError:
        raise HTTPException(400, 'Bad Request - Invalid JSON')
    
    challenge_key = bytes_from_wb64(json.loads(bytes_from_wb64(
        body['response']['clientDataJSON']))['challenge'])
    if challenge_key not in challenges:
        raise HTTPException(422, 'Unprocessable Content - Challenge not valid')
    if challenges[challenge_key].username is None:
        user = null_user
    else:
        user = users[challenges[challenge_key].username]
    
    try:
        verified_registration = webauthn.verify_registration_response(
            credential=body,
            expected_challenge=challenge_key,
            expected_rp_id=config.rpid,
            expected_origin=config.origins,
        )
    except webauthn.helpers.exceptions.InvalidRegistrationResponse as e:
        raise HTTPException(401, f'Unauthorized - {e}')
    finally:
        challenges.pop(challenge_key)
    
    user.challenges_remaining += 1
    
    return fr.JSONResponse({
        'id': wb64_from_bytes(verified_registration.credential_id),
        'public_key':
            wb64_from_bytes(verified_registration.credential_public_key),
    })

@app.post('/api/login')
async def post_api_login(request: Request):
    try:
        body = json.loads(await request.body())
    except json.decoder.JSONDecodeError:
        raise HTTPException(400, 'Bad Request - Invalid JSON')
    
    challenge_key = bytes_from_wb64(json.loads(bytes_from_wb64(
        body['response']['clientDataJSON']))['challenge'])
    if challenge_key not in challenges \
    or challenges[challenge_key].username is None:
        raise HTTPException(422, 'Unprocessable Content - Challenge not valid')
    user = users[challenges[challenge_key].username]
    
    for key in user.keys:
        if key.id == body['rawId']:
            public_key = bytes_from_wb64(key.public_key)
            break
    else:
        raise HTTPException(403, 'Forbidden - Key ID not found in registered '
            'keys')
    
    try:
        verified_response = webauthn.verify_authentication_response(
            credential=body,
            expected_challenge=challenge_key,
            expected_rp_id=config.rpid,
            expected_origin=config.origins,
            credential_public_key=public_key,
            # Sign count is required, but doesn't seem to do anything
            credential_current_sign_count=0,
            require_user_verification=False,
        )
    except webauthn.helpers.exceptions.InvalidAuthenticationResponse as e:
        raise HTTPException(401, f'Unauthorized - {e}')
    finally:
        challenges.pop(challenge_key)
    
    user.challenges_remaining += 1
    token = wb64_from_bytes(os.urandom(32))
    tokens.append(token)
    res = fr.PlainTextResponse(token)
    res.set_cookie(key='token', value=token)
    return res

def check_token(token: str | None):
    if not token:
        raise HTTPException(401, 'Unauthorized - login at https:/login.html')
    
    if token not in tokens:
        raise HTTPException(403, 'Forbidden')

@app.post('/api/logout')
async def post_api_logout(token: str | None = Cookie(default=None)):
    check_token(token)
    tokens.remove(token)

@app.post('/api/logout-all')
async def post_api_logout_all(token: str | None = Cookie(default=None)):
    check_token(token)
    tokens.clear()

@app.get('/verify')
async def get_verify(request: Request,
    # These headers are just for logging, so fallback placeholders are fine
    x_forwarded_for   : str = Header(default='?.?.?.?'),
    x_forwarded_port  : str = Header(default='???'    ),
    x_forwarded_method: str = Header(default='???'    ),
    x_forwarded_uri   : str = Header(default='/???'   ),
    token: str | None = Cookie(default=None),
):
    # request.client may not exist, if FastAPI is running behind a proxy and
    # does not receive X-Forwarded-* headers
    host = request.client.host if request.client else None
    port = request.client.port if request.client else None
    
    # While request.client.host is automatically popuplated from X-Forwarded-For
    # if available, request.client.port is not automatically filled.
    # Additionally, I use the header arguments to this function to supply
    # default values
    host = host or x_forwarded_for
    port = port or x_forwarded_port
    
    logger.info(
        f'{host}:{port} - '
        f'{style([YELLOW])}Verifying '
        f'{style([BOLD, BLUE])}{x_forwarded_method} '
        f'{style([RESET, VIOLET])}{x_forwarded_uri} '
        f'{style([RESET])}...'
    )
    check_token(token)

################
# Style Helper #
################

# Copied from ffvrc. ffvrc's copy should be considered authoritative
def style(styles: List[str | int], string: object = '',
width: int | None = None) -> str:
    string = str(string)
    
    if width is not None:
        assert width > 0
        
        if len(string) <= width: string = f'{string:{width}}'
        else: string = string[:max(width - 3, 0)] + min(width, 3)*'.'
    
    ansi_codes = ''
    
    if not isinstance(styles, list):
        styles = [styles]
    
    for style in styles:
        match style:
            case int():
                ansi_codes += f'\033[{style}m'
            case str() if re.fullmatch('#[0-9a-fA-F]{3}', style):
                r, g, b = (int(style[i], 16)*0xff//0xf for i in [1, 2, 3])
                ansi_codes += f'\033[38;2;{r};{g};{b}m'
            case str() if re.fullmatch('#[0-9a-fA-F]{6}', style):
                r, g, b = (int(style[i:i+2], 16) for i in [1, 3, 5])
                ansi_codes += f'\033[38;2;{r};{g};{b}m'
            case _:
                raise ValueError(f'Unknown style: {style}')
    
    reset = '\033[0m' if styles and string else ''
    
    return ansi_codes + string + reset

RESET = 0
BOLD = 1
GRAY = '#ccc'
MAGENTA = '#f0f'
VIOLET = '#c6f'
BLUE = '#4ad'
AQUA = '#1aba97'
GREEN = '#4d4'
YELLOW = '#fe0'
ORANGE = '#ecb64a'
RED = '#f00'

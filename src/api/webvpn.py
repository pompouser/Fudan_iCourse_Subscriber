"""
WebVPN URL encoding and authentication for Fudan University.

Handles:
- AES-128-CFB URL encoding/decoding for WebVPN proxy URLs
- Full 7-step IDP authentication flow against id.fudan.edu.cn
"""

import html as html_mod
import re
import time
from binascii import hexlify, unhexlify
from urllib.parse import urlparse, quote

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

from src.runtime import config


class LoginRejected(RuntimeError):
    """IDP refused login for a reason that retrying will not fix.

    Wrong or expired password, a locked account, a captcha, a forced
    password change, or a second factor this client must not try to bypass.
    """


_REDACT_KEYS = {
    "logintoken", "password", "newpassword", "lck", "loginname",
    "username", "userid", "userphone", "phone", "sms", "smscode",
    "otp", "verifycode", "pic", "ticket",
}

_TRANSIENT_HTTP = (502, 503, 504)

_TRANSIENT_EXC = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
)


def _safe_text(value, limit: int = 160) -> str:
    """Short, single-line text with token-like blobs removed."""
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    text = re.sub(r"[A-Za-z0-9+/=_-]{24,}", "[redacted]", text)
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def _public_keys(data: dict) -> list[str]:
    return sorted(
        key for key in data
        if isinstance(key, str) and key.lower() not in _REDACT_KEYS
    )


def second_factor_modules(data: dict) -> list[str]:
    """Module codes from an authExecute body, when a second step is required.

    The official IDP page treats a truthy ``second`` field (with
    ``moduleCodes``) as "do not use loginToken yet". ``second`` may itself
    be that object, or a flag with ``moduleCodes`` beside it.
    """
    raw = data.get("second")
    modules = raw.get("moduleCodes") if isinstance(raw, dict) else None
    if modules is None and raw:
        modules = data.get("moduleCodes")
    if not isinstance(modules, list):
        return []
    return [item for item in modules if isinstance(item, str) and item][:6]


def extract_login_token(data: dict) -> str:
    """Return a loginToken from the top level or a nested ``data`` object."""
    token = data.get("loginToken") or ""
    if isinstance(token, str) and token:
        return token
    nested = data.get("data")
    if isinstance(nested, dict):
        token = nested.get("loginToken") or ""
        if isinstance(token, str) and token:
            return token
    return ""


def auth_diagnosis(data: object) -> str:
    """Describe an authExecute body without secrets, tokens, or cookies."""
    if not isinstance(data, dict):
        return f"non-object body ({type(data).__name__})"
    modules = second_factor_modules(data)
    message = _safe_text(data.get("message") or data.get("msg") or "")
    parts = [
        f"code={data.get('code')!s}",
        f"keys={_public_keys(data)}",
        f"second={bool(data.get('second'))}",
    ]
    if modules:
        parts.append(f"modules={modules}")
    if message:
        parts.append(f"message={message}")
    return "; ".join(parts)


def rejection_message(data: dict) -> str | None:
    """Owner-facing text when another attempt cannot succeed.

    Returns None for the password-expiry reminder (the official page has a
    Skip button for that) and for ordinary transient failures.
    """
    message = _safe_text(data.get("message") or data.get("msg") or "")
    lowered = message.lower()
    modules = second_factor_modules(data)
    code = str(data.get("code"))

    if modules and modules[0] != "pwdExpRemd":
        first = modules[0]
        if first == "changePwd":
            return (
                "Fudan IDP requires a password change before login can finish "
                f"({auth_diagnosis(data)}). Open https://id.fudan.edu.cn in a "
                "browser, change the UIS password, then update the UISPSW "
                "repository secret. This was not retried."
            )
        label = {
            "userAndSms": "SMS code",
            "sms": "SMS code",
            "userAndOtp": "one-time password",
            "otp": "one-time password",
            "userAndMail": "email code",
            "mail": "email code",
            "userAndQr": "QR-code confirmation",
            "qr": "QR-code confirmation",
        }.get(first, first)
        return (
            "Fudan IDP returned a second-factor challenge "
            f"({label}; modules={modules}) instead of a loginToken. "
            "GitHub-hosted runners cannot complete SMS, OTP, email, or QR "
            "verification. Sign in once at https://id.fudan.edu.cn from a "
            "browser, then re-run iCourse Check. This client does not try "
            f"to bypass that challenge. Detail: {auth_diagnosis(data)}"
        )

    captcha = (
        any(hint in message or hint in lowered for hint in ("验证码", "captcha", "verifycode"))
        or bool(data.get("pic"))
    )
    if captcha:
        return (
            "Fudan IDP is asking for a captcha "
            f"({auth_diagnosis(data)}). A GitHub Actions runner cannot solve "
            "it. Wait and re-run later, or sign in once from a browser at "
            "https://id.fudan.edu.cn so the risk control cools down. Confirm "
            "STUID and UISPSW are still current; repeated failures also "
            "trigger the captcha."
        )

    if any(hint in message or hint in lowered for hint in (
        "密码错误", "密码不正确", "用户名或密码", "账号或密码", "账户或密码",
        "password",
    )):
        return (
            "Fudan IDP rejected the UIS password "
            f"({auth_diagnosis(data)}). Update the UISPSW repository secret "
            "and confirm STUID is still the current student id. "
            "The login was not retried, so this run does not keep guessing."
        )

    if any(hint in message or hint in lowered for hint in ("锁定", "冻结", "locked")):
        return (
            "Fudan IDP says the account is locked "
            f"({auth_diagnosis(data)}). Unlock it in a browser at "
            "https://id.fudan.edu.cn before re-running."
        )

    if code == "4340":
        return (
            "Fudan IDP returned code 4340, which the official login page "
            "handles by sending the browser to another URL. Complete that "
            "step at https://id.fudan.edu.cn, then re-run. "
            f"Detail: {auth_diagnosis(data)}"
        )
    return None


def password_reminder_skip_payload(
    data: dict,
    *,
    student_id: str,
    entity_id: str,
    lck: str,
    request_type: str,
) -> dict:
    """Body of the official "skip" button on a password-expiry reminder.

    The IDP page posts ``isPassRemind=yes`` for ``pwdExpRemd`` and then
    reads ``loginToken`` from that second authExecute response. No new
    password is sent.
    """
    source = data.get("second") if isinstance(data.get("second"), dict) else data
    login_name = source.get("userName") or data.get("userName") or student_id
    request_number = source.get("requestNumber")
    if request_number is None:
        request_number = data.get("requestNumber") or ""
    return {
        "authModuleCode": "pwdExpRemd",
        "authChainCode": source.get("authChainCode") or data.get("authChainCode") or "",
        "entityId": entity_id,
        "requestNumber": request_number,
        "requestType": request_type,
        "lck": lck,
        "authPara": {
            "loginName": login_name,
            "isPassRemind": "yes",
        },
    }


def read_json_object(resp: requests.Response) -> dict:
    """Parse a JSON object. The body is never included in the error."""
    try:
        data = resp.json()
    except ValueError as exc:
        ctype = (resp.headers.get("Content-Type") or "").split(";", 1)[0]
        raise RuntimeError(
            f"Fudan returned a non-JSON body (HTTP {resp.status_code}, "
            f"type={ctype or 'unknown'}, {len(resp.content)} bytes)."
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"Fudan returned JSON {type(data).__name__} instead of an object "
            f"(HTTP {resp.status_code})."
        )
    return data


def encrypt_host(hostname: str) -> str:
    """Encrypt hostname using AES-128-CFB for WebVPN URL encoding.

    Returns the hex-encoded ciphertext of the hostname.
    """
    key = config.WEBVPN_AES_KEY
    iv = config.WEBVPN_AES_IV
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    plaintext = hostname.encode("utf-8")
    encrypted = cipher.encrypt(plaintext)
    return hexlify(encrypted).decode("ascii")


def decrypt_host(ciphertext_hex: str) -> str:
    """Decrypt a WebVPN-encoded hostname."""
    key = config.WEBVPN_AES_KEY
    iv = config.WEBVPN_AES_IV
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    decrypted = cipher.decrypt(unhexlify(ciphertext_hex))
    return decrypted.decode("utf-8")


def get_vpn_url(url: str) -> str:
    """Convert a regular URL to its WebVPN proxy URL.

    Example:
        https://icourse.fudan.edu.cn/courseapi/v3/...
        ->
        https://webvpn.fudan.edu.cn/https/77726476706e69737468656265737421f9f44e.../courseapi/v3/...
    """
    parsed = urlparse(url)
    protocol = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment

    # Remove leading slash from path for concatenation
    path = path.lstrip("/")

    encrypted = encrypt_host(hostname)
    iv_hex = hexlify(config.WEBVPN_AES_IV).decode("ascii")

    # Include non-standard port
    port_suffix = ""
    if port and not (
        (protocol == "http" and port == 80)
        or (protocol == "https" and port == 443)
    ):
        port_suffix = f"-{port}"

    vpn_url = f"{config.WEBVPN_BASE}/{protocol}{port_suffix}/{iv_hex}{encrypted}"
    if path:
        vpn_url += f"/{path}"
    return vpn_url


def get_ordinary_url(vpn_url: str) -> str:
    """Convert a WebVPN URL back to the original URL."""
    parsed = urlparse(vpn_url)
    path_parts = parsed.path.strip("/").split("/", 2)
    if len(path_parts) < 2:
        raise ValueError(f"Invalid WebVPN URL: {vpn_url}")

    protocol_part = path_parts[0]  # e.g. "https" or "https-8080"
    encoded_host = path_parts[1]  # IV + ciphertext
    rest = path_parts[2] if len(path_parts) > 2 else ""

    # Parse protocol and optional port
    if "-" in protocol_part:
        protocol, port_str = protocol_part.rsplit("-", 1)
        port = f":{port_str}"
    else:
        protocol = protocol_part
        port = ""

    # Strip the 32-char IV hex prefix
    iv_hex_len = 32
    ciphertext_hex = encoded_host[iv_hex_len:]
    hostname = decrypt_host(ciphertext_hex)

    original = f"{protocol}://{hostname}{port}"
    if rest:
        original += f"/{rest}"
    if parsed.query:
        original += f"?{parsed.query}"
    return original


class WebVPNSession:
    """Manages a WebVPN session with full IDP authentication."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.logged_in = False

    def _call(self, method: str, url: str, retries: int = 3, **kwargs):
        """HTTP call with a short retry on timeouts, disconnects, and 502/503/504.

        Other status codes are returned as-is. Response bodies are not logged.
        """
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                resp = getattr(self.session, method)(url, **kwargs)
            except _TRANSIENT_EXC as exc:
                last_exc = exc
                if attempt + 1 >= retries:
                    raise
                print(
                    f"    {type(exc).__name__} calling Fudan "
                    f"({attempt + 1}/{retries}); retrying..."
                )
                time.sleep(min(2 ** attempt, 8))
                continue
            if resp.status_code in _TRANSIENT_HTTP and attempt + 1 < retries:
                print(
                    f"    HTTP {resp.status_code} from Fudan "
                    f"({attempt + 1}/{retries}); retrying..."
                )
                time.sleep(min(2 ** attempt, 8))
                continue
            return resp
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Fudan request failed")

    def _probe_portal(self) -> requests.Response:
        """GET the WebVPN portal without following redirects."""
        return self._call(
            "get",
            config.WEBVPN_BASE + "/",
            allow_redirects=False,
            timeout=20,
            retries=2,
        )

    def _require_hot_portal(self) -> None:
        """Raise when the portal still sends the browser to the login page.

        A logged-in portal returns 200. An anonymous one returns 302 to
        /login. The ticket cookie alone is not proof of login: the VPN sets
        that cookie on the anonymous login page too.
        """
        probe = self._probe_portal()
        if probe.status_code == 200:
            return
        target = "the login page" if "login" in probe.headers.get("Location", "") else "another page"
        raise RuntimeError(
            "WebVPN session is not logged in "
            f"(portal HTTP {probe.status_code} to {target}). "
            "A fresh WebVPN login is required."
        )

    def _post_auth_execute(self, payload: dict, *, via_vpn: bool) -> dict:
        url = f"{config.IDP_BASE}/idp/authn/authExecute"
        headers = {
            "Content-Type": "application/json",
            "Referer": f"{config.IDP_BASE}/ac/",
            "Origin": config.IDP_BASE,
        }
        if via_vpn:
            url = get_vpn_url(url)
            headers["Referer"] = f"{get_vpn_url(config.IDP_BASE)}/ac/"
            headers["Origin"] = config.WEBVPN_BASE
        resp = self._call(
            "post", url, json=payload, headers=headers, timeout=60, retries=2,
        )
        return read_json_object(resp)

    def _accept_login_token(
        self,
        data: dict,
        *,
        via_vpn: bool,
        student_id: str,
        entity_id: str,
        lck: str,
        request_type: str,
        where: str,
        allow_reminder: bool = True,
    ) -> str:
        """Turn an authExecute body into a loginToken or a clear error.

        A code of 200 with no loginToken is what the official page shows for
        a second step. Password-expiry reminders are continued with that
        page's Skip action. SMS, OTP, mail, QR, captcha, and a bad password
        stop here.
        """
        modules = second_factor_modules(data)
        # The official page ignores loginToken whenever ``second`` is set,
        # and only offers Skip after a code-200 password-expiry reminder.
        if (
            str(data.get("code")) == "200"
            and data.get("second")
            and modules
            and modules[0] == "pwdExpRemd"
        ):
            if not allow_reminder:
                raise LoginRejected(
                    "Fudan IDP still requires a password-expiry confirmation "
                    "after the official skip action. Open "
                    "https://id.fudan.edu.cn and clear the reminder, then "
                    f"re-run. {auth_diagnosis(data)}"
                )
            print("    IDP password-expiry reminder; using the official skip action.")
            follow = self._post_auth_execute(
                password_reminder_skip_payload(
                    data,
                    student_id=student_id,
                    entity_id=entity_id,
                    lck=lck,
                    request_type=request_type,
                ),
                via_vpn=via_vpn,
            )
            return self._accept_login_token(
                follow,
                via_vpn=via_vpn,
                student_id=student_id,
                entity_id=entity_id,
                lck=lck,
                request_type=request_type,
                where=where,
                allow_reminder=False,
            )

        token = extract_login_token(data)
        if token and not (data.get("second") and modules):
            print("    loginToken: OK")
            return token

        rejected = rejection_message(data)
        if rejected:
            raise LoginRejected(rejected)
        if str(data.get("code")) != "200":
            raise RuntimeError(
                f"Authentication failed ({where}). {auth_diagnosis(data)}"
            )
        raise RuntimeError(
            f"No loginToken in {where}. {auth_diagnosis(data)}"
        )

    def login(self, student_id: str = None, password: str = None) -> bool:
        """Execute the full 7-step IDP authentication flow.

        Returns True on success, raises on failure.
        """
        student_id = student_id or config.STUDENT_ID
        password = password or config.PASSWORD

        if not student_id or not password:
            raise ValueError(
                "Student ID and password are required. "
                "Set STUID and UISPsw environment variables."
            )

        print("[1/7] Getting authentication context...")
        lck, entity_id = self._get_auth_context()

        print("[2/7] Querying authentication methods...")
        auth_chain_code, request_type = self._query_auth_methods(lck, entity_id)

        print("[3/7] Getting RSA public key...")
        pub_key_pem = self._get_public_key()

        print("[4/7] Encrypting password...")
        encrypted_password = self._encrypt_password(password, pub_key_pem)

        print("[5/7] Executing authentication...")
        login_token = self._auth_execute(
            student_id,
            encrypted_password,
            lck,
            entity_id,
            auth_chain_code,
            request_type,
        )

        print("[6/7] Getting CAS ticket...")
        ticket_url = self._get_cas_ticket(login_token)

        print("[7/7] Establishing WebVPN session...")
        self._establish_session(ticket_url)

        self.logged_in = True
        print("[*] WebVPN login successful!")
        return True

    def authenticate_icourse(
        self, student_id: str = None, password: str = None
    ) -> bool:
        """Authenticate to iCourse via CAS/IDP through WebVPN.

        Mimics the browser flow:
        1. Access casapi login URL (like clicking "校内用户登录")
        2. Follow redirect to IDP authenticate (casapi generates correct
           service URL with forward param and r=auth/login)
        3. IDP auth steps through WebVPN
        4. Follow ticket back to iCourse through WebVPN
        """
        student_id = student_id or config.STUDENT_ID
        password = password or config.PASSWORD

        print("[*] Starting iCourse CAS authentication through WebVPN...")

        # A cold session redirects to /login (302). A hot one returns 200.
        # Timeouts are retried inside the probe; they are not treated as
        # "logged out", and the anonymous ticket cookie is not trusted.
        self._require_hot_portal()

        idp_vpn_base = get_vpn_url(config.IDP_BASE)

        # Step 1: Initiate CAS login via casapi.  Use allow_redirects=True
        # so requests follows the full redirect chain like a browser.
        print("[1/7] Initiating CAS login via casapi...")
        casapi_url = (
            f"{config.ICOURSE_BASE}/casapi/index.php"
            f"?r=auth/login&school_login=1"
            f"&tenant_code={config.TENANT_CODE}"
            f"&forward={quote(config.ICOURSE_BASE + '/', safe='')}"
        )
        vpn_url = get_vpn_url(casapi_url)

        resp = self._call("get", vpn_url, allow_redirects=True, timeout=60)
        lck = None
        for source in [resp.url] + [
            h.headers.get("Location", "") for h in (resp.history or [])
        ]:
            m = re.search(r'lck=([^&#"]+)', source)
            if m:
                lck = m.group(1)
                break
        if not lck:
            m = re.search(r'lck=([^&#"]+)', resp.text[:5000])
            if m:
                lck = m.group(1)
        if not lck:
            raise RuntimeError(
                "Failed to extract lck from CAS redirect chain "
                f"(status={resp.status_code})"
            )

        entity_id = config.ICOURSE_BASE
        print("    lck: OK")

        # Step 2: Query auth methods (through WebVPN)
        print("[2/7] Querying auth methods (via WebVPN)...")
        url = get_vpn_url(f"{config.IDP_BASE}/idp/authn/queryAuthMethods")
        resp = self._call(
            "post",
            url,
            json={"lck": lck, "entityId": entity_id},
            headers={
                "Content-Type": "application/json",
                "Referer": f"{idp_vpn_base}/ac/",
                "Origin": config.WEBVPN_BASE,
            },
            timeout=60,
        )
        data = read_json_object(resp)
        auth_method_list = data.get("data") or []
        if not isinstance(auth_method_list, list):
            raise RuntimeError(
                "Auth method list was not a list. " + auth_diagnosis(data)
            )
        request_type = data.get("requestType", "chain_type")

        auth_chain_code = ""
        for method in auth_method_list:
            if method.get("moduleCode") == "userAndPwd":
                auth_chain_code = method.get("authChainCode", "")
                break
        if not auth_chain_code:
            raise RuntimeError("No authChainCode found in response")
        print("    authChainCode: OK")

        # Step 3: Get RSA public key (through WebVPN)
        print("[3/7] Getting RSA public key (via WebVPN)...")
        url = get_vpn_url(f"{config.IDP_BASE}/idp/authn/getJsPublicKey")
        resp = self._call(
            "get",
            url,
            headers={"Referer": f"{idp_vpn_base}/ac/"},
            timeout=60,
        )
        data = read_json_object(resp)
        pub_key_b64 = data.get("data", "")
        if not pub_key_b64:
            raise RuntimeError("Failed to get public key via WebVPN")
        print("    Got RSA public key")

        # Step 4: Encrypt password
        print("[4/7] Encrypting password...")
        encrypted_password = self._encrypt_password(password, pub_key_b64)

        # Step 5: Execute authentication (through WebVPN)
        print("[5/7] Executing authentication (via WebVPN)...")
        payload = {
            "authModuleCode": "userAndPwd",
            "authChainCode": auth_chain_code,
            "entityId": entity_id,
            "requestType": request_type,
            "lck": lck,
            "authPara": {
                "loginName": student_id,
                "password": encrypted_password,
                "verifyCode": "",
            },
        }
        data = self._post_auth_execute(payload, via_vpn=True)
        login_token = self._accept_login_token(
            data,
            via_vpn=True,
            student_id=student_id,
            entity_id=entity_id,
            lck=lck,
            request_type=request_type,
            where="iCourse CAS response",
        )

        # Step 6: Get CAS ticket (through WebVPN)
        print("[6/7] Getting CAS ticket (via WebVPN)...")
        url = get_vpn_url(f"{config.IDP_BASE}/idp/authCenter/authnEngine")
        resp = self._call(
            "post",
            url,
            data={"loginToken": login_token},
            headers={
                "Referer": f"{idp_vpn_base}/ac/",
                "Origin": config.WEBVPN_BASE,
            },
            timeout=60,
        )
        html = resp.text

        # Extract ticket URL from the authnEngine response
        # The URL may already be rewritten to a WebVPN URL by the proxy
        ticket_match = re.search(
            r'locationValue\s*=\s*"([^"]*ticket=[^"]*)"', html
        )
        if not ticket_match:
            ticket_match = re.search(
                r'(https?://[^\s"\'<>]*ticket=[^\s"\'<>]*)', html
            )
        if not ticket_match:
            raise RuntimeError(
                f"Failed to extract iCourse ticket URL (response length: {len(html)})"
            )

        ticket_url = html_mod.unescape(ticket_match.group(1))
        print("    Ticket extracted.")

        # Step 7: Follow ticket to iCourse (through WebVPN)
        print("[7/7] Following ticket to iCourse (via WebVPN)...")
        if not ticket_url.startswith(config.WEBVPN_BASE):
            ticket_url = get_vpn_url(ticket_url)

        resp = self._call(
            "get", ticket_url, allow_redirects=True, timeout=90,
        )
        print(f"    Status: {resp.status_code}")

        # Verify by making a test API call
        test_url = get_vpn_url(
            f"{config.ICOURSE_BASE}/userapi/v1/infosimple"
        )
        resp = self._call("get", test_url, timeout=60)
        if resp.status_code == 200:
            try:
                user_data = resp.json()
                if user_data.get("code") in (0, 200):
                    print("    Verified: login OK")
                    print("[*] iCourse authentication successful!")
                    return True
            except Exception:
                pass

        print("    Could not verify iCourse auth via API, proceeding...")
        return True

    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request through WebVPN. Converts URL automatically."""
        vpn_url = get_vpn_url(url)
        kwargs.setdefault("timeout", 60)
        return self._call("get", vpn_url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request through WebVPN. Converts URL automatically."""
        vpn_url = get_vpn_url(url)
        kwargs.setdefault("timeout", 60)
        kwargs.setdefault("retries", 2)
        return self._call("post", vpn_url, **kwargs)

    def get_raw(self, url: str, **kwargs) -> requests.Response:
        """GET request without URL conversion (for already-converted URLs)."""
        kwargs.setdefault("timeout", 30)
        return self._call("get", url, **kwargs)

    def post_raw(self, url: str, **kwargs) -> requests.Response:
        """POST request without URL conversion."""
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("retries", 2)
        return self._call("post", url, **kwargs)

    # --- Private authentication steps ---

    def _get_auth_context(self) -> tuple[str, str]:
        """Step 1: GET authenticate endpoint, extract lck from redirect."""
        service_url = f"{config.WEBVPN_BASE}/login?cas_login=true"
        url = (
            f"{config.IDP_BASE}/idp/authCenter/authenticate"
            f"?service={quote(service_url, safe='')}"
        )
        resp = self._call("get", url, allow_redirects=False, timeout=60)

        # Follow redirects manually to extract lck
        location = resp.headers.get("Location", "")
        while resp.status_code in (301, 302) and "lck=" not in location:
            resp = self._call("get", location, allow_redirects=False, timeout=60)
            location = resp.headers.get("Location", "")

        if resp.status_code in (301, 302):
            location = resp.headers.get("Location", "")

        # Extract lck parameter
        lck_match = re.search(r"[?&]lck=([^&]+)", location)
        if not lck_match:
            raise RuntimeError(
                f"Failed to extract lck from redirect (status={resp.status_code})"
            )

        lck = lck_match.group(1)
        entity_id = config.WEBVPN_BASE
        print("    lck: OK")
        return lck, entity_id

    def _query_auth_methods(
        self, lck: str, entity_id: str
    ) -> tuple[str, str]:
        """Step 2: Query available authentication methods."""
        url = f"{config.IDP_BASE}/idp/authn/queryAuthMethods"
        resp = self._call(
            "post",
            url,
            json={"lck": lck, "entityId": entity_id},
            headers={
                "Content-Type": "application/json",
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=60,
        )
        data = read_json_object(resp)

        # data["data"] is a list of auth methods; pick the userAndPwd one
        # authChainCode for userAndPwd is in the list items;
        # requestType is at the top level
        auth_method_list = data.get("data") or []
        if not isinstance(auth_method_list, list):
            raise RuntimeError(
                "Auth method list was not a list. " + auth_diagnosis(data)
            )
        request_type = data.get("requestType", "chain_type")

        auth_chain_code = ""
        for method in auth_method_list:
            if method.get("moduleCode") == "userAndPwd":
                auth_chain_code = method.get("authChainCode", "")
                break

        if not auth_chain_code:
            raise RuntimeError("Failed to get authChainCode")

        print("    authChainCode: OK")
        return auth_chain_code, request_type

    def _get_public_key(self) -> str:
        """Step 3: Get RSA public key for password encryption."""
        url = f"{config.IDP_BASE}/idp/authn/getJsPublicKey"
        resp = self._call(
            "get",
            url,
            headers={
                "Referer": f"{config.IDP_BASE}/ac/",
            },
            timeout=60,
        )
        data = read_json_object(resp)
        pub_key_b64 = data.get("data", "")
        if not pub_key_b64:
            raise RuntimeError("Failed to get public key")

        print("    Got RSA public key")
        return pub_key_b64

    def _encrypt_password(self, password: str, pub_key_b64: str) -> str:
        """Step 4: RSA-encrypt the password with PKCS1_v1_5."""
        # Construct PEM format
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + pub_key_b64
            + "\n-----END PUBLIC KEY-----"
        )
        rsa_key = RSA.import_key(pem)
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted = cipher.encrypt(password.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")

    def _auth_execute(
        self,
        student_id: str,
        encrypted_password: str,
        lck: str,
        entity_id: str,
        auth_chain_code: str,
        request_type: str,
    ) -> str:
        """Step 5: Execute authentication and get loginToken."""
        payload = {
            "authModuleCode": "userAndPwd",
            "authChainCode": auth_chain_code,
            "entityId": entity_id,
            "requestType": request_type,
            "lck": lck,
            "authPara": {
                "loginName": student_id,
                "password": encrypted_password,
                "verifyCode": "",
            },
        }
        data = self._post_auth_execute(payload, via_vpn=False)
        return self._accept_login_token(
            data,
            via_vpn=False,
            student_id=student_id,
            entity_id=entity_id,
            lck=lck,
            request_type=request_type,
            where="response",
        )

    def _get_cas_ticket(self, login_token: str) -> str:
        """Step 6: Exchange loginToken for a CAS ticket URL."""
        url = f"{config.IDP_BASE}/idp/authCenter/authnEngine"
        resp = self._call(
            "post",
            url,
            data={"loginToken": login_token},
            headers={
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=60,
        )

        # The response is HTML containing a JS redirect with the ticket URL
        html = resp.text

        # Extract the locationValue from the JavaScript
        ticket_match = re.search(
            r'locationValue\s*=\s*"([^"]*ticket=[^"]*)"', html
        )
        if not ticket_match:
            # Fallback: any URL with ticket= parameter
            ticket_match = re.search(
                r'(https?://[^\s"\'<>]*ticket=[^\s"\'<>]*)', html
            )

        if not ticket_match:
            raise RuntimeError(
                f"Failed to extract ticket URL (response length: {len(html)})"
            )

        ticket_url = ticket_match.group(1)
        # Unescape HTML entities (e.g., &amp; -> &)
        ticket_url = html_mod.unescape(ticket_url)
        print("    Ticket extracted.")
        return ticket_url

    def _establish_session(self, ticket_url: str):
        """Step 7: Follow the ticket URL, then confirm the portal is logged in.

        HTTP 200 on the ticket URL is not enough: a consumed or slow ticket
        lands on the login page, which is also 200. The anonymous portal
        sets a ``wengine_vpn_ticket*`` cookie, so that cookie is not proof
        either. The portal itself returns 200 only after a real login.
        """
        last_status = None
        for attempt in range(3):
            try:
                resp = self.session.get(
                    ticket_url, allow_redirects=True, timeout=60
                )
                last_status = resp.status_code
            except _TRANSIENT_EXC as exc:
                print(
                    f"    Ticket follow {type(exc).__name__} "
                    f"({attempt + 1}/3)..."
                )
                last_status = type(exc).__name__
            try:
                if self._probe_portal().status_code == 200:
                    print("    Session established.")
                    return
            except _TRANSIENT_EXC as exc:
                print(
                    f"    Portal probe {type(exc).__name__} "
                    f"({attempt + 1}/3)..."
                )
            if attempt < 2:
                print(f"    Portal still on the login page, retrying ({attempt + 2}/3)...")
                continue
        raise RuntimeError(
            "WebVPN session was not established "
            f"(ticket follow: {last_status}; portal still redirects to login). "
            "The CAS ticket was not accepted."
        )

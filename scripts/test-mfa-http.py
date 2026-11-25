#!/usr/bin/env python3
"""Black-box MFA HTTP regression test. Run against a disposable CI container only."""
import base64
import hashlib
import hmac
import http.cookiejar
import re
import struct
import sys
import time
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:18788"
PASSWORD = "ci-only-mfa-password"
API_KEY = "c1" * 32

def require(condition, message):
    if not condition:
        raise AssertionError(message)

class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def fetch(self, path):
        with self.opener.open(BASE + path, timeout=20) as response:
            return response.read(), urllib.parse.urlparse(response.geturl()).path

    def get(self, path):
        data, route = self.fetch(path)
        return data.decode("utf-8"), route

    def post(self, path, **fields):
        page, _ = self.get(path)
        token = re.search(r'name="csrf" value="([^"]+)"', page)
        require(token is not None, "CSRF input missing for " + path)
        fields["csrf"] = token.group(1)
        payload = urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request(BASE + path, data=payload, method="POST")
        with self.opener.open(request, timeout=20) as response:
            return response.read().decode("utf-8"), urllib.parse.urlparse(response.geturl()).path

def totp(secret):
    key = base64.b32decode(secret)
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    index = digest[-1] & 15
    num = struct.unpack(">I", digest[index:index + 4])[0] & 0x7fffffff
    return "{:06d}".format(num % 1000000)

one = Browser()
two = Browser()
page, _ = one.get("/login.php")
require('name="api_key"' in page, "API key login absent before MFA activation")

_, route = one.post("/login.php", mode="password", username="admin", password=PASSWORD)
require(route == "/", "first administrator did not log in")

_, route = two.post("/login.php", mode="password", username="admin", password=PASSWORD)
require(route == "/", "second administrator session not established")

page, route = one.post("/security_mfa.php", action="begin", password=PASSWORD)
require(route == "/security_mfa.php", "setup did not stay in MFA settings")
secret = re.search(r"<code>([A-Z2-7]{32})</code>", page)
require(secret is not None, "manual TOTP secret missing")
qr_bytes, qr_route = one.fetch("/mfa_qr.php")
require(qr_bytes.startswith(b"\x89PNG\r\n\x1a\n"), "QR PNG missing or invalid")
current_otp = totp(secret.group(1))
page, route = one.post("/security_mfa.php", action="enable",
                       password=PASSWORD, code=current_otp)
require("Status: Enabled." in page, "MFA enrollment failed")
codes = re.findall(r"[A-F0-9]{5}(?:-[A-F0-9]{5}){3}", page)
require(len(codes) == 10, "10 recovery codes were not displayed")
require(one.get("/settings.php")[1] == "/settings.php", "enrolling session lost access")
require(two.get("/settings.php")[1] == "/login.php", "old administrator session bypassed MFA")

three = Browser()
page, _ = three.get("/login.php")
require('name="api_key"' not in page, "API-key login form still present with MFA enabled")
_, route = three.post("/login.php", mode="api_key", api_key=API_KEY)
require(route == "/login.php", "API-key login bypassed MFA")
require(three.get("/settings.php")[1] == "/login.php", "API-key established session")

_, route = three.post("/login.php", mode="password", username="admin", password=PASSWORD)
require(route == "/login.php", "password unexpectedly bypassed TOTP")
require(three.get("/settings.php")[1] == "/login.php", "password-only session gained access")

_, route = three.post("/login.php", mode="mfa", mfa_code="invalid-code")
require(route == "/login.php", "invalid MFA caused login redirect")
require(three.get("/settings.php")[1] == "/login.php", "invalid MFA gained access")

_, route = three.post("/login.php", mode="mfa", mfa_code=current_otp)
require(route == "/", "valid TOTP failed authentication")
require(three.get("/settings.php")[1] == "/settings.php", "MFA login lacks session")

three.get("/logout.php")
three.post("/login.php", mode="password", username="admin", password=PASSWORD)
_, route = three.post("/login.php", mode="mfa", mfa_code=current_otp)
require(route == "/login.php", "TOTP replay accepted")
_, route = three.post("/login.php", mode="mfa", mfa_code=codes[0])
require(route == "/", "one-time recovery code not accepted")

three.get("/logout.php")
three.post("/login.php", mode="password", username="admin", password=PASSWORD)
_, route = three.post("/login.php", mode="mfa", mfa_code=codes[0])
require(route == "/login.php", "used recovery code accepted")
_, route = three.post("/login.php", mode="mfa", mfa_code=codes[1])
require(route == "/", "unused recovery code rejected")

page, route = three.post("/security_mfa.php", action="disable", password=PASSWORD, code=codes[2])
require("Status: Disabled." in page, "MFA disable with verified credentials failed")

four = Browser()
require('name="api_key"' in four.get("/login.php")[0],
        "API-key login not restored once MFA disabled")
_, route = four.post("/login.php", mode="api_key", api_key=API_KEY)
require(route == "/", "legacy API-key login stopped working after MFA disabled")
require(four.get("/settings.php")[1] == "/settings.php", "API-key session lacks access when MFA off")

print("PASS: enrollment + local QR + old-session invalidation + API-key bypass rejection"
      " + password/TOTP challenge + OTP replay + single-use recovery + disable")

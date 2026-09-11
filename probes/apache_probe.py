from packaging.version import Version, InvalidVersion

def get_solr_version(url, user="", password=""):
    headers = auth_headers(user, password)

    endpoints = [
        "/admin/info/system",
        "/solr/admin/info/system",
    ]

    for endpoint in endpoints:
        try:
            r = requests.get(
                url.rstrip("/") + endpoint,
                headers=headers,
                verify=False,
                timeout=TIMEOUT
            )

            if r.status_code != 200:
                continue

            data = r.json()

            # Typical Solr response:
            # lucene -> solr-spec-version
            lucene = data.get("lucene", {})

            version = (
                lucene.get("solr-spec-version")
                or lucene.get("solr-impl-version")
                or data.get("solr-spec-version")
            )

            if version:
                return version

        except (requests.RequestException, ValueError):
            pass

    return None

def version_between(version, low, high):
    try:
        v = Version(version)
        return Version(low) <= v <= Version(high)
    except InvalidVersion:
        return False

def check_cves(version):
    results = []

    if not version:
        return results

    # CVE-2019-17558
    #
    # Solr 5.0.0 through 8.3.1 are in the affected range.
    if version_between(version, "5.0.0", "8.3.1"):
        results.append({
            "cve": "CVE-2019-17558",
            "reason": "Solr version falls within the affected version range."
        })

    # CVE-2026-44825
    #
    # Keep this separate because applicability also depends
    # on the relevant Velocity functionality/configuration.
    if version_between(version, "9.4.0", "9.10.1"):
        results.append({
            "cve": "CVE-2026-44825",
            "reason": "Solr version falls within the reported affected range."
        })

    if version_between(version, "10.0.0", "10.0.0"):
        results.append({
            "cve": "CVE-2026-44825",
            "reason": "Solr 10.0.0 is within the reported affected range."
        })

    # CVE-2020-13936 is a Velocity dependency vulnerability.
    # A Solr version alone is NOT sufficient to establish
    # whether the bundled/deployed Velocity component is affected.
    results.append({
        "cve": "CVE-2020-13936",
        "reason": "This is an Apache Velocity vulnerability; inspect the actual Velocity version/configuration."
    })

    return results


def probe(url, user="", password=""):
    print("\n[*] Probing Solr...")

    version = get_solr_version(url, user, password)

    if not version:
        print("[-] Could not determine Solr version.")
        return

    print(f"[+] Solr version: {version}")

    results = check_cves(version)

    print("\nCVE assessment:")
    print("-" * 60)

    for result in results:
        print(f"{result['cve']}: {result['status']}")
        print(f"  {result['reason']}")

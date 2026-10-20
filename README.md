# plex2shell-check

Read-only compromise check for **Plex2Shell** (CVE-2026-96652, -96654, -96655, -96656), the unauthenticated RCE chain in Plex Media Server before **1.43.3.10861** that has been exploited in the wild since 2026-10-17 to drop an XMRig miner and a residential-proxy tool.

```bash
curl -fsSLO https://raw.githubusercontent.com/ChrisLPJones/plex2shell-check/main/plex2shell-check.sh
less plex2shell-check.sh          # read it before running anything as root
sudo bash plex2shell-check.sh -o plex2shell-report.txt
```

Exit code: `0` clean, `1` warnings to review, `2` indicators of compromise found. Nothing on the system is modified.

## What it checks

1. **Version**: dpkg/rpm, PMS logs, and the local `/identity` endpoint.
2. **Exploit traces**: chain request patterns and attacker IPs in PMS logs, `dump-yuv` left in `TranscoderH264Options` in `Preferences.xml`, planted `zz<hex>.so` libraries in `Codecs/`, and codec files with the uniform padded tail that a dump-yuv write leaves.
3. **Running processes**: `mylovelyminer*`, `myawesomeproxy`, `x12345`, `xmrig`, deleted binaries running as the Plex user, non-Plex children of the transcoder, reverse shells, and deleted Codecs libraries still mapped in memory. Suspect binaries are hashed via `/proc/<pid>/exe` against known IOC hashes.
4. **Dropped files** in `/tmp`, `/var/tmp`, `/dev/shm`, Plex working dirs and the Plex data dir.
5. **Network**: live connections to known attacker IPs or the pool port (3333).
6. **Persistence**: cron, systemd units, SSH keys in the Plex home dir, and miner-like Docker containers.

Plex is discovered natively, as a snap, in Docker, and in any running container through `/proc/<pid>/root`. Running it once on a Proxmox host therefore also covers Plex inside running LXC containers. For a VM, a stopped container or a custom path, run it inside the guest or pass `-d "/path/to/Plex Media Server"`.

Options: `-d DIR` (extra data dir, repeatable), `-s DATE` (flag executables newer than this, default `2026-10-15`), `-y RULES.yar` (also run YARA rules, for example the researcher's), `-o FILE` (save the report).

## If it finds something

1. Copy `Logs/`, `Preferences.xml` and the flagged files somewhere safe.
2. Stop Plex, kill the flagged processes, delete the planted `.so` files (or the whole `Codecs/` dir, which Plex re-downloads), and remove `TranscoderH264Options` from `Preferences.xml`.
3. Update to 1.43.3.10861 or later **before** starting Plex again.
4. The chain steals the owner's token, so change your Plex password and use **Sign out of all devices**.
5. If the Plex user has sudo or docker access, or shares a uid with other services, rebuild the host or container.
6. Stop port-forwarding 32400 unless you need it.

## Indicators (from the honeypot data)

| Type | Value |
| --- | --- |
| Exploitation IPs | 45.194.92.222, 91.92.40.202, 176.65.139.228 |
| Payload hosts | 217.60.194.116, 77.90.185.205 (`/m/sh`, `/m/xmrig`, `/p/i686`) |
| Mining pool | `ota.proxystream.st:3333`, `--rig-id plex` |
| Files and processes | `/tmp/mylovelyminer<pid>` (deleted after start), `myawesomeproxy`, `x12345`, `/tmp/xsetup.lock`, `Codecs/*/zz<hex>.so` |
| SHA-256 | see `IOC_SHA256` in the script |

## Limits

PMS keeps only a few log rotations, and attackers can change names, IPs and paths. The script covers Linux only.

## Credits

Detection logic adapted from [code-zm/plex2shell](https://github.com/code-zm/plex2shell/tree/main/detection) by Zach Main ([write-up](https://zmain.info/blog/plex2shell)). In-the-wild IOCs come from [BoredHackerBlog](https://www.boredhackerblog.info/2026/10/plex-vulnerabilities-being-exploited-in.html) and its [pcaps](https://github.com/BoredHackerBlog/plex2shell_pcap).

Licensed GPL-3.0, the same license as the detection content it adapts.

#!/usr/bin/env bash
# plex2shell-check.sh - read-only compromise check for the Plex2Shell chain
#   CVE-2026-96652 / -96654 / -96655 / -96656, Plex Media Server < 1.43.3.10861
#
# Covers three questions:
#   1. Is this server vulnerable?            (PMS version)
#   2. Was the exploit attempted / did it run? (PMS logs, Preferences.xml, planted Codecs .so)
#   3. Was a payload dropped / is it live?   (miner + proxy processes, files, network, persistence)
#
# Finds Plex installs natively, in snaps, in Docker and in LXC/other containers (via /proc/<pid>/root),
# so on a Proxmox host it also sees Plex running inside any *running* LXC container.
#
# Usage: sudo ./plex2shell-check.sh [-d PLEX_DATA_DIR]... [-s SINCE_DATE] [-y RULES.yar] [-o REPORT]
#   -d DIR   "…/Library/Application Support/Plex Media Server" dir to check (repeatable; adds to auto-discovery)
#   -s DATE  flag new executables modified since DATE (default 2026-10-15, the day before the PoC went public)
#   -y FILE  also run YARA rules (e.g. detection/yara/plex2shell.yar from github.com/code-zm/plex2shell)
#   -o FILE  also write the report to FILE
#
# Exit: 0 clean, 1 warnings to review, 2 indicators of compromise found.
# Nothing on the system is modified. Run as root for full coverage.
#
# IOC sources: zmain.info/blog/plex2shell, github.com/code-zm/plex2shell/tree/main/detection,
#   boredhackerblog.info (honeypot report) and its pcap (github.com/BoredHackerBlog/plex2shell_pcap).
#
# Source: https://github.com/ChrisLPJones/plex2shell-check  (GPL-3.0; detection logic adapted from code-zm/plex2shell)

set -u
export LC_ALL=C

FIXED_BUILD="1.43.3.10861"
SINCE="2026-10-15"
HITS=0
WARNS=0
ATTEMPTS=0
DIRS=()
RULES=""
REPORT=""

# ------------------------------------------------------------------ IOCs (observed in the wild, Oct 2026)
IOC_IPS=(
    45.194.92.222    # exploitation source
    91.92.40.202     # exploitation source
    176.65.139.228   # exploitation source
    217.60.194.116   # payload host, wave 1 ("docker", "x")
    77.90.185.205    # payload host, wave 2 (/m/sh, /m/xmrig, /p/i686)
)
IOC_STRINGS='mylovelyminer|myawesomeproxy|x12345|xsetup\.lock|proxystream\.st|--rig-id plex|77\.90\.185\.205|217\.60\.194\.116|45-194-92-222\.sslip'
IOC_PROC_NAMES='^(mylovelyminer.*|myawesomeproxy|x12345|xmrig.*)$'
POOL_PORT=3333   # ota.proxystream.st:3333
declare -A IOC_SHA256=(
    [5712ef510481f15fe8b18fdd10b73026d57cb3d9d151878a692358b99a464441]="docker (wave-1 dropper)"
    [68938fb428f2bcfef4ede62f7b29cd0f15f37ed59e94462c099f2ca64e36baa7]="x (UPX packed)"
    [b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49]="x (unpacked)"
    [e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9]="myawesomeproxy"
    [2d3c618b21a7e2f8bcd735da188e44a7609ff3f204832dd0781cd09e4388c9db]="xmrig"
)

# ------------------------------------------------------------------ output helpers
if [ -t 1 ]; then R=$'\e[1;31m' Y=$'\e[1;33m' G=$'\e[32m' B=$'\e[1m' N=$'\e[0m'; else R='' Y='' G='' B='' N=''; fi
hit()     { HITS=$((HITS + 1));   printf '%s[HIT]%s  %s\n' "$R" "$N" "$*"; }
attempt() { ATTEMPTS=$((ATTEMPTS + 1)); printf '%s[ATTEMPT]%s %s\n' "$Y" "$N" "$*"; }
warn()    { WARNS=$((WARNS + 1)); printf '%s[WARN]%s %s\n' "$Y" "$N" "$*"; }
ok()      { printf '%s[OK]%s   %s\n' "$G" "$N" "$*"; }
info()    { printf '[INFO] %s\n' "$*"; }
section() { printf '\n%s== %s%s\n' "$B" "$*" "$N"; }
indent()  { cut -c1-300 | sed 's/^/         /'; }

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
while getopts "d:s:y:o:h" opt; do
    case "$opt" in
        d) DIRS+=("$OPTARG") ;;
        s) SINCE="$OPTARG" ;;
        y) RULES="$OPTARG" ;;
        o) REPORT="$OPTARG" ;;
        *) usage ;;
    esac
done

if [ -n "$REPORT" ]; then
    exec > >(tee "$REPORT") 2>&1
fi

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# ------------------------------------------------------------------ process helpers
proc_exe()  { readlink "/proc/$1/exe" 2>/dev/null; }
proc_name() { local e; e=$(proc_exe "$1") && { basename -- "${e% (deleted)}"; return; }; cat "/proc/$1/comm" 2>/dev/null; }
proc_cmd()  { { tr '\0\n' '  ' < "/proc/$1/cmdline"; } 2>/dev/null | cut -c1-250; }   # pids can vanish mid-scan
proc_ppid() { local s; s=$(cat "/proc/$1/stat" 2>/dev/null) || return; s=${s##*) }; set -- $s; echo "$2"; }
proc_uid()  { awk '/^Uid:/{print $2}' "/proc/$1/status" 2>/dev/null; }
proc_pidns() { readlink "/proc/$1/ns/pid" 2>/dev/null; }

# A binary that ships with Plex (install dir or a Plex-downloaded codec helper)
is_plex_binary() {
    case "$1" in
        */plexmediaserver/*|*/Plex\ Media\ Server/Codecs/EasyAudioEncoder*|*/usr/lib/plexmediaserver*) return 0 ;;
    esac
    return 1
}

# PIDs of the main PMS process(es); comm is truncated to 15 chars
PMS_PIDS=()
for pd in /proc/[0-9]*; do
    [ "$(cat "$pd/comm" 2>/dev/null)" = "Plex Media Serv" ] && PMS_PIDS+=("${pd#/proc/}")
done

# ------------------------------------------------------------------ discovery
declare -A SEEN_DIR=()
declare -A DIR_ROOT=()   # data dir -> filesystem root it lives under ("" for host, /proc/PID/root for containers)
add_dir() {   # add_dir DIR ROOT
    local d="$1" key
    [ -d "$d" ] || return
    key=$(stat -L -c '%d:%i' -- "$d" 2>/dev/null) || return
    [ -n "${SEEN_DIR[$key]:-}" ] && return
    SEEN_DIR[$key]=1
    DIRS_FOUND+=("$d")
    DIR_ROOT["$d"]="$2"
}

DIRS_FOUND=()
for d in "${DIRS[@]}"; do add_dir "$d" ""; done

REL_DEFAULTS=(
    "var/lib/plexmediaserver/Library/Application Support/Plex Media Server"
    "config/Library/Application Support/Plex Media Server"
    "var/snap/plexmediaserver/common/Library/Application Support/Plex Media Server"
    "snap/plexmediaserver/common/Library/Application Support/Plex Media Server"
)
for rel in "${REL_DEFAULTS[@]}"; do add_dir "/$rel" ""; done

# Running PMS processes: works for native, Docker, LXC, anything with its own mount namespace
for pid in "${PMS_PIDS[@]}"; do
    root="/proc/$pid/root"
    asd=$({ tr '\0' '\n' < "/proc/$pid/environ"; } 2>/dev/null | sed -n 's/^PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR=//p')
    [ -n "$asd" ] && add_dir "$root$asd/Plex Media Server" "$root"
    for rel in "${REL_DEFAULTS[@]}"; do add_dir "$root/$rel" "$root"; done
done

# Docker containers (also catches stopped ones)
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    while read -r id image; do
        src=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/config"}}{{.Source}}{{end}}{{end}}' "$id" 2>/dev/null)
        [ -n "$src" ] && add_dir "$src/Library/Application Support/Plex Media Server" ""
    done < <(docker ps -a --format '{{.ID}} {{.Image}}' 2>/dev/null | awk 'tolower($2) ~ /plex/')
fi

# ================================================================== report
printf '%splex2shell-check%s  %s  host=%s  root=%s\n' "$B" "$N" "$(date -u +%FT%TZ)" "$(hostname)" "$([ $IS_ROOT -eq 1 ] && echo yes || echo NO)"
[ $IS_ROOT -eq 1 ] || warn "NOT RUNNING AS ROOT: Preferences.xml, Plex's processes and container filesystems can't be inspected, so a clean result is incomplete. Re-run with: sudo bash $0"

if [ ${#DIRS_FOUND[@]} -eq 0 ]; then
    warn "no Plex data directory found. If Plex runs in a stopped container/VM or a custom path, pass it with -d"
else
    info "Plex data dir(s):"
    printf '%s\n' "${DIRS_FOUND[@]}" | indent
fi
[ ${#PMS_PIDS[@]} -gt 0 ] && info "running Plex Media Server PID(s): ${PMS_PIDS[*]}" || info "no running Plex Media Server process found"

# ------------------------------------------------------------------ 1. version
version_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

check_version() {   # check_version LABEL VERSION
    local v
    v=$(printf '%s' "$2" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -z "$v" ]; then
        return 1
    elif version_lt "$v" "$FIXED_BUILD"; then
        warn "$1: PMS $v is VULNERABLE (fixed in $FIXED_BUILD) - update now"
    else
        ok "$1: PMS $v >= $FIXED_BUILD (patched)"
    fi
}

section "1. Plex version"
vchecked=0
for d in "${DIRS_FOUND[@]}"; do
    root=${DIR_ROOT[$d]}
    v=""
    # package database inside the same root (host, LXC or Docker image)
    if [ -f "$root/var/lib/dpkg/status" ]; then
        v=$(awk '/^Package: plexmediaserver$/{f=1} f&&/^Version:/{print $2; exit}' "$root/var/lib/dpkg/status")
    fi
    if [ -z "$v" ] && [ -z "$root" ] && command -v rpm >/dev/null 2>&1; then
        v=$(rpm -q --qf '%{VERSION}' plexmediaserver 2>/dev/null) || v=""
    fi
    # most recent version PMS logged at startup
    if [ -z "$v" ]; then
        v=$(grep -ahoE 'Plex Media Server v[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$d"/Logs/Plex\ Media\ Server*.log 2>/dev/null | sed 's/.* v//' | sort -V | tail -1)
    fi
    check_version "$d" "$v" && vchecked=1
done
if command -v curl >/dev/null 2>&1; then
    v=$(curl -s -m 3 http://127.0.0.1:32400/identity 2>/dev/null | grep -oE 'version="[^"]+"')
    [ -n "$v" ] && check_version "live server on 127.0.0.1:32400" "$v" && vchecked=1
fi
[ $vchecked -eq 1 ] || warn "could not determine the PMS version - check Settings > General in Plex Web and make sure it is >= $FIXED_BUILD"

# ------------------------------------------------------------------ 2. exploit traces in Plex data
# Stage 1: the unauthenticated SSRF request. A patched server answers it with 400 "unsupported protocol".
LOG_ATTEMPT='/player/timeline/subscribe\?([^ ]*&)?protocol=[a-z0-9+.-]{1,16}(%3a|%253a|:)'
# Lines that only echo a stage-1 request (the request itself, its response, the rejection warning)
LOG_ATTEMPT_ECHO='/player/timeline/subscribe\?|unsupported protocol'
# Later stages: these only appear if the server actually processed the chain
LOG_HIGH=(
    'searchOne\?[^ ]*identifier=[^& ]*(%2f|%252f|/)function(%2f|%252f|/)'
    'GetResultFromNetwork'
    'TranscoderH264Options(=|%3d)[^& ]*(dump(-|%2d)yuv|stats(=|%3d))'
    'dump-yuv='
)
LOG_MED=(
    'resources/[^? ]*\?([^ ]*&)?resource_name=(%2f|%5c|/|\\|[a-z](%3a|:)|[^& ]*(\.\.|%2e%2e))'
    '(sslip|nip)\.io'
    'X-Plex-Client-Identifier=(vfyclient01|poc_[0-9a-f])|X-Plex-Target-Client-Identifier=poc_|/TKN_[0-9a-f]|X-Plex-Token=TOTALLY_INVALID_JUNK'
    'transcode/universal/[^ ]*[?&]path=https?(%3a|:)(%2f|/){2}'
)

check_prefs() {
    local p="$1/Preferences.xml" val
    [ -f "$p" ] || { info "no Preferences.xml"; return; }
    [ -r "$p" ] || { warn "Preferences.xml: not readable - run as root to check it"; return; }
    val=$(grep -oE 'TranscoderH264Options="[^"]*"' "$p")
    if [ -z "$val" ]; then
        ok "Preferences.xml: TranscoderH264Options not set"
    elif printf '%s' "$val" | grep -qiE 'dump-yuv|stats='; then
        hit "Preferences.xml: file-writing x264 option left behind by the exploit: $val"
    elif [ "$val" = 'TranscoderH264Options=""' ]; then
        warn "Preferences.xml: TranscoderH264Options present but empty - the exploit clears it this way after use (an admin toggling it does the same)"
    else
        warn "Preferences.xml: non-default TranscoderH264Options: $val"
    fi
}

check_logs() {
    local logs=() f m pat ip
    while IFS= read -r -d '' f; do logs+=("$f"); done \
        < <(find "$1/Logs" -maxdepth 2 -type f -name '*.log*' -print0 2>/dev/null)
    if [ ${#logs[@]} -eq 0 ]; then info "no logs under $1/Logs"; return; fi
    m=$(grep -ahoE '^[A-Z][a-z]{2} [0-9]{2}, [0-9]{4}' "${logs[@]}" 2>/dev/null | sort -u | head -1)
    info "scanning ${#logs[@]} log file(s)${m:+, oldest entry ~ $m}. PMS keeps few rotations; copy Logs/ somewhere safe now if you find anything"
    # Stage 1: who tried, when, and whether the server accepted it
    local reqs accepted
    reqs=$(grep -ahiE -- "Request: .*$LOG_ATTEMPT" "${logs[@]}" 2>/dev/null)
    if [ -n "$reqs" ]; then
        accepted=$(grep -ahiE -- "Completed: \[[^]]*\] 2[0-9][0-9] [A-Z]+ $LOG_ATTEMPT" "${logs[@]}" 2>/dev/null)
        if [ -n "$accepted" ]; then
            hit "log: exploit SSRF request ACCEPTED by the server (2xx) - the server was vulnerable when this ran"
            printf '%s\n' "$accepted" | head -4 | indent
        else
            attempt "log: exploit attempted but REJECTED by the server ($(printf '%s\n' "$reqs" | wc -l) request(s), none answered 2xx)"
        fi
        info "exploit attempts by source (count, source ip, first seen, last seen):"
        printf '%s\n' "$reqs" | sed -nE 's/^([A-Z][a-z]{2} [0-9]{2}, [0-9]{4} [0-9:]{8}).*Request: \[([^]:]+):[0-9]+ \(([^)]*)\)\].*/\2 (\3)\t\1/p' \
            | sort -s -t$'\t' -k1,1 | awk -F'\t' '{n[$1]++; if(!($1 in f)) f[$1]=$2; l[$1]=$2} END {for (k in n) printf "%5d  %s  %s  ->  %s\n", n[k], k, f[k], l[k]}' | indent
        info "a LAN/Subnet source means a device on your own network sent it (you testing, or a compromised machine)"
    fi
    # Later stages: only lines that are not just an echo of a stage-1 request
    local rest
    rest=$(grep -ahivE -- "$LOG_ATTEMPT_ECHO" "${logs[@]}" 2>/dev/null)
    for pat in "${LOG_HIGH[@]}"; do
        m=$(printf '%s\n' "$rest" | grep -aiE -- "$pat")
        [ -n "$m" ] && { hit "log: later exploit stage executed /$pat/ ($(printf '%s\n' "$m" | wc -l) lines)"; printf '%s\n' "$m" | head -4 | indent; }
    done
    for pat in "${LOG_MED[@]}"; do
        m=$(printf '%s\n' "$rest" | grep -aiE -- "$pat" | grep -viE 'path=https?(%3a|:)(%2f|/){2}(127\.0\.0\.1|localhost)')
        [ -n "$m" ] && { warn "log: suspicious /$pat/ ($(printf '%s\n' "$m" | wc -l) lines)"; printf '%s\n' "$m" | head -4 | indent; }
    done
    for ip in "${IOC_IPS[@]}"; do
        m=$(grep -ahF -- "$ip" "${logs[@]}" 2>/dev/null)
        [ -n "$m" ] && { hit "log: requests from/to known attacker IP $ip ($(printf '%s\n' "$m" | wc -l) lines)"; printf '%s\n' "$m" | head -3 | indent; }
    done
    m=$(grep -ahiE -- "$IOC_STRINGS" "${logs[@]}" 2>/dev/null)
    [ -n "$m" ] && { hit "log: payload strings ($(printf '%s\n' "$m" | wc -l) lines)"; printf '%s\n' "$m" | head -3 | indent; }
    [ -z "$(grep -lahiE 'player/timeline|searchOne|dump-yuv' "${logs[@]}" 2>/dev/null)" ] && ok "logs: no exploit request patterns"
}

magic() { head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n'; }
# The dump-yuv write leaves the payload followed by a long run of one repeated byte (raw frame padding)
tail_uniform() { [ "$(tail -c 65536 -- "$1" | od -An -v -tx1 | tr -s ' ' '\n' | sed '/^$/d' | sort -u | head -2 | wc -l)" -eq 1 ]; }

check_codecs() {
    local cdir="$1/Codecs" f mg sz n=0 bad=0 base
    [ -d "$cdir" ] || { info "no Codecs dir"; return; }
    while IFS= read -r -d '' f; do
        n=$((n + 1))
        base=$(basename -- "$f")
        case "$base" in
            zz[0-9a-f]*.so) hit "Codecs: planted library (exploit naming, e.g. zzf83c7d6d.so): $f  mtime $(stat -c %y -- "$f" | cut -c1-19)"; bad=1 ;;
        esac
        mg=$(magic "$f")
        case "$mg" in 7f454c46*|4d5a*) ;; *) continue ;; esac
        sz=$(stat -c %s -- "$f")
        if [ "$sz" -ge 131072 ] && tail_uniform "$f"; then
            hit "Codecs: binary with uniform 64 KiB tail (the shape dump-yuv writes): $f ($sz B, mtime $(stat -c %y -- "$f" | cut -c1-19))"
            bad=1
        fi
        if grep -qaE -- "$IOC_STRINGS|/dev/tcp/|exec /usr/bin/script -qc" "$f" 2>/dev/null; then
            hit "Codecs: binary contains payload/reverse-shell strings: $f"; bad=1
        fi
    done < <(find "$cdir" -type f -print0 2>/dev/null)
    [ $bad -eq 0 ] && ok "Codecs: $n file(s), nothing planted"
    if [ $bad -eq 1 ]; then
        info "the planted .so re-runs the payload every time Plex transcodes - killing the miner alone does not stop it"
    fi
}

check_new_executables() {   # ELF/scripts written into the data dir (outside Codecs) since $SINCE
    local f out=""
    while IFS= read -r -d '' f; do
        case "$(magic "$f")" in
            7f454c46*|2321*) out+="$f  ($(stat -c '%y' -- "$f" | cut -c1-19))"$'\n' ;;
        esac
    done < <(find "$1" \( -path "$1/Metadata" -o -path "$1/Media" -o -path "$1/Cache" -o -path "$1/Codecs" \
                          -o -path "$1/Plug-in Support" -o -path "$1/Logs" -o -path "$1/Crash Reports" \) -prune \
                     -o -type f -size -64M -newermt "$SINCE" -print0 2>/dev/null)
    if [ -n "$out" ]; then
        warn "executables/scripts written in the Plex data dir since $SINCE (the dropper writes 'myawesomeproxy' into its working dir):"
        printf '%s' "$out" | head -20 | indent
    fi
}

check_yara() {
    [ -n "$RULES" ] || return
    if ! command -v yara >/dev/null 2>&1; then warn "-y given but yara is not installed"; return; fi
    local y
    y=$(yara -r -w "$RULES" "$1" 2>/dev/null)
    if [ -n "$y" ]; then hit "YARA matches:"; printf '%s\n' "$y" | indent; else ok "YARA: no matches"; fi
}

section "2. Exploit traces in Plex data"
for d in "${DIRS_FOUND[@]}"; do
    printf '%s-- %s%s\n' "$B" "$d" "$N"
    check_prefs "$d"
    check_logs "$d"
    check_codecs "$d"
    check_new_executables "$d"
    check_yara "$d"
done

# ------------------------------------------------------------------ 3. live processes
section "3. Running processes"
declare -A PLEX_NS=()      # pid namespaces Plex runs in
declare -A PLEX_UIDS=()    # uids Plex runs as (per namespace)
HOST_NS=$(proc_pidns self)
for pid in "${PMS_PIDS[@]}"; do
    ns=$(proc_pidns "$pid"); u=$(proc_uid "$pid")
    [ -n "$ns" ] || { [ $IS_ROOT -eq 1 ] || warn "can't inspect Plex process $pid without root - the process checks below are incomplete"; continue; }
    PLEX_NS[$ns]=1; PLEX_UIDS["$ns:$u"]=1
done
PLEX_USER_UID=$(id -u plex 2>/dev/null || true)
[ -n "$PLEX_USER_UID" ] && PLEX_UIDS["$HOST_NS:$PLEX_USER_UID"]=1

SUSPECT_PIDS=()
proc_hits=0
for pd in /proc/[0-9]*; do
    pid=${pd#/proc/}
    [ "$pid" = "$$" ] && continue
    exe=$(proc_exe "$pid") || exe=""
    name=$(proc_name "$pid")
    comm=$(cat "$pd/comm" 2>/dev/null)
    cmd=$(proc_cmd "$pid")
    [ -n "$name$cmd" ] || continue
    ns=$(proc_pidns "$pid"); u=$(proc_uid "$pid")
    flagged=0

    # known payload names (comm is what the dropper itself checks for)
    if printf '%s\n%s\n' "$comm" "$name" | grep -qE "$IOC_PROC_NAMES"; then
        hit "pid $pid: known payload process '$comm' exe=$exe cmd=$cmd"; flagged=1
    elif printf '%s' "$cmd" | grep -qE -- "$IOC_STRINGS"; then
        hit "pid $pid: command line matches payload IOCs: $cmd"; flagged=1
    elif printf '%s' "$cmd" | grep -qE -- '--rig-id|stratum\+tcp|-o [^ ]+:3333|/dev/(tcp|udp)/'; then
        hit "pid $pid: miner / reverse-shell style command line: $cmd"; flagged=1
    fi

    # anything mapping a deleted library from a Codecs dir (payload loaded, then removed)
    if grep -F '/Codecs/' "$pd/maps" 2>/dev/null | grep -qF '(deleted)'; then
        hit "pid $pid ($name) has a deleted file from a Plex Codecs dir mapped in memory"; flagged=1
    fi

    # processes in Plex's container / running as Plex's user that aren't Plex
    if [ -n "${PLEX_UIDS["$ns:$u"]:-}" ] && ! is_plex_binary "${exe% (deleted)}"; then
        case "$exe" in
            *" (deleted)")
                hit "pid $pid: runs as the Plex user from a DELETED binary $exe (the miner deletes itself from /tmp): $cmd"; flagged=1 ;;
            /tmp/*|/var/tmp/*|/dev/shm/*|*/Plex\ Media\ Server/*)
                hit "pid $pid: runs as the Plex user from a writable dir: $exe $cmd"; flagged=1 ;;
            *)
                pp=$(proc_ppid "$pid"); pn=$(proc_name "$pp")
                case "$pn" in
                    "Plex Transcoder"|"Plex Media Server"|"Plex Script Host")
                        hit "pid $pid: '$name' spawned by $pn (pid $pp): $cmd"; flagged=1 ;;
                    *)
                        # linuxserver/hotio images run s6 etc. as the same uid; only report, don't alarm
                        [ "$ns" != "$HOST_NS" ] || [ "$u" = "${PLEX_USER_UID:-x}" ] && \
                            { warn "pid $pid: non-Plex process '$name' running as the Plex user: $cmd"; flagged=1; } ;;
                esac ;;
        esac
    fi

    # any process (any user) running a deleted binary out of /tmp-style dirs
    if [ $flagged -eq 0 ]; then
        case "$exe" in
            /tmp/*" (deleted)"|/var/tmp/*" (deleted)"|/dev/shm/*" (deleted)")
                warn "pid $pid: running from a deleted binary in a temp dir: $exe $cmd"; flagged=1 ;;
        esac
    fi

    if [ $flagged -eq 1 ]; then
        SUSPECT_PIDS+=("$pid"); proc_hits=1
        # the miner's file is deleted, but /proc/PID/exe still lets us hash it
        if [ -r "$pd/exe" ]; then
            h=$(sha256sum < "$pd/exe" 2>/dev/null | cut -d' ' -f1)
            [ -n "$h" ] && { printf '         sha256 %s%s\n' "$h" "${IOC_SHA256[$h]:+  <- known IOC: ${IOC_SHA256[$h]}}"; [ -n "${IOC_SHA256[$h]:-}" ] && hit "pid $pid binary matches known IOC hash (${IOC_SHA256[$h]})"; }
        fi
        printf '         cpu-time %s  started %s  cwd %s\n' "$(ps -o time= -p "$pid" 2>/dev/null | tr -d ' ')" \
            "$(ps -o lstart= -p "$pid" 2>/dev/null)" "$(readlink "$pd/cwd" 2>/dev/null)"
    fi
done
[ $proc_hits -eq 0 ] && ok "no miner, proxy, reverse shell or stray Plex-user processes running"

# High CPU from the Plex user while nothing is transcoding is the main user-visible symptom
top=$(ps -eo pid=,uid=,pcpu=,comm= --sort=-pcpu 2>/dev/null | head -8)
info "top CPU consumers (pid uid %cpu name):"
printf '%s\n' "$top" | indent

# ------------------------------------------------------------------ 4. files dropped by the payload
section "4. Dropped files"
ROOTS=("")
declare -A SEEN_ROOT=()
for pid in "${PMS_PIDS[@]}"; do
    r="/proc/$pid/root"
    k=$(stat -L -c '%d:%i' "$r/" 2>/dev/null) || continue
    [ "$k" = "$(stat -L -c '%d:%i' / 2>/dev/null)" ] && continue
    [ -n "${SEEN_ROOT[$k]:-}" ] && continue
    SEEN_ROOT[$k]=1; ROOTS+=("$r")
done

file_hits=0
scan_file() {   # scan_file PATH  - hash + strings check on one candidate
    local f="$1" h
    h=$(sha256sum -- "$f" 2>/dev/null | cut -d' ' -f1)
    if [ -n "${IOC_SHA256[$h]:-}" ]; then
        hit "known IOC file (${IOC_SHA256[$h]}): $f"; file_hits=1; return
    fi
    case "$(basename -- "$f")" in
        myawesomeproxy|mylovelyminer*|x12345|xsetup.lock)
            hit "payload file name: $f ($(stat -c '%s B, %y' -- "$f" | cut -c1-40))"; file_hits=1; return ;;
    esac
    if grep -qaE -- "$IOC_STRINGS" "$f" 2>/dev/null; then
        hit "file contains payload IOC strings: $f"; file_hits=1; return
    fi
    case "$(magic "$f")" in
        7f454c46*)
            if grep -qa 'UPX!' "$f" 2>/dev/null; then
                warn "UPX-packed ELF in a temp dir (wave-1 payload 'x' was UPX packed): $f"; file_hits=1
            fi ;;
    esac
}

for r in "${ROOTS[@]}"; do
    label=${r:-host}
    for t in tmp var/tmp dev/shm; do
        [ -d "$r/$t" ] || continue
        while IFS= read -r -d '' f; do scan_file "$f"; done \
            < <(find "$r/$t" -xdev -maxdepth 3 -type f -size -64M -print0 2>/dev/null)
    done
    [ -e "$r/tmp/xsetup.lock" ] && { hit "[$label] dropper lock file present: /tmp/xsetup.lock ($(stat -c %y "$r/tmp/xsetup.lock" | cut -c1-19))"; file_hits=1; }
done
# working dirs of Plex processes (the proxy is downloaded into the dropper's cwd) and the data dirs
for pid in "${PMS_PIDS[@]}"; do
    c=$(readlink "/proc/$pid/cwd" 2>/dev/null) || continue
    for f in "/proc/$pid/root$c"/*; do [ -f "$f" ] && scan_file "$f"; done
done
for d in "${DIRS_FOUND[@]}"; do
    while IFS= read -r -d '' f; do scan_file "$f"; done \
        < <(find "$d" \( -path "$d/Metadata" -o -path "$d/Media" -o -path "$d/Cache" \) -prune -o -type f \
                 \( -name myawesomeproxy -o -name 'mylovelyminer*' -o -name x12345 -o -name xmrig -o -name 'zz*.so' \) -print0 2>/dev/null)
    # Plex home (one level above Library/) - wget/curl drops land here when cwd is the home dir
    h="${d%/Library/Application Support/Plex Media Server}"
    for f in "$h"/*; do [ -f "$f" ] && scan_file "$f"; done
done
[ $file_hits -eq 0 ] && ok "no payload files in temp dirs, Plex working dirs or Plex data"

# ------------------------------------------------------------------ 5. network
section "5. Network connections"
net_hits=0
hex_to_ip4() { printf '%d.%d.%d.%d' "0x${1:6:2}" "0x${1:4:2}" "0x${1:2:2}" "0x${1:0:2}"; }
declare -A SEEN_NETNS=()
scan_netns() {   # scan_netns PID LABEL - established IPv4 TCP connections in that process's network namespace
    local pid=$1 label=$2 ns line rem rip rport st ioc
    ns=$(readlink "/proc/$pid/ns/net" 2>/dev/null) || return
    [ -n "${SEEN_NETNS[$ns]:-}" ] && return
    SEEN_NETNS[$ns]=1
    while read -r _ _ rem st _; do
        [ "$st" = "01" ] || continue
        rip=$(hex_to_ip4 "${rem%:*}"); rport=$((16#${rem#*:}))
        for ioc in "${IOC_IPS[@]}"; do
            [ "$rip" = "$ioc" ] && { hit "[$label] live connection to attacker IP $rip:$rport"; net_hits=1; }
        done
        [ "$rport" -eq "$POOL_PORT" ] && { hit "[$label] live connection to $rip:$POOL_PORT (the miner's pool port, ota.proxystream.st:3333)"; net_hits=1; }
    done < <(tail -n +2 "/proc/$pid/net/tcp" 2>/dev/null)
}
scan_netns self host
for pid in "${PMS_PIDS[@]}" "${SUSPECT_PIDS[@]}"; do scan_netns "$pid" "netns of pid $pid"; done
if [ ${#SUSPECT_PIDS[@]} -gt 0 ] && command -v ss >/dev/null 2>&1; then
    for pid in "${SUSPECT_PIDS[@]}"; do
        c=$(ss -tnpH 2>/dev/null | grep -F "pid=$pid,")
        [ -n "$c" ] && { info "connections of suspect pid $pid:"; printf '%s\n' "$c" | indent; }
    done
fi
[ $net_hits -eq 0 ] && ok "no connections to known attacker IPs or the mining pool port"

# Exposure: is 32400 reachable from outside this box?
if command -v ss >/dev/null 2>&1; then
    l=$(ss -tlnH 2>/dev/null | awk '$4 ~ /:32400$/ {print $4}' | sort -u | tr '\n' ' ')
    [ -n "$l" ] && info "port 32400 listening on: $l- if this is port-forwarded to the internet, that is how the chain gets in"
fi

# ------------------------------------------------------------------ 6. persistence
section "6. Persistence"
pers_hits=0
# pkg_unmodified ROOT PATH: true if PATH belongs to a dpkg/rpm package and still matches the package checksum
pkg_unmodified() {
    local r="${1:-/}" f="$2" pkg cand
    for cand in "$f" "/usr$f" "${f#/usr}"; do
        if command -v dpkg-query >/dev/null 2>&1 && [ -d "$r/var/lib/dpkg" ]; then
            pkg=$(dpkg-query --admindir="$r/var/lib/dpkg" -S "$cand" 2>/dev/null | head -1 | cut -d: -f1)
            if [ -n "$pkg" ]; then
                dpkg --root="$r" --verify "$pkg" 2>/dev/null | grep -qF -- "/${f##*/}" && return 1
                return 0
            fi
        fi
    done
    if [ "$r" = / ] && command -v rpm >/dev/null 2>&1 && rpm -qf "$f" >/dev/null 2>&1; then
        rpm -Vf "$f" 2>/dev/null | grep -qF -- "/${f##*/}" && return 1
        return 0
    fi
    return 1
}
for r in "${ROOTS[@]}"; do
    label=${r:-host}
    # cron
    for f in "$r"/var/spool/cron/crontabs/* "$r"/var/spool/cron/* "$r"/etc/cron.d/* "$r"/etc/crontab; do
        [ -f "$f" ] || continue
        if grep -qaE -- "$IOC_STRINGS|wget .*\| *sh|curl .*\| *sh|/m/sh" "$f" 2>/dev/null; then
            hit "[$label] cron entry with payload/dropper pattern: $f"; grep -aE -- "$IOC_STRINGS|wget|curl" "$f" | indent; pers_hits=1
        elif [ -n "$(find "$f" -newermt "$SINCE" 2>/dev/null)" ]; then
            warn "[$label] cron file changed since $SINCE: $f"; pers_hits=1
        fi
    done
    # systemd units (package updates, e.g. the Plex update itself, legitimately touch these)
    declare -A seen_unit=()
    while IFS= read -r -d '' f; do
        k=$(stat -L -c '%d:%i' -- "$f" 2>/dev/null); [ -n "${seen_unit[$k]:-}" ] && continue; seen_unit[$k]=1
        if grep -qaE -- "$IOC_STRINGS" "$f" 2>/dev/null; then hit "[$label] systemd unit with payload strings: $f"; pers_hits=1
        elif pkg_unmodified "$r" "${f#"$r"}"; then :
        else warn "[$label] systemd unit created/changed since $SINCE and not an unmodified package file: $f"; pers_hits=1; fi
    done < <(find "$r/etc/systemd/system" "$r/lib/systemd/system" "$r/usr/lib/systemd/system" -maxdepth 2 -type f -newermt "$SINCE" -print0 2>/dev/null)
    # Plex user's home: ssh keys, shell rc, user units
    for home in "$r/var/lib/plexmediaserver" "$r/config"; do
        [ -d "$home" ] || continue
        for f in "$home/.ssh/authorized_keys" "$home/.bashrc" "$home/.profile" "$home/.config/systemd/user"; do
            [ -e "$f" ] || continue
            if [ "${f##*/}" = authorized_keys ]; then
                warn "[$label] SSH authorized_keys exists in the Plex service home: $f"; pers_hits=1
            elif [ -n "$(find "$f" -maxdepth 2 -newermt "$SINCE" 2>/dev/null | head -1)" ]; then
                warn "[$label] changed since $SINCE in Plex home: $f"; pers_hits=1
            fi
        done
    done
done
[ $pers_hits -eq 0 ] && ok "no cron/systemd/ssh persistence found (note: the planted Codecs .so is itself the persistence - see section 2)"

# Docker: miner containers / containers created after the PoC went public
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    c=$(docker ps -a --format '{{.ID}} {{.Image}} {{.CreatedAt}} {{.Names}} {{.Command}}' 2>/dev/null)
    m=$(printf '%s\n' "$c" | grep -iE 'xmrig|miner|proxy|monero')
    [ -n "$m" ] && { warn "docker containers with miner/proxy-like names - confirm you created these:"; printf '%s\n' "$m" | indent; }
    n=$(printf '%s\n' "$c" | awk -v s="$SINCE" '$3 >= s')
    [ -n "$n" ] && { info "docker containers created since $SINCE (check you recognise them):"; printf '%s\n' "$n" | indent; }
fi

# ------------------------------------------------------------------ verdict
section "Summary"
printf '%d hit(s), %d blocked attempt(s), %d warning(s)\n\n' "$HITS" "$ATTEMPTS" "$WARNS"
if [ "$HITS" -gt 0 ]; then
    printf '%sINDICATORS OF COMPROMISE FOUND.%s Suggested response:\n' "$R" "$N"
    cat <<'EOF'
  1. Preserve evidence first: copy the Plex Logs/ dir, Preferences.xml and any flagged files.
  2. Stop Plex, kill flagged PIDs, delete planted zz*.so files from Codecs/ (or delete the whole
     Codecs/ dir - Plex re-downloads it), and remove TranscoderH264Options from Preferences.xml.
  3. Update PMS to 1.43.3.10861 or later BEFORE starting it again.
  4. The chain steals the owner's admin token: change your Plex account password and use
     "Sign out of all devices" at plex.tv, which invalidates old tokens.
  5. Code ran as the Plex user. If that user has sudo, docker group membership, or shares a uid
     with other services, treat the whole host/container as compromised and rebuild it.
  6. Stop port-forwarding 32400 unless you need it; block the IOC IPs at your firewall.
EOF
elif [ "$ATTEMPTS" -gt 0 ]; then
    printf '%sEXPLOIT ATTEMPTED BUT BLOCKED.%s The server rejected the first stage and no later stage,\n' "$Y" "$N"
    printf 'planted file or payload was found. Nothing on this server needs cleaning up, but:\n'
    printf '  - identify the source IP(s) listed in section 2; if it was not you testing, investigate that machine\n'
    printf '  - if Plex was ever on a vulnerable build while reachable, change your Plex password and sign out all devices\n'
    [ $IS_ROOT -eq 1 ] || printf '  - re-run as root: this run could not check Preferences.xml or Plex'"'"'s processes\n'
elif [ "$WARNS" -gt 0 ]; then
    printf '%sReview the warnings above.%s A vulnerable version alone does not mean you were hit, but\n' "$Y" "$N"
    printf 'if 32400 was exposed to the internet on a vulnerable build, update and rotate your Plex password.\n'
else
    printf '%sNo indicators found.%s\n' "$G" "$N"
fi
printf '\nLimits: logs only go back a few rotations; attackers can change names, IPs and paths.\n'

[ "$HITS" -gt 0 ] && exit 2
[ "$WARNS" -gt 0 ] || [ "$ATTEMPTS" -gt 0 ] && exit 1
exit 0

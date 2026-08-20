import subprocess
import sys
import ctypes
import os

def _ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        print("\n not running as administrator relaunching with elevation", flush=True)
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas",
                sys.executable,
                " ".join(f'"{a}"' for a in sys.argv),
                None, 1
            )
        except Exception as e:
            print(f" failed to elevate {e}", flush=True)
            input(" press enter to continue without admin some features disabled ")
        sys.exit(0)

_ensure_admin()

def install_deps():
    pkgs = ["pefile", "yara-python", "colorama"]
    for pkg in pkgs:
        mod = pkg.replace("-python", "").replace("-", "_")
        try:
            __import__(mod)
        except ImportError:
            print(f" installing dependency {pkg}", flush=True)
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

print("\n please wait setting up dependencies", flush=True)
install_deps()

import re
import mmap
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import colorama

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

colorama.init(autoreset=True)

class c_logger:
    def __init__(self):
        self.time_c = "\x1b[38;2;74;105;107m"
        self.tag_c  = "\x1b[38;2;112;156;123m"
        self.text_c = "\x1b[37m"
        self.warn_c = "\x1b[38;2;210;150;70m"
        self.err_c  = "\x1b[38;2;220;70;70m"
        self.succ_c = "\x1b[38;2;70;200;90m"
        self.dim_c  = "\x1b[38;2;100;100;100m"
        self.reset  = "\x1b[0m"

    def _ts(self):
        return datetime.now().strftime("%m %d %Y %H %M %S")

    def out(self, msg, level="info"):
        color = self.text_c
        if level == "warn": color = self.warn_c
        elif level == "error" or level == "act": color = self.err_c
        elif level == "success" or level == "clean": color = self.succ_c
        elif level == "dim": color = self.dim_c

        print(
            f"{self.time_c}{self._ts()}{self.reset} "
            f"{self.tag_c}lucky{self.reset} "
            f"{color}{msg}{self.reset}"
        )

    def inp(self, prompt, return_type=str):
        val = input(
            f"{self.time_c}{self._ts()}{self.reset} "
            f"{self.tag_c}lucky{self.reset} "
            f"{self.text_c}{prompt} {self.reset}"
        )
        try:
            return return_type(val)
        except Exception:
            return val

log = c_logger()

def setup_console(title="lucky killer"):
    os.system(f"title {title}")
    kernel32 = ctypes.windll.kernel32
    
    std_handle = kernel32.GetStdHandle(-11) 
    mode = ctypes.c_uint32()
    kernel32.GetConsoleMode(std_handle, ctypes.byref(mode))
    mode.value |= 0x0004 
    kernel32.SetConsoleMode(std_handle, mode)

    os.system("mode con cols=120 lines=45")

    try:
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            GWL_EXSTYLE = -20
            WS_EX_LAYERED = 0x00080000
            LWA_ALPHA = 0x00000002
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED)
            ctypes.windll.user32.SetLayeredWindowAttributes(hwnd, 0, 235, LWA_ALPHA)
    except Exception:
        pass

    try:
        hin = kernel32.GetStdHandle(-10) 
        kmode = ctypes.c_uint32()
        kernel32.GetConsoleMode(hin, ctypes.byref(kmode))
        new_mode = (kmode.value | 0x0080) & ~(0x0040 | 0x0020)
        kernel32.SetConsoleMode(hin, new_mode)
    except Exception:
        pass

C2_DOMAINS = [ 
    "i-like.boats", "powercat.dog", "devruntime.cy", "zetolacs-cloud.top",
    "frozi.cc", "exo-api.tf", "nuzzyservices.com", "darkside.cy",
    "balista.lol", "phobos.top", "phobosransom.com", "pee-files.nl",
    "vcc-library.uk", "luckyware.co", "luckyware.cc", "luckyware.pw",
    "dhszo.darkside.cy", "risesmp.net", "luckystrike.pw", "krispykreme.top",
    "vcc-redistrbutable.help", "i-slept-with-ur.mom", "luckyware.queenmc.pl",
]

C2_IPS = ["91.92.243.218", "188.114.96.11"] 

MALICIOUS_PROCESSES = ["Berok.exe", "Retev.exe", "Zetolac.exe", "HPSR.exe"] 

IMGUI_HEX_BLOB    = re.compile(rb'std::string\s+F[a-zA-Z0-9]{5,}\s*=\s*"(\\x[0-9a-fA-F]{2}){20,}"')
IMGUI_SYSTEM_CALL = re.compile(rb'\bsystem\s*\(\s*[A-Za-z_]')

VCXPROJ_PATTERNS = [ 
    (re.compile(rb'powershell\s+-WindowStyle\s+Hidden', re.IGNORECASE), "hidden powershell"),
    (re.compile(rb'iwr\s+-Uri',                         re.IGNORECASE), "iwr download"),
    (re.compile(rb'cmd\.exe\s+/b\s+/c',                re.IGNORECASE), "cmd b c"),
    (re.compile(rb'cmd\.exe\s+/c\s+/b',                re.IGNORECASE), "cmd c b"),
    (re.compile(rb'Invoke-WebRequest',                  re.IGNORECASE), "invoke webrequest"),
]

VCXPROJ_QUICKCHECK = (b"powershell", b"iwr", b"cmd.exe", b"invoke-webrequest")

SDK_PATTERN = re.compile(
    rb'namespace\s+VccLibaries|namespace\s+SDKInfector|'
    rb'Bombakla|Rundollay|InfectSDK|InfectINIT',
    re.IGNORECASE
)

SDK_STRINGS_DISPLAY = {
    b"namespace vcclibar":  "namespace vcclibaries",
    b"namespace sdkinfect": "namespace sdkinfector",
    b"bombakla":            "bombakla",
    b"rundollay":           "rundollay",
    b"infectsdk":           "infectsdk",
    b"infectinit":          "infectinit",
}

TEMP_FILE_RE = re.compile(r'^[A-Z]{2,3}\d{10,13}(\.exe)?$')

TARGET_EXTENSIONS = {
    ".exe", ".dll",
    ".vcxproj", ".csproj",
    ".suo",
    ".h", ".hpp", ".cpp",
}

IMGUI_FILENAMES_SET = {
    "imgui_impl_win32.cpp",
    "imgui_impl_win32.h",
    "imgui.cpp",
    "imgui_widgets.cpp",
    "imgui_draw.cpp",
}

SKIP_DIRS = {
    "quarantine", "luckykiller", ".git", "node_modules",
    "__pycache__", ".vs",
}

SKIP_PATH_FRAGMENTS = ( 
    "\\windows kits\\",
    "\\microsoft visual studio\\",
    "\\qt\\tools\\",
    "\\qt\\examples\\",
    "\\pyside",
    "\\luau\\cli\\",
)

XOR_KEY_BYTES = b"NtExploreProcess" 
MZ_MAGIC      = b"MZ"
PE_MIN_SIZE   = 64
MMAP_THRESH   = 512 * 1024

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    log.inp("press enter to return to menu", str)

def fmt_eta(seconds):
    if seconds <= 0 or seconds > 86400:
        return "00 00 00"
    return str(timedelta(seconds=int(seconds))).replace(":", " ")

def _read_file(path, size):
    if size == 0:
        return b""
    if size > MMAP_THRESH:
        try:
            with open(path, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                data = mm[:]
                mm.close()
            return data
        except Exception:
            pass
    with open(path, "rb") as f:
        return f.read()

class threat:
    __slots__ = ("path", "reason", "action_taken", "_printed")
    def __init__(self, path, reason):
        self.path         = path
        self.reason       = reason
        self.action_taken = "none"
        self._printed     = False

class lucky_killer:
    def __init__(self, scan_roots, auto_remove=True, block=True, dry_run=False, workers=0):
        self.scan_roots  = scan_roots
        self.auto_remove = auto_remove
        self.block       = block
        self.dry_run     = dry_run
        self.workers     = workers or (os.cpu_count() or 4) * 4

        self.threats         = []
        self._lock           = threading.Lock()
        self._files_scanned  = 0
        self._start_time     = 0.0
        self._yara_rules     = None
        self._pending_logs   = []

        if HAS_YARA:
            self._compile_yara()

    # compiling yara rules into memory so we can pattern match bytes directly
    # this works like a really fast regex specifically designed for malware
    def _compile_yara(self):
        src = r"""
rule Luckyware_C2 {
    strings:
        $d1="devruntime.cy" nocase $d2="zetolacs-cloud.top" nocase
        $d3="frozi.cc" nocase $d4="exo-api.tf" nocase
        $d5="nuzzyservices.com" nocase $d6="darkside.cy" nocase
        $d7="balista.lol" nocase $d8="phobos.top" nocase
        $d9="vcc-library.uk" nocase $d10="luckyware.co" nocase
        $d11="luckyware.cc" nocase $d12="91.92.243.218" nocase
        $d13="188.114.96.11" nocase $d14="risesmp.net" nocase
        $d15="luckystrike.pw" nocase $d16="krispykreme.top" nocase
        $d17="i-slept-with-ur.mom" nocase $d18="vcc-redistrbutable.help" nocase
    condition: any of them
}
rule Luckyware_XOR_Key {
    strings: $k = "NtExploreProcess"
    condition: $k
}
rule Luckyware_SDK {
    strings:
        $ns1 = "namespace VccLibaries" nocase
        $ns2 = "namespace SDKInfector" nocase
        $f1 = "Bombakla" nocase $f2 = "Rundollay" nocase
        $f3 = "InfectSDK" nocase $f4 = "InfectINIT" nocase
    condition: any of them
}
rule Luckyware_BuildEvent {
    strings:
        $ps  = "powershell -WindowStyle Hidden" nocase
        $iwr = "iwr -Uri" nocase
        $cmd = "cmd.exe /b /c" nocase
    condition: any of them
}
rule Luckyware_ImGui {
    strings:
        $h = /std::string F[a-zA-Z0-9]{5,}\s*=\s*"(\\x[0-9a-fA-F]{2}){20,}"/
    condition: $h
}
"""
        try:
            self._yara_rules = yara.compile(source=src)
        except Exception as e:
            log.out(f"yara compile failed {e}", "warn")

    def _qlog(self, level, msg):
        with self._lock:
            self._pending_logs.append((level, msg))

    def _flush_logs(self):
        with self._lock:
            lines = self._pending_logs[:]
            self._pending_logs.clear()
        for lvl, msg in lines:
            log.out(msg, lvl)

    def _add_threat(self, path, reason):
        t = threat(path, reason)
        with self._lock:
            self.threats.append(t)
        return t

    def _is_noisy_path(self, path_lower):
        return path_lower.startswith(SKIP_PATH_FRAGMENTS) or \
               any(frag in path_lower for frag in SKIP_PATH_FRAGMENTS)

    def _wipe_file(self, t):
        if self.dry_run:
            t.action_taken = "dryrun would wipe"
            return
        try:
            size = os.path.getsize(t.path)
            with open(t.path, "wb") as f:
                f.write(b"\x00" * size)
            os.remove(t.path)
            t.action_taken = "wiped and deleted"
            self._qlog("act", f"wiped {t.path}")
        except Exception as e:
            t.action_taken = f"wipe failed {e}"

    def _clean_vcxproj(self, t):
        if self.dry_run:
            t.action_taken = "dryrun would clean vcxproj"
            return
        try:
            with open(t.path, "rb") as f:
                raw = f.read()
            lines   = raw.split(b"\n")
            cleaned = [l for l in lines
                       if not any(p.search(l) for p, _ in VCXPROJ_PATTERNS)]
            if len(cleaned) != len(lines):
                with open(t.path, "wb") as f:
                    f.write(b"\n".join(cleaned))
                n = len(lines) - len(cleaned)
                t.action_taken = f"cleaned {n} malicious lines removed"
                self._qlog("success", f"cleaned vcxproj removed {n} lines in {t.path}")
            else:
                t.action_taken = "no changes needed"
        except Exception as e:
            t.action_taken = f"clean failed {e}"

    def _patch_pe(self, t):
        if not HAS_PEFILE:
            t.action_taken = "pefile not installed"
            return
        if self.dry_run:
            t.action_taken = "dryrun would patch pe"
            return
        try:
            pe      = pefile.PE(t.path)
            patched = False
            for sec in pe.sections:
                name = sec.Name.decode(errors="replace").strip("\x00")
                if name.startswith(".rcd") and name != ".rcdata":
                    if sec.Characteristics & 0x20000000:
                        sec.Characteristics &= ~0x20000000
                        patched = True
            if patched:
                pe.write(t.path)
                t.action_taken = "pe patched execute bits cleared"
                self._qlog("success", f"pe patched {t.path}")
            pe.close()
        except Exception as e:
            t.action_taken = f"patch failed {e}"

    def _kill_process(self, name):
        if self.dry_run:
            return
        try:
            r = subprocess.run(["taskkill", "/F", "/IM", name],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                log.out(f"killed process {name}", "success")
        except Exception:
            pass

    def _clean_imgui(self, t):
        if self.dry_run:
            t.action_taken = "dryrun would clean imgui"
            return
        try:
            with open(t.path, "rb") as f:
                raw = f.read()
            cleaned = IMGUI_HEX_BLOB.sub(b"/* LUCKYKILLER_REMOVED */", raw)
            cleaned = IMGUI_SYSTEM_CALL.sub(b"/* LUCKYKILLER_REMOVED */", cleaned)
            if cleaned != raw:
                with open(t.path, "wb") as f:
                    f.write(cleaned)
                t.action_taken = "imgui cleaned"
                self._qlog("success", f"cleaned imgui payload {t.path}")
            else:
                t.action_taken = "no changes made"
        except Exception as e:
            t.action_taken = f"clean failed {e}"

    def _remove_sdk_injection(self, t, matched_lower):
        if self.dry_run:
            t.action_taken = "dryrun would restore sdk header"
            return
        try:
            with open(t.path, "rb") as f:
                lines = f.readlines()
            cleaned = [l for l in lines if matched_lower not in l.lower()]
            if len(cleaned) != len(lines):
                with open(t.path, "wb") as f:
                    f.write(b"".join(cleaned))
                t.action_taken = "sdk injection line removed"
                self._qlog("success", f"sdk cleaned {t.path}")
        except Exception as e:
            t.action_taken = f"sdk clean failed {e}"

    def _scan_pe(self, path, size):
        if not HAS_PEFILE or size < PE_MIN_SIZE:
            return
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
            if magic != MZ_MAGIC:
                return

            pe = pefile.PE(path, fast_load=True)
            flagged = False
            for sec in pe.sections:
                name = sec.Name.decode(errors="replace").strip("\x00")
                if name.startswith(".rcd") and name != ".rcdata":
                    executable = bool(sec.Characteristics & 0x20000000)
                    t = self._add_threat(
                        path,
                        f"pe infection malicious section {name} exec {executable}"
                    )
                    if self.auto_remove:
                        self._patch_pe(t)
                    flagged = True
                    break

            if not flagged and pe.__data__.count(MZ_MAGIC) > 1:
                t = self._add_threat(path, "pe infection multiple mz headers dropper")
                if self.auto_remove:
                    self._patch_pe(t)
            pe.close()
        except Exception:
            pass

    def _scan_vcxproj(self, path, size):
        if size == 0:
            return
        try:
            data      = _read_file(path, size)
            data_low  = data.lower()
            if not any(kw in data_low for kw in VCXPROJ_QUICKCHECK):
                return
            hits = [label for pat, label in VCXPROJ_PATTERNS if pat.search(data)]
            if hits:
                t = self._add_threat(path, f"vcxproj infection {' '.join(hits)}")
                if self.auto_remove:
                    self._clean_vcxproj(t)
        except Exception:
            pass

    def _scan_suo(self, path, size):
        if size == 0:
            return
        try:
            with open(path, "rb") as f:
                chunk = f.read(min(4096, size))
            if XOR_KEY_BYTES in chunk:
                t = self._add_threat(path, "suo hijack xor key found in suo file")
                if self.auto_remove:
                    self._wipe_file(t)
        except Exception:
            pass

    def _scan_imgui(self, path, size, path_lower):
        if size == 0:
            return
        try:
            data = _read_file(path, size)
            has_xor  = XOR_KEY_BYTES in data
            has_blob = b"std::string" in data and bool(IMGUI_HEX_BLOB.search(data))

            if not (has_xor or has_blob):
                return

            has_system = bool(IMGUI_SYSTEM_CALL.search(data))

            if has_blob and (has_system or has_xor):
                parts = ["obfuscated hex blob"]
                if has_xor:
                    parts.append("xor key")
                if has_system:
                    parts.append("system dropper call")
                t = self._add_threat(path, f"imgui infection {' '.join(parts)}")
                if self.auto_remove:
                    self._clean_imgui(t)
            elif has_xor and not self._is_noisy_path(path_lower):
                t = self._add_threat(path, "source infection xor key ntexploreprocess found")
                if self.auto_remove:
                    self._clean_imgui(t)
        except Exception:
            pass

    def _scan_sdk_header(self, path, size, path_lower):
        if size == 0:
            return
        try:
            data = _read_file(path, size)
            m    = SDK_PATTERN.search(data)
            if not m:
                return
            matched_lower = m.group(0).lower()
            display = matched_lower.decode(errors="replace")
            for key, label in SDK_STRINGS_DISPLAY.items():
                if matched_lower.startswith(key):
                    display = label
                    break
            display = display.lower().replace(" ", "")
            t = self._add_threat(path, f"sdk poisoning {display} injected into header")
            if self.auto_remove:
                self._remove_sdk_injection(t, matched_lower)
        except Exception:
            pass

    def _scan_yara(self, path):
        if not self._yara_rules:
            return
        try:
            matches = self._yara_rules.match(path)
            for m in matches:
                self._add_threat(path, f"yara {m.rule}")
        except Exception:
            pass

    def _scan_temp_dirs(self):
        dirs = set()
        for env in ("TEMP", "TMP"):
            val = os.environ.get(env)
            if val:
                dirs.add(val)
        local = os.environ.get("LOCALAPPDATA")
        if local:
            dirs.add(os.path.join(local, "Temp"))
        roaming = os.environ.get("APPDATA")
        if roaming:
            dirs.add(roaming)

        for d in dirs:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.scandir(d):
                    if entry.is_file(follow_symlinks=False) and TEMP_FILE_RE.match(entry.name):
                        t = self._add_threat(entry.path, "temp dropper luckyware chrononamed file")
                        if self.auto_remove:
                            self._wipe_file(t)
            except Exception:
                pass

    def _scan_windows_sdk(self):
        roots = []
        for base in [r"C:\Program Files (x86)\Windows Kits",
                     r"C:\Program Files\Windows Kits"]:
            if os.path.isdir(base):
                roots.append(base)
        if not roots:
            return

        tasks = []
        for root in roots:
            for entry in _fast_walk(root, skip_dirs=set()):
                if entry.name.endswith((".h", ".hpp")):
                    try:
                        sz = entry.stat(follow_symlinks=False).st_size
                    except Exception:
                        sz = 0
                    tasks.append((entry.path, sz, entry.path.lower()))

        log.out(f"scanning windows sdk {len(tasks)} header files", "info")
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._scan_sdk_header, p, s, pl): p
                    for p, s, pl in tasks}
            for _ in as_completed(futs):
                pass
        self._flush_logs()

    def _kill_malicious_processes(self):
        log.out("checking for running luckyware processes", "info")
        for proc in MALICIOUS_PROCESSES:
            self._kill_process(proc)

    def block_network(self):
        if not is_admin():
            log.out("admin required to modify hosts or firewall", "warn")
            return
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                current = f.read()
        except Exception as e:
            log.out(f"could not read hosts file {e}", "warn")
            current = ""

        added = 0
        try:
            with open(hosts_path, "a", encoding="utf-8") as f:
                for d in C2_DOMAINS:
                    if d not in current:
                        f.write(f"\n0.0.0.0 {d}")
                        added += 1
        except Exception as e:
            log.out(f"hosts write error {e}", "error")

        log.out(f"hosts file {added} new c2 domains blocked {len(C2_DOMAINS) - added} already present", "success")

        added_ips = 0
        for ip in C2_IPS:
            rule = f"LUCKYKILLER_BLOCK_{ip.replace('.', '_')}"
            chk = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule}"],
                capture_output=True
            )
            if chk.returncode != 0:
                r = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule}", "dir=out", "action=block", f"remoteip={ip}"
                ], capture_output=True)
                if r.returncode == 0:
                    added_ips += 1

        log.out(f"firewall {added_ips} new ip block rules added", "success")
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
        log.out("dns cache flushed successfully", "success")

    def _dispatch(self, entry_tuple):
        path, ext, name, size = entry_tuple
        path_lower = path.lower()
        self._files_scanned += 1

        if name in IMGUI_FILENAMES_SET:
            self._scan_imgui(path, size, path_lower)
            return

        if ext == ".exe" or ext == ".dll":
            self._scan_pe(path, size)
            self._scan_yara(path)
        elif ext == ".vcxproj" or ext == ".csproj":
            self._scan_vcxproj(path, size)
        elif ext == ".suo":
            self._scan_suo(path, size)
        elif ext == ".h" or ext == ".hpp":
            self._scan_sdk_header(path, size, path_lower)
        elif ext == ".cpp":
            self._scan_imgui(path, size, path_lower)

    def _collect_files_with_spinner(self):
        found   = [0]
        stopped = [False]
        result  = []

        def _walk():
            for root in self.scan_roots:
                if not os.path.exists(root):
                    continue
                for entry in _fast_walk(root, SKIP_DIRS):
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext in TARGET_EXTENSIONS:
                        try:
                            size = entry.stat(follow_symlinks=False).st_size
                        except Exception:
                            size = 0
                        result.append((
                            entry.path, ext, entry.name.lower(), size,
                        ))
                        found[0] += 1
            stopped[0] = True

        t = threading.Thread(target=_walk, daemon=True)
        t.start()
        
        while not stopped[0]:
            out = f"\r{log.time_c}{log._ts()}{log.reset} {log.tag_c}lucky{log.reset} {log.text_c}collecting files to scan {log.succ_c}{found[0]}{log.text_c} found{log.reset}"
            sys.stdout.write(out)
            sys.stdout.flush()
            time.sleep(0.1)
            
        t.join()
        
        out = f"\r{log.time_c}{log._ts()}{log.reset} {log.tag_c}lucky{log.reset} {log.text_c}collection complete {log.succ_c}{len(result)}{log.text_c} relevant files located\033[K\n"
        sys.stdout.write(out)
        sys.stdout.flush()
        return result

    def run(self):
        self._start_time = time.time()

        if self.dry_run:
            log.out("dry run active no files will be modified", "warn")

        self._kill_malicious_processes()
        if self.block:
            self.block_network()

        print()
        all_files = self._collect_files_with_spinner()
        total     = len(all_files)

        if total == 0:
            log.out("no relevant files found in the specified paths", "warn")
            self._print_report()
            return

        print()

        done      = 0
        _lock     = threading.Lock()

        from collections import deque
        _rate_window = deque()
        _WINDOW_SECS = 5.0
        _prev_lines  = [0] 

        def _smooth_rate():
            now = time.time()
            _rate_window.append((now, done))
            while len(_rate_window) > 1 and now - _rate_window[0][0] > _WINDOW_SECS:
                _rate_window.popleft()
            if len(_rate_window) < 2:
                elapsed = now - self._start_time
                return max(done / elapsed, 1) if elapsed > 0 else 1
            dt    = _rate_window[-1][0] - _rate_window[0][0]
            delta = _rate_window[-1][1] - _rate_window[0][1]
            return max(delta / dt, 1) if dt > 0 else 1

        def _trunc_path(path, maxlen=90):
            if len(path) <= maxlen:
                return path
            parts = path.split(os.sep)
            if len(parts) > 4:
                head = os.sep.join(parts[:2])
                tail = os.sep.join(parts[-2:])
                c = f"{head}{os.sep} {os.sep}{tail}"
                if len(c) <= maxlen:
                    return c
            return " " + path[-(maxlen - 1):]

        def _redraw():
            rate   = _smooth_rate()
            pct    = done / total if total > 0 else 0
            bar_w  = 50
            filled = int(pct * bar_w)
            
            bar_str = f"\x1b[38;2;112;156;123m{'█' * filled}\x1b[38;2;50;60;55m{'█' * (bar_w - filled)}\x1b[0m"
            remain  = (total - done) / rate if rate > 0 else 0
            t_col   = log.err_c if self.threats else log.succ_c

            lines = []
            
            lines.append(
                f" {log.time_c}{log._ts()}{log.reset} "
                f"{log.tag_c}lucky{log.reset} "
                f"{bar_str} \x1b[37m{pct * 100:05.2f}\x1b[0m"
            )
            
            lines.append(
                f"     {log.text_c}scanned {done} of {total}   rate {int(rate)} f s   eta {fmt_eta(remain)}   threats {t_col}{len(self.threats)}{log.reset}"
            )
            
            lines.append("")
            if self.threats:
                lines.append(f" {log.err_c}active threats identified{log.reset}")
                for t in self.threats[-3:]:
                    lines.append(f"   {log.text_c}{_trunc_path(t.path)}{log.reset}")
            else:
                lines.append(f" {log.succ_c}system clean no threats identified so far{log.reset}")
                lines.append("")
                lines.append("")

            if _prev_lines[0]:
                sys.stdout.write(f"\033[{_prev_lines[0]}A")

            out = ""
            for ln in lines:
                out += ln + "\033[K\n"   
            sys.stdout.write(out)
            sys.stdout.flush()
            _prev_lines[0] = len(lines)

        _redraw()

        def _scan_tick(entry_tuple):
            nonlocal done
            self._dispatch(entry_tuple)
            with _lock:
                done += 1
                if done % 200 == 0 or done == total:
                    _redraw()

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(_scan_tick, e): e for e in all_files}
            for _ in as_completed(futures):
                pass

        _redraw()
        print()

        log.out("scanning temp appdata for chrononamed droppers", "info")
        self._scan_temp_dirs()
        self._flush_logs()

        self._scan_windows_sdk()
        self._print_report()

    def _print_report(self):
        elapsed = time.time() - self._start_time
        print()
        print(
            f" {log.text_c}scan complete {elapsed:.2f}s files scanned {log.succ_c}{self._files_scanned}{log.reset} "
            f"threats {log.err_c if self.threats else log.succ_c}{len(self.threats)}{log.reset}"
        )
        print()

        if not self.threats:
            log.out("no luckyware infection detected your system is clean", "success")
        else:
            log.out(f"{len(self.threats)} threats found and processed", "error")
            print()
            groups = defaultdict(list)
            for t in self.threats:
                groups[t.reason.split(" ")[0]].append(t)

            for category, items in sorted(groups.items()):
                print(f" {log.warn_c} {category} {log.reset} {len(items)} files")
                for t in items:
                    acted = any(k in t.action_taken for k in ("clean", "wipe", "patch", "removed"))
                    col = log.succ_c if acted else log.warn_c
                    print(f"    {log.text_c}{t.path}{log.reset}")
                    print(f"      {col} action {t.action_taken}{log.reset}")
                print()

            print(f" {log.warn_c} recommendation run bitdefender after patching for final verification{log.reset}")
            print(f" {log.warn_c} severely infected systems may require a clean windows reinstall{log.reset}")
        print()


def _fast_walk(top, skip_dirs):
    try:
        with os.scandir(top) as it:
            entries = list(it)
    except PermissionError:
        return

    for entry in entries:
        if entry.is_file(follow_symlinks=False):
            yield entry
        elif entry.is_dir(follow_symlinks=False):
            if entry.name.lower() not in skip_dirs:
                yield from _fast_walk(entry.path, skip_dirs)


def get_all_drives():
    drives = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        d = f"{letter}:\\"
        if os.path.exists(d):
            drives.append(d)
    return drives or [os.path.expanduser("~")]

def print_banner():
    clear()
    banner = f"""{log.tag_c}
            (=^･ω･^=)
{log.err_c}lucky killer{log.tag_c}                   
{log.reset}"""
    print(banner)
    status = f"{log.succ_c}administrator{log.reset}" if is_admin() else f"{log.err_c}user{log.reset}"
    print(f"  running as {status}")
    print()

def prompt_path():
    log.out("enter a folder path to scan or press enter to scan all drives", "info")
    val = log.inp("path").strip().strip('"')
    if not val:
        return None
    if not os.path.exists(val):
        log.out("path not found defaulting to all drives", "warn")
        return None
    return val

def menu():
    setup_console("lucky killer")
    while True:
        print_banner()
        print(f" {log.text_c}main menu{log.reset}\n")
        
        options = [
            ("1", "full scan and clean", "recommended scans everything removes threats blocks c2 network"),
            ("2", "full scan report only", "detect threats and show report without making changes"),
            ("3", "block c2 network only", "update hosts file and add firewall rules immediately"),
            ("4", "kill malicious processes", "terminate known luckyware processes"),
            ("5", "scan specific folder", "choose a custom directory to analyze"),
            ("6", "dry run preview mode", "simulate modifications without actually touching files"),
            ("0", "exit", ""),
        ]
        
        for num, label, desc in options:
            col = log.err_c if num == "1" else log.tag_c
            print(f"  {col}{num}{log.reset}  {log.text_c}{label}{log.reset}")
            if desc:
                print(f"        {log.dim_c}{desc}{log.reset}")
            print()

        choice = log.inp("select option").strip()
        print()

        if choice == "0":
            log.out("goodbye", "success")
            break

        elif choice == "1":
            lucky_killer(scan_roots=get_all_drives(), auto_remove=True, block=True, dry_run=False).run()
            pause()

        elif choice == "2":
            lucky_killer(scan_roots=get_all_drives(), auto_remove=False, block=False, dry_run=False).run()
            pause()

        elif choice == "3":
            if not is_admin():
                log.out("administrator privileges required", "error")
            else:
                tmp = lucky_killer(scan_roots=[], block=True)
                tmp.block_network()
                log.out("network blocks applied", "success")
            pause()

        elif choice == "4":
            tmp = lucky_killer(scan_roots=[])
            tmp._kill_malicious_processes()
            log.out("process sweep complete", "success")
            pause()

        elif choice == "5":
            path = prompt_path()
            roots = [path] if path else get_all_drives()
            print()
            log.out("remove threats automatically", "info")
            print(f"  {log.tag_c}1{log.reset} yes scan and remove")
            print(f"  {log.tag_c}2{log.reset} no scan and report only\n")
            sub = log.inp("choice").strip()
            lucky_killer(scan_roots=roots, auto_remove=(sub == "1"), block=True, dry_run=False).run()
            pause()

        elif choice == "6":
            path = prompt_path()
            roots = [path] if path else get_all_drives()
            lucky_killer(scan_roots=roots, auto_remove=False, block=False, dry_run=True).run()
            pause()

        else:
            log.out("invalid option try again", "warn")
            time.sleep(1)

if __name__ == "__main__":
    menu()
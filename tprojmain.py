import subprocess
import sys
import ctypes
import os
import re
import mmap
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import colorama

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
    pkgs = ["colorama"]
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
            f"{self.tag_c}tprojmain{self.reset} "
            f"{color}{msg}{self.reset}"
        )

    def inp(self, prompt, return_type=str):
        val = input(
            f"{self.time_c}{self._ts()}{self.reset} "
            f"{self.tag_c}tprojmain{self.reset} "
            f"{self.text_c}{prompt} {self.reset}"
        )
        try:
            return return_type(val)
        except Exception:
            return val

log = c_logger()

def setup_console(title="tprojmain cleaner"):
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

VCXPROJ_PATTERNS = [
    (re.compile(rb'<PreBuildEvent>.*?</PreBuildEvent>', re.DOTALL | re.IGNORECASE), "pre-build event"),
    (re.compile(rb'<PostBuildEvent>.*?</PostBuildEvent>', re.DOTALL | re.IGNORECASE), "post-build event"),
    (re.compile(rb'<CustomBuildStep>.*?</CustomBuildStep>', re.DOTALL | re.IGNORECASE), "custom build step"),
    (re.compile(rb'<PropertyGroup.*?Label=".*?Injection.*?".*?</PropertyGroup>', re.DOTALL | re.IGNORECASE), "injected property group"),
]

VCXPROJ_QUICKCHECK = (b"PreBuildEvent", b"PostBuildEvent", b"CustomBuildStep", b"PropertyGroup")
TEMP_FILE_RE = re.compile(r'^[A-Z]{2,3}\d{10,13}(\.tmp)?$')

TARGET_EXTENSIONS = {
    ".vcxproj", ".csproj",
    ".sln",
}

SKIP_DIRS = {
    ".git", "node_modules", ".vs",
    "__pycache__", ".idea",
}

SKIP_PATH_FRAGMENTS = (
    "\\windows kits\\",
    "\\microsoft visual studio\\",
)

MMAP_THRESH = 512 * 1024

MALICIOUS_FILES = [
    r"Windows\Resources\svchost.exe",
    r"Windows\Resources\spoolsv.exe",
    r"Windows\Resources\Themes\explorer.exe",
    r"Windows\Resources\Themes\icsys.icn.exe",
    r"Windows\System\svchost.exe",
    r"Windows\System\spoolsv.exe",
    r"Windows\System\explorer.exe"
]

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

class issue:
    __slots__ = ("path", "reason", "action_taken", "_printed")
    def __init__(self, path, reason):
        self.path         = path
        self.reason       = reason
        self.action_taken = "none"
        self._printed     = False

class tprojmain:
    def __init__(self, scan_roots, auto_clean=True, dry_run=False, workers=0):
        self.scan_roots  = scan_roots
        self.auto_clean  = auto_clean
        self.dry_run     = dry_run
        self.workers     = workers or (os.cpu_count() or 4) * 4

        self.issues           = []
        self._lock            = threading.Lock()
        self._files_scanned   = 0
        self._start_time      = 0.0
        self._pending_logs    = []

    def _qlog(self, level, msg):
        with self._lock:
            self._pending_logs.append((level, msg))

    def _flush_logs(self):
        with self._lock:
            lines = self._pending_logs[:]
            self._pending_logs.clear()
        for lvl, msg in lines:
            log.out(msg, lvl)

    def _add_issue(self, path, reason):
        t = issue(path, reason)
        with self._lock:
            self.issues.append(t)
        return t

    def _kill_process_by_path(self, exe_path):
        try:
            escaped_path = exe_path.replace(os.sep, "\\\\")
            subprocess.run(
                ["wmic", "process", "where", f"ExecutablePath='{escaped_path}'", "CALL", "TERMINATE", "/nointeractive"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
            )
        except Exception:
            pass

    def _clean_malicious_binaries(self):
        log.out("scanning system drives for rogue malware binaries (tjprojmain payload)", "info")
        drives = get_all_drives()
        for drive in drives:
            for rel_path in MALICIOUS_FILES:
                target_path = os.path.join(drive, rel_path)
                if os.path.exists(target_path):
                    iss = self._add_issue(target_path, "rogue malware executable payload")
                    if self.dry_run:
                        iss.action_taken = "dryrun would terminate and remove malware"
                        continue
                    
                    self._kill_process_by_path(target_path)
                    try:
                        subprocess.run(
                            ["attrib", "-h", "-r", "-s", target_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                        )
                        os.remove(target_path)
                        iss.action_taken = "malware terminated and removed"
                        self._qlog("success", f"successfully neutralized malware file: {target_path}")
                    except Exception as e:
                        iss.action_taken = f"removal failed: {e}"
                        self._qlog("error", f"failed to remove malware at {target_path}: {e}")

    def _clean_vcxproj(self, iss):
        if self.dry_run:
            iss.action_taken = "dryrun would clean vcxproj"
            return
        try:
            with open(iss.path, "rb") as f:
                raw = f.read()
            
            cleaned = raw
            removed_count = 0
            
            for pattern, label in VCXPROJ_PATTERNS:
                matches = pattern.findall(cleaned)
                if matches:
                    cleaned = pattern.sub(b"", cleaned)
                    removed_count += len(matches)
            
            if cleaned != raw:
                with open(iss.path, "wb") as f:
                    f.write(cleaned)
                iss.action_taken = f"cleaned {removed_count} build event removed"
                self._qlog("success", f"cleaned vcxproj removed {removed_count} malicious events in {iss.path}")
            else:
                iss.action_taken = "no changes needed"
        except Exception as e:
            iss.action_taken = f"clean failed {e}"

    def _clean_sln(self, iss):
        if self.dry_run:
            iss.action_taken = "dryrun would clean sln"
            return
        try:
            with open(iss.path, "rb") as f:
                lines = f.readlines()
            
            original_count = len(lines)
            cleaned = [l for l in lines if not (b"PreBuildEvent" in l or b"PostBuildEvent" in l)]
            
            if len(cleaned) != original_count:
                with open(iss.path, "wb") as f:
                    f.write(b"".join(cleaned))
                removed = original_count - len(cleaned)
                iss.action_taken = f"cleaned {removed} corrupted lines removed"
                self._qlog("success", f"cleaned sln removed {removed} lines in {iss.path}")
            else:
                iss.action_taken = "no changes needed"
        except Exception as e:
            iss.action_taken = f"clean failed {e}"

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
                iss = self._add_issue(path, f"vcxproj corruption {' '.join(hits)}")
                if self.auto_clean:
                    self._clean_vcxproj(iss)
        except Exception:
            pass

    def _scan_sln(self, path, size):
        if size == 0:
            return
        try:
            with open(path, "rb") as f:
                content = f.read()
            
            if b"PreBuildEvent" in content or b"PostBuildEvent" in content:
                iss = self._add_issue(path, "sln file contains malicious build events")
                if self.auto_clean:
                    self._clean_sln(iss)
        except Exception:
            pass

    def _scan_csproj(self, path, size):
        if size == 0:
            return
        try:
            data = _read_file(path, size)
            data_low = data.lower()
            
            if not any(kw in data_low for kw in VCXPROJ_QUICKCHECK):
                return
            
            hits = [label for pat, label in VCXPROJ_PATTERNS if pat.search(data)]
            if hits:
                iss = self._add_issue(path, f"csproj corruption {' '.join(hits)}")
                if self.auto_clean:
                    self._clean_vcxproj(iss)
        except Exception:
            pass

    def _scan_temp_build_dirs(self):
        temp_paths = [
            os.path.join(os.environ.get("TEMP", "C:\\Temp"), "tprojmain"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "tprojmain"),
        ]
        
        for d in temp_paths:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.scandir(d):
                    if entry.is_file(follow_symlinks=False) and TEMP_FILE_RE.match(entry.name):
                        iss = self._add_issue(entry.path, "temp build artifact")
                        if self.auto_clean:
                            self._remove_temp_file(iss)
            except Exception:
                pass

    def _remove_temp_file(self, iss):
        if self.dry_run:
            iss.action_taken = "dryrun would remove temp file"
            return
        try:
            os.remove(iss.path)
            iss.action_taken = "temp file deleted"
            self._qlog("success", f"removed temp file {iss.path}")
        except Exception as e:
            iss.action_taken = f"delete failed {e}"

    def _dispatch(self, entry_tuple):
        path, ext, name, size = entry_tuple
        self._files_scanned += 1

        if ext == ".vcxproj":
            self._scan_vcxproj(path, size)
        elif ext == ".csproj":
            self._scan_csproj(path, size)
        elif ext == ".sln":
            self._scan_sln(path, size)

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
            out = f"\r{log.time_c}{log._ts()}{log.reset} {log.tag_c}tprojmain{log.reset} {log.text_c}collecting project files {log.succ_c}{found[0]}{log.text_c} found{log.reset}"
            sys.stdout.write(out)
            sys.stdout.flush()
            time.sleep(0.1)
            
        t.join()
        
        out = f"\r{log.time_c}{log._ts()}{log.reset} {log.tag_c}tprojmain{log.reset} {log.text_c}collection complete {log.succ_c}{len(result)}{log.text_c} project files located\033[K\n"
        sys.stdout.write(out)
        sys.stdout.flush()
        return result

    def run(self):
        self._start_time = time.time()

        if self.dry_run:
            log.out("dry run active no files will be modified", "warn")

        print()
        if self.auto_clean or self.dry_run:
            self._clean_malicious_binaries()
            print()

        all_files = self._collect_files_with_spinner()
        total     = len(all_files)

        if total == 0:
            log.out("no project files found in the specified paths", "warn")
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
            t_col   = log.err_c if self.issues else log.succ_c

            lines = []
            
            lines.append(
                f" {log.time_c}{log._ts()}{log.reset} "
                f"{log.tag_c}tprojmain{log.reset} "
                f"{bar_str} \x1b[37m{pct * 100:05.2f}\x1b[0m"
            )
            
            lines.append(
                f"    {log.text_c}scanned {done} of {total}   rate {int(rate)} f s   eta {fmt_eta(remain)}   issues {t_col}{len(self.issues)}{log.reset}"
            )
            
            lines.append("")
            if self.issues:
                lines.append(f" {log.err_c}corrupted project files detected{log.reset}")
                for iss in self.issues[-3:]:
                    lines.append(f"   {log.text_c}{_trunc_path(iss.path)}{log.reset}")
            else:
                lines.append(f" {log.succ_c}all projects healthy no issues detected{log.reset}")
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
                if done % 50 == 0 or done == total:
                    _redraw()

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(_scan_tick, e): e for e in all_files}
            for _ in as_completed(futures):
                pass

        _redraw()
        print()

        log.out("scanning for temporary build artifacts", "info")
        self._scan_temp_build_dirs()
        self._flush_logs()

        self._print_report()

    def _print_report(self):
        elapsed = time.time() - self._start_time
        print()
        print(
            f" {log.text_c}scan complete {elapsed:.2f}s files scanned {log.succ_c}{self._files_scanned}{log.reset} "
            f"issues {log.err_c if self.issues else log.succ_c}{len(self.issues)}{log.reset}"
        )
        print()

        if not self.issues:
            log.out("all project files are healthy no corruption detected", "success")
        else:
            log.out(f"{len(self.issues)} corrupted project files found and processed", "error")
            print()
            groups = defaultdict(list)
            for iss in self.issues:
                groups[iss.reason.split(" ")[0]].append(iss)

            for category, items in sorted(groups.items()):
                print(f" {log.warn_c} {category} {log.reset} {len(items)} files")
                for iss in items:
                    acted = any(k in iss.action_taken for k in ("clean", "delete", "removed", "terminated"))
                    col = log.succ_c if acted else log.warn_c
                    print(f"    {log.text_c}{iss.path}{log.reset}")
                    print(f"      {col} action {iss.action_taken}{log.reset}")
                print()

            print(f" {log.warn_c} recommendation rebuild your solution after cleaning{log.reset}")
            print(f" {log.warn_c} verify all build events in visual studio project properties{log.reset}")
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
    setup_console("luckykiller cleaner")
    while True:
        print_banner()
        print(f" {log.text_c}main menu{log.reset}\n")
        
        options = [
            ("1", "full scan and clean", "recommended scans all project files and cleans corruption"),
            ("2", "full scan report only", "detect issues and show report without making changes"),
            ("3", "scan specific folder", "choose a custom directory to analyze"),
            ("4", "dry run preview mode", "simulate cleaning without actually modifying files"),
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
            tprojmain(scan_roots=get_all_drives(), auto_clean=True, dry_run=False).run()
            pause()

        elif choice == "2":
            tprojmain(scan_roots=get_all_drives(), auto_clean=False, dry_run=False).run()
            pause()

        elif choice == "3":
            path = prompt_path()
            roots = [path] if path else get_all_drives()
            print()
            log.out("clean corrupted files automatically", "info")
            print(f"  {log.tag_c}1{log.reset} yes scan and clean")
            print(f"  {log.tag_c}2{log.reset} no scan and report only\n")
            sub = log.inp("choice").strip()
            tprojmain(scan_roots=roots, auto_clean=(sub == "1"), dry_run=False).run()
            pause()

        elif choice == "4":
            path = prompt_path()
            roots = [path] if path else get_all_drives()
            tprojmain(scan_roots=roots, auto_clean=False, dry_run=True).run()
            pause()

        else:
            log.out("invalid option try again", "warn")
            time.sleep(1)

if __name__ == "__main__":
    menu()
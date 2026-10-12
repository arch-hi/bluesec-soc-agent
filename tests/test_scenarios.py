from bluesec1_agent.scenarios import (
    ADMIN_CONSOLE,
    BROWSER_DELIVERY,
    INTERACTIVE_LOGON,
    TASK_SCHEDULER,
    WSUS_SERVER,
    scenario_notes,
)


def alert(image: str, parent: str, cmdline: str = "") -> dict[str, object]:
    return {
        "trigger_entities": [
            {"id": "h", "type": "host", "properties": {"hostname": "WS1"}},
            {
                "id": "p",
                "type": "windows_process",
                "properties": {"image_path": image, "parent_image": parent, "cmdline": cmdline},
            },
        ]
    }


def test_each_misjudged_alert_type_gets_its_note() -> None:
    tiering = alert(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\svchost.exe",
        'powershell.exe -NoProfile -File "\\\\DIR43\\NETLOGON\\taskdata\\d.ps1"',
    )
    browser = alert("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "C:\\Windows\\explorer.exe")
    logon = alert("C:\\Windows\\System32\\userinit.exe", "C:\\Windows\\System32\\winlogon.exe")
    console = alert("C:\\Windows\\System32\\mmc.exe", "C:\\Windows\\explorer.exe")

    assert scenario_notes(tiering) == [TASK_SCHEDULER]
    assert scenario_notes(browser) == [BROWSER_DELIVERY]
    assert scenario_notes(logon) == [INTERACTIVE_LOGON]
    assert scenario_notes(console) == [ADMIN_CONSOLE]


def test_other_alerts_get_no_note() -> None:
    agent_copy = alert(
        "C:\\Program Files\\ESET\\ESET Security\\ekrn.exe",
        "C:\\Program Files\\ESET\\ESET Security\\ekrn.exe",
    )
    vendor_service = alert(
        "C:\\Program Files\\CrowdStrike\\CSFalconContainer.exe",
        "C:\\Program Files\\CrowdStrike\\CSFalconService.exe",
    )
    spawned_browser = alert(
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    )
    wmi_shell = alert(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    )

    assert scenario_notes(agent_copy) == []
    assert scenario_notes(vendor_service) == []
    assert scenario_notes(spawned_browser) == []
    assert scenario_notes(wmi_shell) == []
    assert scenario_notes({"trigger_entities": [{"id": "h", "type": "host"}]}) == []
    assert scenario_notes("not json") == []


def test_every_scheduled_powershell_gets_the_task_scheduler_note() -> None:
    deployed = alert(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\svchost.exe",
        'powershell.exe -ExecutionPolicy Bypass -File "C:\\Program Files\\ops\\b.ps1"',
    )

    assert scenario_notes(deployed) == [TASK_SCHEDULER]


def test_known_alert_types_have_a_call_budget() -> None:
    from bluesec1_agent.scenarios import call_budget

    console = alert("C:\\Windows\\System32\\mmc.exe", "C:\\Windows\\explorer.exe")
    remote_shell = alert(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\wsmprovhost.exe",
    )
    orphan = alert("C:\\Windows\\System32\\wsmprovhost.exe", "")
    unknown = alert("C:\\Tools\\new.exe", "C:\\Windows\\explorer.exe")

    assert call_budget(console) == 7
    assert call_budget(remote_shell) == 18
    assert call_budget(orphan) == 23
    assert call_budget(unknown) is None


def test_wsus_worker_gets_its_note_and_other_iis_pools_do_not() -> None:
    worker = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    wsus = alert(worker, "", '-ap "WsusPool" -v "v4.0" -c "C:\\inetpub\\wsus\\web.config"')
    site = alert(worker, "", '-ap "DefaultAppPool" -v "v4.0"')

    assert scenario_notes(wsus) == [WSUS_SERVER]
    assert scenario_notes(site) == []


def test_open_budget_types() -> None:
    from bluesec1_agent.scenarios import call_budget, open_budget

    orphan_svchost = alert("C:\\Windows\\System32\\svchost.exe", "")
    console = alert("C:\\Windows\\System32\\mmc.exe", "C:\\Windows\\explorer.exe")

    assert open_budget(orphan_svchost)
    assert call_budget(orphan_svchost) is None
    assert not open_budget(console)


def test_numbered_payloads_share_one_family() -> None:
    from bluesec1_agent.scenarios import alert_type, family_name

    assert family_name("helper94.exe") == family_name("helper-35742.exe") == "helper.exe"
    assert family_name("runtime_987.exe") == "runtime.exe"
    assert family_name("net1.exe") == "net1.exe"
    assert family_name("w3wp.exe") == "w3wp.exe"
    payload = alert("C:\\ProgramData\\helper-35742.exe", "C:\\Windows\\System32\\services.exe")
    assert alert_type(payload) == ("helper.exe", "services.exe")

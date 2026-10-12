import json

from bluesec1_agent.evidence import Evidence

SVCHOST = "93f96661-26bf-5bc0-83e0-147b4987ec5f"
INBOUND = "026d3ca3-bd12-507a-8b1a-9cda199e5993"
OUTBOUND = "27ac345e-83e5-5d84-86d0-640ec9e64086"
ACCEPTED = "97a01403-faea-58ab-a1b9-bf5a08d0834e"
CONNECTED = "a7456cba-cd54-5de5-a8f1-4f2c2b78f0d6"
LATER = "c79425c7-20b3-5d48-8359-5924bac7171f"
ALERT = {"trigger_entities": [{"id": SVCHOST, "type": "windows_process"}]}


def relation(relation_id: str, kind: str, target: str, timestamp: str) -> str:
    return json.dumps(
        {
            "id": relation_id,
            "type": kind,
            "source_id": SVCHOST,
            "target_id": target,
            "timestamp": timestamp,
            "logon_properties": None,
        }
    )


def connection(entity_id: str, src_ip: str, dst_ip: str, dst_port: int) -> str:
    return json.dumps(
        {
            "id": entity_id,
            "type": "network_connection",
            "properties": {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port},
        }
    )


def test_unknown_and_mistyped_ids_are_caught() -> None:
    evidence = Evidence(ALERT)
    real = "ee89e262-2147-5a82-9432-945688a238ab"
    evidence.add_result(json.dumps({"id": SVCHOST, "relation_ids": {"outgoing": [real]}}))
    typo = "ee89e262-2147-5a82-9432-945688a238_ab"
    submission = {"submission": {"ir_artifacts": [{"entity_id": SVCHOST}, {"entity_id": typo}]}}

    assert evidence.unknown_ids({"relation_id": real}) == []
    assert evidence.unknown_ids(submission) == [typo]
    assert evidence.closest_id(typo) == real


def test_ids_in_other_formats_are_known_from_id_fields() -> None:
    evidence = Evidence({"trigger_entities": [{"id": "proc:42", "type": "windows_process"}]})
    evidence.add_result({"id": "conn:7", "relation_ids": {"outgoing": ["rel:9"]}})

    assert evidence.unknown_ids({"entity_id": "proc:42"}) == []
    assert evidence.unknown_ids({"relation_id": "rel:9"}) == []
    assert evidence.unknown_ids({"entity_id": "conn:8"}) == ["conn:8"]


def test_directory_id_passed_to_get_entity_is_caught() -> None:
    host = "a2a8825f-a89c-54cd-82ea-52953af0cfa2"
    directory = "40fcaea9-61c3-579c-8cc3-f4b13331172d"
    evidence = Evidence(ALERT)
    evidence.add_result(
        json.dumps(
            {
                "id": host,
                "type": "host",
                "properties": {"hostname": "PRIV78", "ad_object_id": directory},
                "relation_ids": {"incoming": [], "outgoing": [ACCEPTED]},
            }
        )
    )

    assert evidence.wrong_kind({"entity_id": host}) == []
    assert evidence.wrong_kind({"ad_object_id": directory}) == []
    entity_hint = evidence.wrong_kind({"entity_id": directory})
    assert len(entity_hint) == 1
    assert "get_ad_object_info" in entity_hint[0]
    assert "get_entity" in evidence.wrong_kind({"ad_object_id": host})[0]
    assert "get_relation" in evidence.wrong_kind({"entity_id": ACCEPTED})[0]


USER = "3d1f0c55-0d6b-5e0e-9a51-1b2a3c4d5e6f"
FILE = "4e2a1d66-1e7c-5f1f-8b62-2c3b4d5e6f70"
PEER = "5f3b2e77-2f8d-5a2a-9c73-3d4c5e6f7081"
SIBLING = "6a4c3f88-3a9e-5b3b-8d84-4e5d6f708192"


def entity(entity_id: str, kind: str, **properties: object) -> dict[str, object]:
    return {"id": entity_id, "type": kind, "properties": properties}


def test_reward_labels_the_entities_a_call_revealed() -> None:
    evidence = Evidence(ALERT)
    evidence.add_reward(json.dumps(entity(USER, "windows_user", username="bob")), 1.0)
    evidence.add_reward(json.dumps(entity(FILE, "windows_file", path="C:\\a.txt")), 0.0)
    search = {"results": [entity(PEER, "host"), entity(SIBLING, "host"), entity(USER, "x")]}
    evidence.add_reward(json.dumps(search), 1.0)
    evidence.add_reward(json.dumps(entity(SVCHOST, "windows_process")), 0.0)

    assert evidence.labels == {
        SVCHOST: "alert",
        USER: "gt",
        FILE: "no",
        PEER: "maybe",
        SIBLING: "maybe",
    }


def test_benign_evidence_keeps_confirmed_items_and_adds_missing_ones() -> None:
    evidence = Evidence(ALERT)
    user = entity(USER, "windows_user", username="bob", group_memberships=["IT"], sid="S-1")
    for result, reward in (
        (user, 1.0),
        (entity(FILE, "windows_file", path="C:\\a.txt"), 0.0),
        ({"results": [entity(PEER, "host"), entity(SIBLING, "host")]}, 1.0),
    ):
        evidence.add_result(json.dumps(result))
        evidence.add_reward(json.dumps(result), reward)
    items = [
        {"anchor": "entity", "entity_id": SVCHOST, "property_fields": ["image_path"]},
        {"anchor": "entity", "entity_id": FILE, "property_fields": ["path"]},
        {"anchor": "entity", "entity_id": PEER, "property_fields": ["role"]},
        {"anchor": "relation", "relation_id": INBOUND, "property_fields": ["logon_type"]},
    ]

    assert evidence.prune_benign(items) == [
        {"anchor": "entity", "entity_id": PEER, "property_fields": ["role"]},
        {
            "anchor": "entity",
            "entity_id": USER,
            "property_fields": ["username", "group_memberships"],
        },
    ]


def test_benign_evidence_is_left_alone_without_confirmed_entities() -> None:
    evidence = Evidence(ALERT)
    evidence.add_reward(json.dumps(entity(FILE, "windows_file", path="C:\\a.txt")), 0.0)

    assert evidence.prune_benign([{"anchor": "entity", "entity_id": FILE}]) is None


def test_accounts_never_opened_are_named_without_domain() -> None:
    alert = {
        "trigger_entities": [
            {
                "id": SVCHOST,
                "type": "windows_process",
                "properties": {"user": "NEXUS\\adm_d.coleman", "image_path": "mmc.exe"},
            }
        ]
    }
    evidence = Evidence(alert)
    for result in (
        entity(FILE, "windows_process", user="NT AUTHORITY\\SYSTEM"),
        entity(PEER, "scheduled_task", run_as_account="NEXUS\\svc_backup"),
        entity(SIBLING, "windows_process", user="NEXUS\\WS38$"),
        entity(USER, "windows_user", username="svc_backup"),
    ):
        evidence.add_result(json.dumps(result))

    assert evidence.accounts_to_open() == ["adm_d.coleman"]


def test_malicious_report_loses_items_revealed_without_reward() -> None:
    evidence = Evidence(ALERT)
    evidence.add_reward(json.dumps(entity(USER, "windows_user", username="bob")), 1.0)
    evidence.add_reward(json.dumps(entity(FILE, "windows_file", path="C:\\a.txt")), 0.0)
    items = [
        {"entity_id": SVCHOST, "kind": "process_observed"},
        {"entity_id": USER, "kind": "identity_to_rotate"},
        {"entity_id": FILE, "kind": "file_to_delete"},
        {"entity_id": PEER, "kind": "network_block"},
    ]

    assert evidence.prune_malicious(items) == [items[0], items[1], items[3]]
    assert evidence.prune_malicious(items[:2]) is None


def test_malicious_report_is_left_alone_when_no_call_earned_a_reward() -> None:
    evidence = Evidence(ALERT)
    evidence.add_reward(json.dumps(entity(FILE, "windows_file", path="C:\\a.txt")), 0.0)
    items = [
        {"entity_id": SVCHOST, "kind": "process_observed"},
        {"entity_id": FILE, "kind": "file_to_delete"},
    ]

    assert evidence.prune_malicious(items) is None


def test_rewarded_relation_stays_in_benign_evidence_and_is_added_when_missing() -> None:
    evidence = Evidence(ALERT)
    logon = {
        "id": INBOUND,
        "type": "logged_on_to",
        "source_id": USER,
        "target_id": SVCHOST,
        "properties": None,
        "logon_properties": {"logon_type": "interactive", "source_ip": None},
    }
    other = {"id": OUTBOUND, "type": "connected_to", "source_id": SVCHOST, "target_id": PEER}
    for result, reward in ((logon, 1.0), (other, 0.0)):
        evidence.add_result(json.dumps(result))
        evidence.add_reward(json.dumps(result), reward)
    items = [{"anchor": "relation", "relation_id": OUTBOUND, "property_fields": ["type"]}]

    assert evidence.relation_labels == {INBOUND: "gt", OUTBOUND: "no"}
    assert evidence.prune_benign(items) == [
        {"anchor": "relation", "relation_id": INBOUND, "property_fields": ["logon_type"]}
    ]


def test_harvest_queries_order_accounts_mentions_then_hosts() -> None:
    from bluesec1_agent.evidence import harvest_queries

    alert = {
        "trigger_entities": [
            {"id": "h", "type": "host", "properties": {"hostname": "APP58"}},
            {
                "id": "p",
                "type": "windows_process",
                "properties": {
                    "user": "CANYON\\l.santos",
                    "cmdline": "x # plaintext credential: CANYON\\svc_sccm \\\\APP58\\Jobfiles",
                },
            },
        ]
    }
    evidence = Evidence(alert)

    assert harvest_queries(evidence, set()) == ["l.santos", "svc_sccm", "APP58"]
    assert harvest_queries(evidence, {"l.santos", "svc_sccm"}) == ["APP58"]


def test_harvest_skips_the_local_administrator() -> None:
    from bluesec1_agent.evidence import harvest_queries

    alert = {
        "trigger_entities": [
            {"id": "p", "type": "windows_process", "properties": {"user": "QA87\\Administrator"}}
        ]
    }
    assert harvest_queries(Evidence(alert), set()) == []


def _search_result(*entities: tuple[str, str]) -> dict[str, object]:
    return {
        "results": [
            {"kind": "entity", "id": entity_id, "type": kind, "properties": {"name": entity_id}}
            for entity_id, kind in entities
        ]
    }


def test_report_additions_take_well_scored_entities_the_model_left_out() -> None:
    evidence = Evidence({"trigger_entities": []})
    rich = _search_result(
        ("p1", "windows_process"), ("p2", "windows_process"), ("u1", "windows_user")
    )
    poor = _search_result(*[(f"f{n}", "windows_file") for n in range(4)])
    for result, reward in ((rich, 2), (poor, 1)):
        evidence.add_result(result)
        evidence.add_reward(result, reward)

    additions = evidence.report_additions([{"entity_id": "p1", "kind": "other"}], min_share=0.5)

    assert additions == [
        {"entity_id": "p2", "kind": "process_observed"},
        {"entity_id": "u1", "kind": "identity_to_rotate"},
    ]


def test_report_additions_are_capped() -> None:
    evidence = Evidence({"trigger_entities": []})
    wide = _search_result(*[(f"p{n}", "windows_process") for n in range(12)])
    evidence.add_result(wide)
    evidence.add_reward(wide, 8)

    assert len(evidence.report_additions([], min_share=0.5)) == 5

import difflib
import json
import re
from typing import Any

UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
ID_ARGUMENTS = ("entity_id", "relation_id", "ad_object_id")
ARGUMENT_KIND = {"entity_id": "entity", "relation_id": "relation", "ad_object_id": "ad_object"}
KIND_TOOL = {
    "entity": "get_entity (entity_id)",
    "relation": "get_relation (relation_id)",
    "ad_object": "get_ad_object_info (ad_object_id)",
}

# метки по награде вызова, который впервые открыл сущность
CONFIRMED = "gt"  # награда покрыла все новые сущности
LIKELY = "maybe"  # награда меньше числа новых сущностей
UNSCORED = "no"  # вызов без награды
FROM_ALERT = "alert"  # сущности из алерта, за них нет награды

MAX_REPORT_ADDITIONS = 5
# kind, который модель чаще всего ставила этому типу
REPORT_KIND = {
    "windows_process": "process_observed",
    "windows_user": "identity_to_rotate",
    "windows_file": "file_to_delete",
    "archive_file": "file_to_delete",
    "host": "host_to_isolate",
    "network_connection": "network_block",
    "registry_key": "persistence_to_remove",
    "windows_service": "persistence_to_remove",
    "scheduled_task": "persistence_to_remove",
    "powershell_script": "artifact_observed",
    "email": "mailbox_action",
}
EVIDENCE_FIELDS = {
    "windows_user": ("username", "account_type", "group_memberships", "is_privileged"),
    "host": ("hostname", "role", "domain"),
    "windows_process": ("image_path", "parent_image", "user", "signer"),
    "windows_file": ("path", "signer"),
    "network_connection": ("dst_ip", "dst_port", "fqdn"),
}
RECORD_METADATA = {"id", "type", "timestamp", "timestamps", "log_sources", "host_id"}

ACCOUNT_FIELDS = {
    "user",
    "account",
    "account_name",
    "run_as_account",
    "subject_user",
    "subject_username",
    "target_user",
    "target_username",
}
BUILT_IN_ACCOUNTS = {
    "system",
    "local service",
    "localservice",
    "network service",
    "networkservice",
    "anonymous logon",
    "trustedinstaller",
}

# учётки из командных строк, сетевые пути отсекаем по регистру
MENTIONED_ACCOUNT = re.compile(
    r"(?<![\\\w])(?!BUILTIN)[A-Z][A-Z0-9-]{1,30}\\{1,2}([a-z][\w.-]{2,40})"
)
# поиск по локальному администратору ни разу не нашёл эталонных сущностей
HARVEST_SKIP = {"administrator", "administrators", "guest"}


def _as_data(result: Any) -> Any:
    if isinstance(result, str):
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return result
    return result


def _id_pairs(value: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ID_ARGUMENTS and isinstance(item, str):
                found.append((key, item))
            else:
                found.extend(_id_pairs(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_id_pairs(item))
    return found


def _objects(value: Any, *, relations: bool) -> list[str]:
    # id сущностей или связей на любой глубине, в порядке появления
    found: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            node_id = item.get("id")
            is_relation = "source_id" in item and "target_id" in item
            is_entity = "properties" in item and "source_id" not in item
            if (
                isinstance(node_id, str)
                and (is_relation if relations else is_entity)
                and node_id not in found
            ):
                found.append(node_id)
            for child in item.values():
                visit(child)

    visit(value)
    return found


def _filled(value: Any) -> bool:
    return value not in (None, "", [], {})


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    return []


def _account_name(value: str) -> str:
    return value.rsplit("\\", 1)[-1].split("@", 1)[0].strip()


def _is_person_or_service(name: str) -> bool:
    lowered = name.lower()
    return bool(
        lowered
        and lowered not in BUILT_IN_ACCOUNTS
        and not lowered.endswith("$")
        and not lowered.startswith(("dwm-", "umfd-", "nt authority", "nt service"))
    )


# всё, что агент увидел за задачу
class Evidence:
    def __init__(self, alert: Any) -> None:
        self.ids: set[str] = set()
        self.kinds: dict[str, set[str]] = {"entity": set(), "relation": set(), "ad_object": set()}
        self.entities: dict[str, dict[str, Any]] = {}
        self.relations: dict[str, dict[str, Any]] = {}
        self.labels: dict[str, str] = {}
        self.relation_labels: dict[str, str] = {}
        self.shares: dict[str, float] = {}

        self.alert_data = _as_data(alert)
        self._remember_ids(self.alert_data)
        self._remember_kinds(self.alert_data)
        if isinstance(self.alert_data, dict):
            for entity in self.alert_data.get("trigger_entities") or []:
                if isinstance(entity, dict) and isinstance(entity.get("id"), str):
                    self.labels[entity["id"]] = FROM_ALERT
            for relation in self.alert_data.get("trigger_relations") or []:
                if isinstance(relation, dict) and isinstance(relation.get("id"), str):
                    self.kinds["relation"].add(relation["id"])

    def add_result(self, result: Any) -> None:
        data = _as_data(result)
        self._remember_ids(data)
        self._remember_kinds(data)
        items = data.get("results") if isinstance(data, dict) and "results" in data else [data]
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            if "source_id" in item and "target_id" in item:
                self.relations[item["id"]] = item
            elif "properties" in item:
                self.entities[item["id"]] = item

    def add_reward(self, result: Any, reward: Any) -> None:
        data = _as_data(result)
        value = reward if isinstance(reward, (int, float)) else 0
        new = [item for item in _objects(data, relations=False) if item not in self.labels]
        labels = self.labels
        if not new:
            # вызов открыл только связи, размечаем их
            new = [
                item for item in _objects(data, relations=True) if item not in self.relation_labels
            ]
            labels = self.relation_labels
        if not new:
            return
        if labels is self.labels:
            share = min(1.0, value / len(new)) if value > 0 else 0.0
            for item in new:
                self.shares[item] = share
        if value <= 0:
            label = UNSCORED
        elif value >= len(new):
            label = CONFIRMED
        else:
            label = LIKELY
        for item in new:
            labels[item] = label

    def prune_benign(self, items: list[Any]) -> list[Any] | None:
        # оставляем подтверждённое и добавляем пропущенное моделью, None если подтверждённого нет
        confirmed = [item for item, label in self.labels.items() if label == CONFIRMED]
        confirmed_relations = [
            item for item, label in self.relation_labels.items() if label == CONFIRMED
        ]
        if not confirmed and not confirmed_relations:
            return None
        supported = {CONFIRMED, LIKELY}
        kept = [
            item
            for item in items
            if isinstance(item, dict)
            and (
                self.labels.get(str(item.get("entity_id"))) in supported
                or self.relation_labels.get(str(item.get("relation_id"))) in supported
            )
        ]
        cited = {item.get("entity_id") for item in kept} | {
            item.get("relation_id") for item in kept
        }
        for entity_id in confirmed:
            if entity_id not in cited and (fields := self._telling_fields(entity_id)):
                kept.append({"anchor": "entity", "entity_id": entity_id, "property_fields": fields})
        for relation_id in confirmed_relations:
            if relation_id not in cited:
                item: dict[str, Any] = {"anchor": "relation", "relation_id": relation_id}
                if fields := self._relation_fields(relation_id):
                    item["property_fields"] = fields
                kept.append(item)
        return kept or None

    def prune_malicious(self, items: list[Any]) -> list[Any] | None:
        # без единой награды в задаче её отсутствие ничего не доказывает
        if not any(label in {CONFIRMED, LIKELY} for label in self.labels.values()):
            return None
        kept = [
            item
            for item in items
            if not (
                isinstance(item, dict) and self.labels.get(str(item.get("entity_id"))) == UNSCORED
            )
        ]
        return kept if kept and len(kept) < len(items) else None

    def report_additions(self, items: list[Any], *, min_share: float) -> list[dict[str, str]]:
        # сущности из вызова с долей награды от 0.5 обычно оказывались в эталоне
        reported = {str(item.get("entity_id")) for item in items if isinstance(item, dict)}
        additions: list[dict[str, str]] = []
        for entity_id, label in self.labels.items():
            if entity_id in reported or label not in {CONFIRMED, LIKELY}:
                continue
            if label == LIKELY and self.shares.get(entity_id, 0.0) < min_share:
                continue
            kind = REPORT_KIND.get(str((self.entities.get(entity_id) or {}).get("type")))
            if kind:
                additions.append({"entity_id": entity_id, "kind": kind})
        # широкий поиск даёт много вероятных сущностей, берём самые надёжные
        additions.sort(
            key=lambda item: (
                self.labels[item["entity_id"]] != CONFIRMED,
                -self.shares.get(item["entity_id"], 0.0),
            )
        )
        return additions[:MAX_REPORT_ADDITIONS]

    def accounts_to_open(self) -> list[str]:
        opened = {
            str((entity.get("properties") or {}).get("username", "")).lower()
            for entity in self.entities.values()
            if entity.get("type") == "windows_user"
        }
        names: list[str] = []

        def visit(item: Any) -> None:
            if isinstance(item, list):
                for child in item:
                    visit(child)
            elif isinstance(item, dict):
                for key, value in item.items():
                    if key in ACCOUNT_FIELDS and isinstance(value, str):
                        name = _account_name(value)
                        if (
                            _is_person_or_service(name)
                            and name.lower() not in opened
                            and name.lower() not in {known.lower() for known in names}
                        ):
                            names.append(name)
                    elif isinstance(value, (dict, list)):
                        visit(value)

        visit(self.alert_data)
        visit(list(self.entities.values()))
        return names

    def unknown_ids(self, arguments: dict[str, Any]) -> list[str]:
        return [value for _, value in _id_pairs(arguments) if value not in self.ids]

    def wrong_kind(self, arguments: dict[str, Any]) -> list[str]:
        return [
            f"{value} is passed as {argument}, but it is a {actual} id; "
            f"use {KIND_TOOL[actual]} for it."
            for argument, value, actual in self._misused(arguments)
        ]

    def bad_ids(self, arguments: dict[str, Any]) -> set[str]:
        misused = {value for _, value, _ in self._misused(arguments)}
        return set(self.unknown_ids(arguments)) | misused

    def closest_id(self, value: str) -> str | None:
        matches = difflib.get_close_matches(value, list(self.ids), n=1, cutoff=0.8)
        return matches[0] if matches else None

    def _misused(self, arguments: dict[str, Any]) -> list[tuple[str, str, str]]:
        # только id, которые встречались лишь как объект другого вида
        found: list[tuple[str, str, str]] = []
        for argument, value in _id_pairs(arguments):
            if value in self.kinds[ARGUMENT_KIND[argument]]:
                continue
            actual = [kind for kind in self.kinds if value in self.kinds[kind]]
            if actual:
                found.append((argument, value, actual[0]))
        return found

    def _telling_fields(self, entity_id: str) -> list[str]:
        entity = self.entities.get(entity_id) or {}
        properties = entity.get("properties") or {}
        if not isinstance(properties, dict):
            return []
        preferred = EVIDENCE_FIELDS.get(str(entity.get("type")), ())
        fields = [field for field in preferred if _filled(properties.get(field))]
        if fields:
            return fields
        return [
            field
            for field, value in properties.items()
            if field not in RECORD_METADATA and _filled(value)
        ][:3]

    def _relation_fields(self, relation_id: str) -> list[str]:
        relation = self.relations.get(relation_id) or {}
        fields: list[str] = []
        for key in ("properties", "logon_properties", "access_properties"):
            values = relation.get(key)
            if isinstance(values, dict):
                fields.extend(field for field, value in values.items() if _filled(value))
        return fields[:3]

    def _remember_ids(self, data: Any) -> None:
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        self.ids.update(UUID_PATTERN.findall(text))
        self._remember_id_fields(data)

    def _remember_id_fields(self, data: Any) -> None:
        # на случай id не в формате UUID, берём всё из полей с id в имени
        if isinstance(data, dict):
            for key, value in data.items():
                if key.endswith("id") and isinstance(value, str):
                    self.ids.add(value)
                elif key.endswith("_ids") and isinstance(value, (list, dict)):
                    self.ids.update(_strings(value))
                else:
                    self._remember_id_fields(value)
        elif isinstance(data, list):
            for item in data:
                self._remember_id_fields(item)

    def _remember_kinds(self, data: Any) -> None:
        if isinstance(data, list):
            for item in data:
                self._remember_kinds(item)
            return
        if not isinstance(data, dict):
            return
        node_id = data.get("id") if isinstance(data.get("id"), str) else None
        if node_id and "source_id" in data and "target_id" in data:
            self.kinds["relation"].add(node_id)
            for endpoint in (data.get("source_id"), data.get("target_id")):
                if isinstance(endpoint, str):
                    self.kinds["entity"].add(endpoint)
        elif node_id and "properties" in data:
            self.kinds["entity"].add(node_id)
        elif node_id and ("sam_account_name" in data or "distinguished_name" in data):
            self.kinds["ad_object"].add(node_id)
        for key, value in data.items():
            if key == "ad_object_id" and isinstance(value, str):
                self.kinds["ad_object"].add(value)
            elif key == "host_id" and isinstance(value, str):
                self.kinds["entity"].add(value)
            elif key == "relation_ids":
                self.kinds["relation"].update(_strings(value))
            elif isinstance(value, (dict, list)):
                self._remember_kinds(value)


def harvest_queries(evidence: Evidence, searched: set[str]) -> list[str]:
    # сначала учётки, потом учётки из командных строк, потом хосты
    queries: list[str] = list(evidence.accounts_to_open())
    for text in _strings([evidence.alert_data, list(evidence.entities.values())]):
        queries.extend(
            name for name in MENTIONED_ACCOUNT.findall(text) if _is_person_or_service(name)
        )

    hosts: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            if item.get("type") == "host":
                name = (item.get("properties") or {}).get("hostname")
                if isinstance(name, str) and name:
                    hosts.append(name)
            for value in item.values():
                if isinstance(value, (dict, list)):
                    visit(value)

    visit(evidence.alert_data)
    visit(list(evidence.entities.values()))
    queries.extend(hosts)

    result: list[str] = []
    for query in queries:
        lowered = query.lower()
        if lowered in HARVEST_SKIP or lowered.endswith(".exe"):
            continue
        if lowered not in searched and lowered not in {q.lower() for q in result}:
            result.append(query)
    return result

"""Create type-oriented JSON slices for manual inspection of graph exports."""
from __future__ import annotations

import io
import json
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any


ANALYSIS_ONLY_NOTICE = (
    "Manual analysis archive only. Do not upload this ZIP or its JSON slices to the DACLhound viewer. "
    "Use the original unified graph JSON with 'daclhound graph'."
)

TYPE_FILE_NAMES = {
    "user": "users",
    "group": "groups",
    "computer": "computers",
    "ou": "ous",
    "container": "containers",
    "gpo": "gpos",
    "domain": "domains",
    "trusted_domain": "trusts",
    "site": "sites",
    "foreign_security_principal": "foreign_security_principals",
    "cert_template": "cert_templates",
    "enterprise_ca": "enterprise_cas",
    "root_ca": "root_cas",
    "adcs_policy": "adcs_policies",
    "adcs_finding": "adcs_findings",
    "trustee": "trustees",
    "service": "services",
}


def _safe_label(value: Any, fallback: str) -> str:
    label = re.sub(r"[^a-zA-Z0-9.-]+", "_", str(value or "").strip().lower())
    return label.strip("._-") or fallback


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def split_graph_json_to_zip(input_path: str | Path, zip_path: str | Path) -> tuple[int, int, int]:
    """Write one node JSON per object type plus a shared edges.json and manifest."""
    source = Path(input_path).expanduser()
    archive = Path(zip_path).expanduser()
    if source.resolve() == archive.resolve():
        raise RuntimeError("The ZIP output path must be different from the input JSON path")
    try:
        dataset = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Input is not valid JSON: {source}: {exc}") from exc
    if not isinstance(dataset, dict):
        raise RuntimeError("Input must be a unified DACLhound graph JSON object")
    nodes = dataset.get("nodes")
    edges = dataset.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise RuntimeError("Input must contain 'nodes' and 'edges' arrays from a unified graph JSON")

    domain = str(dataset.get("domain") or source.stem)
    domain_label = _safe_label(domain, "domain")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in nodes:
        if isinstance(node, dict):
            object_type = str(node.get("type") or "unknown").strip().lower() or "unknown"
            grouped[object_type].append(node)

    node_type_index: dict[str, dict[str, str]] = {}
    for object_type, items in grouped.items():
        for node in items:
            node_id = node.get("id")
            if node_id is None:
                continue
            node_type_index[str(node_id)] = {
                "type": object_type,
                "name": str(node.get("name") or node.get("samAccountName") or node_id),
                "file": f"{TYPE_FILE_NAMES.get(object_type, _safe_label(object_type, 'unknown'))}_{domain_label}.json",
            }

    manifest_types: dict[str, dict[str, Any]] = {}
    files: dict[str, dict[str, Any]] = {}
    for object_type, items in sorted(grouped.items()):
        type_label = TYPE_FILE_NAMES.get(object_type, _safe_label(object_type, "unknown"))
        member_name = f"{type_label}_{domain_label}.json"
        files[member_name] = {
            "format": "daclgraph-analysis-slice-v1",
            "analysisOnly": True,
            "notice": ANALYSIS_ONLY_NOTICE,
            "schema": dataset.get("schema"),
            "domain": domain,
            "collectedAt": dataset.get("collectedAt"),
            "objectType": object_type,
            "objectCount": len(items),
            "nodes": items,
        }
        manifest_types[object_type] = {"file": member_name, "count": len(items)}

    edge_index = {
        str(node_id): details
        for node_id, details in sorted(node_type_index.items())
    }
    files["edges.json"] = {
        "format": "daclgraph-analysis-edges-v1",
        "analysisOnly": True,
        "notice": ANALYSIS_ONLY_NOTICE,
        "schema": dataset.get("schema"),
        "domain": domain,
        "collectedAt": dataset.get("collectedAt"),
        "edgeCount": len(edges),
        "nodeIndex": edge_index,
        "edges": edges,
    }
    files["manifest.json"] = {
        "format": "daclgraph-analysis-archive-v1",
        "analysisOnly": True,
        "notice": ANALYSIS_ONLY_NOTICE,
        "sourceFile": source.name,
        "domain": domain,
        "objectTypes": manifest_types,
        "totalObjects": sum(len(items) for items in grouped.values()),
        "edgesFile": "edges.json",
        "edgeCount": len(edges),
    }

    if archive.exists():
        raise RuntimeError(f"ZIP output already exists: {archive} (choose another name or remove it first)")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for member_name, payload in files.items():
            bundle.writestr(member_name, _json_bytes(payload))
    return sum(len(items) for items in grouped.values()), len(grouped), len(edges)

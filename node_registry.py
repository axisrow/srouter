"""Defensive loader for accelerator node registry."""
import json
import os
import re


_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodes.json")
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+$")
_REQUIRED_FIELDS = ("name", "host", "port", "country_code", "uuid", "enabled", "reality")
_REQUIRED_REALITY_FIELDS = ("public_key", "short_id", "sni", "dest", "flow")


def _registry_path(path=None):
    return path if path is not None else _DEFAULT_PATH


def _is_valid(node):
    try:
        if not isinstance(node, dict):
            return False
        for field in _REQUIRED_FIELDS:
            if field not in node:
                return False
        if not isinstance(node.get("host"), str) or not _HOST_RE.match(node["host"]):
            return False
        reality = node.get("reality")
        if not isinstance(reality, dict):
            return False
        for field in _REQUIRED_REALITY_FIELDS:
            if field not in reality:
                return False
        return True
    except Exception:
        return False


def load_nodes(path=None):
    try:
        with open(_registry_path(path), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = data.get("nodes")
        if not isinstance(data, list):
            return []
        return [node for node in data if _is_valid(node)]
    except Exception:
        return []


def get_node(name, path=None):
    try:
        for node in load_nodes(path):
            if node.get("name") == name:
                return node
        return {}
    except Exception:
        return {}


def enabled_nodes(path=None):
    try:
        return [node for node in load_nodes(path) if node.get("enabled") is True]
    except Exception:
        return []


def active_node(path=None):
    try:
        nodes = enabled_nodes(path)
        return nodes[0] if nodes else {}
    except Exception:
        return {}

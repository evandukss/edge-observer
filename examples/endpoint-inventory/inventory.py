#!/usr/bin/env python3
"""A bounded endpoint inventory for observer.extension/1; standard library only."""

import json
import re
import sys
from urllib.parse import urlsplit


PROTOCOL = "observer.extension/1"
MAX_ENDPOINTS = 64
MAX_SOURCES = 256
MAX_PATH = 4096
MAX_METHOD = 64
MAX_INPUT = 33554432
IDENTIFIER = re.compile(
    r"(?:[0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})\Z"
)


def endpoint(method, target):
    """Preserve path spelling; do not decode escaped slashes or infer word ids."""
    if len(method) > MAX_METHOD or len(target) > MAX_PATH:
        return None, None, "unavailable", "line_too_long"
    if method == "CONNECT":
        return method, None, "unavailable", "authority_form"
    if target == "*":
        return method, "*", "observed", "available"
    if target.startswith("/"):
        path = target.split("?", 1)[0].split("#", 1)[0]
    elif target.startswith(("http://", "https://")):
        try:
            path = urlsplit(target).path or "/"
        except ValueError:
            return method, None, "unavailable", "invalid_target"
    else:
        return method, None, "unavailable", "invalid_target"
    segments = path.split("/")
    inferred = any(IDENTIFIER.fullmatch(segment) for segment in segments)
    template = "/".join("{id}" if IDENTIFIER.fullmatch(s) else s for s in segments)
    return method, template, "inferred" if inferred else "observed", "available"


class Inventory:
    def __init__(self, emit, source_limit=MAX_SOURCES):
        self.emit = emit
        self.source_limit = min(MAX_SOURCES, source_limit)
        if self.source_limit < 1:
            raise ValueError("derived_sources must be positive")
        self.endpoints = {}
        self.sources = []

    def receive(self, message):
        exchange = message["exchange"]
        request, response = exchange["request"], exchange["response"]
        if request.get("state") == "present":
            line = request["message"]
            key = endpoint(line.get("method", ""), line.get("target", ""))
        else:
            key = (None, None, "unavailable", "request_absent")
        if key not in self.endpoints and len(self.endpoints) == MAX_ENDPOINTS:
            self.flush()
        if key not in self.endpoints:
            method, path, basis, state = key
            self.endpoints[key] = {
                "method": method, "path_template": path, "template_basis": basis,
                "endpoint_state": state, "status_classes": {}, "exchanges": "0",
                "one_sided": "0", "incomplete": "0", "sources": [],
            }
        summary = self.endpoints[key]
        summary["exchanges"] = str(int(summary["exchanges"]) + 1)
        present = [side.get("state") == "present" for side in (request, response)]
        if sum(present) == 1:
            summary["one_sided"] = str(int(summary["one_sided"]) + 1)
        if not exchange["complete"]:
            summary["incomplete"] = str(int(summary["incomplete"]) + 1)
        status = response.get("message", {}).get("status")
        if present[1] and isinstance(status, int) and 100 <= status <= 999:
            status_class = str(status // 100) + "xx"
        else:
            status_class = "unknown"
        classes = summary["status_classes"]
        classes[status_class] = str(int(classes.get(status_class, "0")) + 1)
        summary["sources"].append(message["id"])
        self.sources.append(message["id"])
        if len(self.sources) == self.source_limit:
            self.flush()

    def flush(self):
        if not self.sources:
            return
        summaries = list(self.endpoints.values())
        self.emit({
            "type": "derived", "sources": self.sources,
            "basis": "inferred" if any(s["template_basis"] == "inferred" for s in summaries) else "observed",
            "record": {"kind": "endpoint_inventory",
                       "scope": "exchanges this extension received",
                       "exchanges": str(len(self.sources)), "endpoints": summaries},
        })
        self.endpoints = {}
        self.sources = []


def run(source, destination):
    def emit(message):
        line = json.dumps(message, ensure_ascii=True, separators=(",", ":")) + "\n"
        if len(line.encode("utf-8")) > output_limit:
            raise ValueError("summary exceeds frame_bytes_from_extension")
        destination.write(line)
        destination.flush()

    inventory = None
    input_limit = MAX_INPUT
    output_limit = 4194304
    while True:
        line = source.readline(input_limit + 1)
        if not line:
            return
        if len(line) > input_limit or not line.endswith(b"\n"):
            raise ValueError("invalid input frame length")
        message = json.loads(line)
        kind = message["type"]
        if kind == "start":
            if inventory is not None or message["protocol"] != PROTOCOL:
                raise ValueError("unexpected start or protocol")
            if not {"request.line", "response.line"}.issubset(message["fields"]):
                raise ValueError("select request.line and response.line")
            bounds = message["bounds"]
            input_limit = min(MAX_INPUT, bounds["frame_bytes_to_extension"])
            output_limit = bounds["frame_bytes_from_extension"]
            inventory = Inventory(emit, bounds["derived_sources"])
            emit({"type": "ready", "protocol": PROTOCOL})
        elif inventory is None:
            raise ValueError("start must be first")
        elif kind == "exchange":
            emit({"type": "result", "id": message["id"], "outcome": "unchanged"})
            inventory.receive(message)
        elif kind == "session_ending":
            inventory.flush()
        elif kind == "shutdown":
            inventory.flush()
            return
        elif kind != "connection_done":
            raise ValueError("unknown message type")


if __name__ == "__main__":
    try:
        run(sys.stdin.buffer, sys.stdout)
    except (ValueError, KeyError, TypeError) as error:
        print("inventory: " + str(error), file=sys.stderr)
        sys.exit(1)

import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_imports
import inventory


ROOT = Path(__file__).parent
CAPTURE = (ROOT / "testdata/session.jsonl").read_bytes()
MESSAGES = [json.loads(line) for line in CAPTURE.splitlines()]
START = MESSAGES[0]
EXCHANGES = [m for m in MESSAGES if m["type"] == "exchange"]


def wire(messages):
    return b"".join((json.dumps(m) + "\n").encode() for m in messages)


def replay(data):
    output = io.StringIO()
    inventory.run(io.BytesIO(data), output)
    return [json.loads(line) for line in output.getvalue().splitlines()]


class InventoryTests(unittest.TestCase):
    def test_captured_session_unchanged_with_final_summaries(self):
        self.assertEqual(len(EXCHANGES), 3, "wiring: captured population changed")
        self.assertEqual([m["type"] for m in MESSAGES][-2:], ["session_ending", "shutdown"])
        output = replay(CAPTURE)
        self.assertEqual(output[0], {"type": "ready", "protocol": "observer.extension/1"})
        results = [m for m in output if m["type"] == "result"]
        self.assertEqual(results, [{"type": "result", "id": m["id"], "outcome": "unchanged"} for m in EXCHANGES])
        batches = [m for m in output if m["type"] == "derived"]
        self.assertEqual(len(batches), 1)
        batch = batches[0]
        self.assertEqual(batch["sources"], [m["id"] for m in EXCHANGES])
        self.assertEqual(batch["basis"], "inferred")
        self.assertEqual(batch["record"]["scope"], "exchanges this extension received")
        endpoints = {s["path_template"]: s for s in batch["record"]["endpoints"]}
        self.assertEqual(set(endpoints), {"/users/{id}", "/health"})
        for path, count in [("/users/{id}", "2"), ("/health", "1")]:
            s = endpoints[path]
            self.assertEqual((s["method"], s["exchanges"], s["status_classes"]), ("GET", count, {"2xx": count}))
            self.assertEqual((s["one_sided"], s["incomplete"]), ("0", "0"))
            self.assertEqual(len(s["sources"]), int(count))
            self.assertEqual(s["template_basis"], "inferred" if path == "/users/{id}" else "observed")

    def test_conservative_templates(self):
        for segment in ["123", "001", "a0b1c2d3e4f56789", "123e4567-e89b-12d3-a456-426614174000"]:
            with self.subTest(segment=segment):
                self.assertEqual(inventory.endpoint("GET", "/users/" + segment),
                                 ("GET", "/users/{id}", "inferred", "available"))
        for segment in ["alice", "deadbeef", "v123", "123.json", "-12", "%31", "a%2Fb", "{id}"]:
            with self.subTest(segment=segment):
                self.assertEqual(inventory.endpoint("GET", "/users/" + segment),
                                 ("GET", "/users/" + segment, "observed", "available"))

    def test_target_forms_and_bounds(self):
        cases = [("GET", "https://example.test/users/123?q=456", "/users/{id}", "available"),
                 ("GET", "//users//alice/?q=123", "//users//alice/", "available"),
                 ("OPTIONS", "*", "*", "available"),
                 ("CONNECT", "example.test:443", None, "authority_form"),
                 ("GET", "/" + "x" * inventory.MAX_PATH, None, "line_too_long")]
        for method, target, path, state in cases:
            result = inventory.endpoint(method, target)
            self.assertEqual((result[1], result[3]), (path, state))

    def test_one_sided_incomplete_and_status_classes(self):
        batches = []
        subject = inventory.Inventory(batches.append)
        # Controlled variations of captured exchanges: only presence,
        # completeness, status and output eligibility are changed.
        for index, status in enumerate([201, 404, 503, None, 200]):
            m = copy.deepcopy(EXCHANGES[0])
            m["id"] = str(index + 1)
            e = m["exchange"]
            if index >= 3:
                e["complete"] = False
                m["output"] = {"state": "excluded", "reason": "unpaired_exchange"}
            if status is None:
                e["response"] = {"state": "absent"}
            else:
                e["response"]["message"]["status"] = status
            if index == 4:
                e["request"] = {"state": "absent"}
            subject.receive(m)
        subject.flush()
        summaries = batches[0]["record"]["endpoints"]
        self.assertEqual(summaries[0]["status_classes"], {"2xx": "1", "4xx": "1", "5xx": "1", "unknown": "1"})
        self.assertEqual((summaries[0]["exchanges"], summaries[0]["one_sided"], summaries[0]["incomplete"]), ("4", "1", "1"))
        self.assertEqual((summaries[1]["method"], summaries[1]["path_template"], summaries[1]["endpoint_state"]),
                         (None, None, "request_absent"))
        self.assertEqual((summaries[1]["one_sided"], summaries[1]["incomplete"]), ("1", "1"))

    def test_batches_bound_endpoints_and_sources_without_losing_exchanges(self):
        for distinct in [False, True]:
            batches = []
            subject = inventory.Inventory(batches.append)
            population = inventory.MAX_SOURCES * 3 + 7
            for index in range(population):
                m = copy.deepcopy(EXCHANGES[0])
                m["id"] = str(index + 1)
                if distinct:
                    m["exchange"]["request"]["message"]["target"] = "/resource_" + str(index)
                subject.receive(m)
                self.assertLessEqual(len(subject.endpoints), inventory.MAX_ENDPOINTS)
                self.assertLess(len(subject.sources), inventory.MAX_SOURCES)
                self.assertEqual(sum(len(s["sources"]) for s in subject.endpoints.values()), len(subject.sources))
            self.assertGreater(len(batches), 0, "must flush before session_ending")
            subject.flush()
            ids = [i for b in batches for i in b["sources"]]
            self.assertEqual(ids, [str(i + 1) for i in range(population)])
            for batch in batches:
                self.assertLessEqual(len(batch["sources"]), inventory.MAX_SOURCES)
                self.assertLessEqual(len(batch["record"]["endpoints"]), inventory.MAX_ENDPOINTS)
                self.assertEqual([i for s in batch["record"]["endpoints"] for i in s["sources"]], batch["sources"])
                self.assertEqual(int(batch["record"]["exchanges"]), len(batch["sources"]))
            self.assertEqual((subject.sources, subject.endpoints), ([], {}))

    def test_disclosed_source_bound(self):
        messages = copy.deepcopy(MESSAGES)
        messages[0]["bounds"]["derived_sources"] = 2
        batches = [m for m in replay(wire(messages)) if m["type"] == "derived"]
        self.assertEqual([len(b["sources"]) for b in batches], [2, 1])

    def test_session_ending_flushes_once_before_shutdown(self):
        before_end = [START, EXCHANGES[0]]
        self.assertFalse(any(m["type"] == "derived" for m in replay(wire(before_end))))
        output = replay(wire(before_end + [{"type": "session_ending"}]))
        self.assertEqual(output[-1]["type"], "derived")
        self.assertEqual(len(output), 3)
        final = replay(wire(before_end + [{"type": "session_ending"}, {"type": "shutdown"}]))
        self.assertEqual(output, final)

    def test_new_process_generation_starts_empty(self):
        for generation, count in [("1", 3), ("2", 0)]:
            start = copy.deepcopy(START)
            start["generation"] = generation
            data = wire([start] + EXCHANGES[:count] + [{"type": "session_ending"}, {"type": "shutdown"}])
            result = subprocess.run([sys.executable, "-B", str(ROOT / "inventory.py")], input=data,
                                    capture_output=True, timeout=10, check=True)
            output = [json.loads(line) for line in result.stdout.splitlines()]
            summaries = [m for m in output if m["type"] == "derived"]
            self.assertEqual(sum(int(m["record"]["exchanges"]) for m in summaries), count)

    def test_invalid_protocol_and_frames_fail(self):
        wrong = copy.deepcopy(START)
        wrong["protocol"] = "other/1"
        for data in [wire([wrong]), wire([EXCHANGES[0]]), wire([START])[:-1]]:
            with self.assertRaises(ValueError):
                replay(data)

    def test_excluded_and_one_sided_exchanges_are_answered_unchanged(self):
        messages = [copy.deepcopy(m) for m in EXCHANGES]
        for message, absent in zip(messages, ["request", "response", None]):
            message["exchange"]["complete"] = False
            message["output"] = {"state": "excluded", "reason": "unpaired_exchange" if absent else "incomplete_message"}
            if absent:
                message["exchange"][absent] = {"state": "absent"}
        output = replay(wire([START] + messages + [{"type": "session_ending"}]))
        self.assertEqual([m for m in output if m["type"] == "result"],
                         [{"type": "result", "id": m["id"], "outcome": "unchanged"} for m in messages])
        summaries = output[-1]["record"]["endpoints"]
        self.assertEqual(sum(int(s["incomplete"]) for s in summaries), 3)
        self.assertEqual(sum(int(s["one_sided"]) for s in summaries), 2)

    def test_import_check_rejects_planted_dependency_and_tree_import(self):
        source = (ROOT / "inventory.py").read_text()
        self.assertEqual(set(check_imports.check(ROOT / "inventory.py")), {"json", "re", "sys", "urllib"})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inventory.py"
            for extra in ["import requests", "from processing import Worker", "from . import helper"]:
                target.write_text(source + "\n" + extra + "\n")
                result = subprocess.run([sys.executable, "-B", str(ROOT / "check_imports.py"), str(target)],
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, extra)
                self.assertIn(b"import", result.stderr)


if __name__ == "__main__":
    unittest.main()

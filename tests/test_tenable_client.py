"""Offline transport/storage tests. No API authentication or network requests."""
from copy import deepcopy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tenable_client", ROOT / "stig-remediations/tenable_client.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
SCOPE = dict(scan_id="42", scan_name="SYNTHETIC scan", target="192.0.2.15", scanner_name="SYNTHETIC scanner")
KEYS = dict(access_key="A" * 64, secret_key="B" * 64)


def details():
    return dict(info=dict(name=SCOPE["scan_name"], targets=SCOPE["target"],
                         scanner_name=SCOPE["scanner_name"], alt_targets_used=False,
                         tag_targets=[], hostcount=0, status="completed"), hosts=[], comphosts=[])


def history():
    return dict(pagination=dict(total=1, limit=50, offset=0),
                history=[dict(id=7, status="completed", time_start=1, time_end=60)])


class Queue:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, method, path, body):
        self.calls.append((method, path, body))
        result = self.results.pop(0)
        return result if isinstance(result, bytes) else json.dumps(result).encode()


class TenableClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def client(self, *responses):
        transport = Queue(*responses)
        return T.Client(SCOPE, KEYS, transport), transport

    def test_plan_and_nonexecute_actions_never_read_keys_or_connect(self):
        for action in ("plan", "inspect", "request-export", "fetch-export"):
            with self.subTest(action=action), patch.object(T, "private_read", side_effect=AssertionError), \
                    patch.object(T.http.client, "HTTPSConnection", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(T.main([action]), 0)
                self.assertFalse(json.loads(out.getvalue())["network_contacted"])

    def test_only_fixed_scan_routes_are_available(self):
        client, transport = self.client({}, {}, {}, {}, b"export")
        client.request("details", history=7); client.request("history")
        client.request("export", history=7); client.request("status", file_id=9); client.request("download", file_id=9)
        self.assertEqual(transport.calls, [
            ("GET", "/scans/42?history_id=7", None),
            ("GET", "/scans/42/history?limit=50&offset=0&exclude_rollover=false", None),
            ("POST", "/scans/42/export?history_id=7", b'{"format":"nessus"}'),
            ("GET", "/scans/42/export/9/status", None),
            ("GET", "/scans/42/export/9/download", None)])

    def test_mutations_inventory_and_arbitrary_urls_rejected(self):
        client, transport = self.client()
        for action in ("launch", "create", "delete", "edit", "scanners", "credentials", "https://example.invalid"):
            with self.subTest(action=action), self.assertRaises(T.Blocked): client.request(action)
        self.assertEqual(transport.calls, [])

    def test_identifier_injection_rejected_before_transport(self):
        client, transport = self.client()
        for value in (True, None, 0, -1, "../other", "7&target=other", "1\r\n", "01"):
            with self.subTest(value=value), self.assertRaises(T.Blocked): client.request("export", history=value)
        self.assertFalse(transport.calls)

    def test_scope_rejects_multiple_noncanonical_and_nonip_targets(self):
        for target in ("192.0.2.15,192.0.2.16", "192.0.2.0/24", "host.example", "::1", None):
            config = dict(SCOPE, target=target)
            with self.subTest(target=target), self.assertRaises(T.Blocked): T.scope(config)

    def test_credential_header_injection_rejected(self):
        for key in ("A" * 64 + "\r\nInjected: value", "A" * 64 + ";other=value", "short"):
            with self.assertRaises(T.Blocked): T.Client(SCOPE, dict(KEYS, secret_key=key))

    def test_unrecognized_credential_and_scope_fields_rejected(self):
        with self.assertRaises(T.Blocked): T.Client(dict(SCOPE, url="https://example.invalid"), KEYS)
        with self.assertRaises(T.Blocked): T.Client(SCOPE, dict(KEYS, password="fixture"))

    def test_wrong_scan_name_stops_before_history_or_export(self):
        value = details(); value["info"]["name"] = "OTHER"
        client, transport = self.client(value)
        with self.assertRaises(T.Blocked): client.export_request(7, self.base / "run")
        self.assertEqual(len(transport.calls), 1)
        self.assertFalse((self.base / "run").exists())

    def test_expanded_unknown_and_alternate_targets_rejected(self):
        for key, value in (("targets", "192.0.2.16"), ("targets", None), ("tag_targets", ["other"]),
                           ("alt_targets_used", True), ("alt_targets_used", None)):
            d = details(); d["info"][key] = value
            client, _ = self.client(d)
            with self.subTest(key=key, value=value), self.assertRaises(T.Blocked): client.details()

    def test_unknown_or_different_scanner_rejected(self):
        d = details(); d["info"]["scanner_name"] = None
        client, _ = self.client(d)
        with self.assertRaises(T.Blocked): client.details()

    def test_other_or_multiple_reported_hosts_rejected(self):
        for rows in ([{"hostname": "192.0.2.16"}], [{"hostname": SCOPE["target"]}] * 2):
            d = details(); d["hosts"] = rows
            client, _ = self.client(d)
            with self.assertRaises(T.Blocked): client.details()

    def test_zero_hosts_retained_as_evidence_not_compliance_success(self):
        client, _ = self.client(details(), history())
        out = self.base / "inspect"
        result = client.inspect(out)
        self.assertEqual(result["claim"], "unverified")
        self.assertEqual(T.decode(T.private_read(out / "scan-details.private.json"))["info"]["hostcount"], 0)

    def test_unnamed_compliance_host_binds_to_exact_reported_host(self):
        d = details()
        d["hosts"] = [{"hostname": SCOPE["target"], "host_id": 2, "uuid": "synthetic"}]
        d["comphosts"] = [{"host_id": 2, "uuid": "synthetic"}]
        client, _ = self.client(d)
        self.assertEqual(client.details()["comphosts"], d["comphosts"])

    def test_unnamed_compliance_host_requires_matching_positive_id(self):
        for host_id in (None, 3, True, 0, "invalid"):
            d = details()
            d["hosts"] = [{"hostname": SCOPE["target"], "host_id": 2}]
            d["comphosts"] = [{"host_id": host_id, "host_index": 0}]
            client, _ = self.client(d)
            with self.subTest(host_id=host_id), self.assertRaises(T.Blocked):
                client.details()

    def test_unnamed_compliance_host_without_scoped_host_rejected(self):
        d = details(); d["comphosts"] = [{"host_id": 2}]
        client, _ = self.client(d)
        with self.assertRaises(T.Blocked): client.details()

    def test_compliance_identity_conflicts_rejected(self):
        for field, val in (("hostname", "192.0.2.16"), ("host_id", 3),
                           ("asset_id", "different"), ("uuid", "different")):
            d = details()
            row = {"hostname": SCOPE["target"], "host_id": 2,
                   "asset_id": "synthetic-asset", "uuid": "synthetic-uuid"}
            d["hosts"] = [row]
            d["comphosts"] = [dict(row, **{field: val})]
            client, _ = self.client(d)
            with self.subTest(field=field), self.assertRaises(T.Blocked): client.details()

    def test_multiple_compliance_hosts_rejected(self):
        d = details()
        d["hosts"] = [{"hostname": SCOPE["target"], "host_id": 2}]
        d["comphosts"] = [{"host_id": 2}, {"host_id": 2}]
        client, _ = self.client(d)
        with self.assertRaises(T.Blocked): client.details()

    def test_history_pagination_not_silently_truncated(self):
        h = history(); h["pagination"]["total"] = 51
        client, _ = self.client(h)
        with self.assertRaises(T.Blocked): client.history()

    def test_duplicate_history_ids_rejected(self):
        h = history(); h["history"] *= 2; h["pagination"]["total"] = 2
        client, _ = self.client(h)
        with self.assertRaises(T.Blocked): client.history()

    def test_missing_or_running_history_cannot_export(self):
        for change in ("missing", "running"):
            h = history(); h["history"][0]["id" if change == "missing" else "status"] = 8 if change == "missing" else "running"
            client, transport = self.client(details(), h)
            with self.assertRaises(T.Blocked): client.export_request(7, self.base / "new")
            self.assertTrue(all(c[0] == "GET" for c in transport.calls))

    def test_export_job_stores_file_id_without_response_token(self):
        client, transport = self.client(details(), history(), {"file": 9, "token": "SENSITIVE-EXPORT-TOKEN"})
        out = self.base / "request"
        client.export_request(7, out)
        saved = b"".join(p.read_bytes() for p in out.iterdir())
        self.assertNotIn(b"SENSITIVE-EXPORT-TOKEN", saved)
        self.assertEqual(sum(c[0] == "POST" for c in transport.calls), 1)
        self.assertEqual(T.decode((out / "job.private.json").read_bytes())["history_id"], "7")

    def test_unsupported_export_response_not_retried(self):
        client, transport = self.client(details(), history(), {"token": "opaque"})
        with self.assertRaises(T.Blocked): client.export_request(7, self.base / "request")
        self.assertEqual(sum(c[0] == "POST" for c in transport.calls), 1)

    def test_uuid_export_identifier_round_trip(self):
        file_id = "12345678-1234-4abc-8def-123456789abc"
        client, transport = self.client(details(), history(), {"file": file_id, "token": "PRIVATE-TOKEN"},
                                        {"status": "ready"}, b"SYNTHETIC EXPORT")
        out = self.base / "request"
        client.export_request(7, out)
        job = T.decode(T.private_read(out / "job.private.json"))
        self.assertEqual(job["file_id"], file_id)
        self.assertNotIn(b"PRIVATE-TOKEN", (out / "job.private.json").read_bytes())
        self.assertTrue(client.fetch_export(job, self.base / "download")["readback_verified"])
        self.assertEqual(transport.calls[-2:], [
            ("GET", f"/scans/42/export/{file_id}/status", None),
            ("GET", f"/scans/42/export/{file_id}/download", None)])
        self.assertEqual(sum(c[0] == "POST" for c in transport.calls), 1)

    def test_opaque_live_shape_identifier_round_trip(self):
        # Synthetic 47-character shape; no private live identifier is included.
        file_id = "scan-export_" + "a" * 35
        client, transport = self.client(details(), history(), {"file": file_id}, {"status": "loading"})
        out = self.base / "request"
        client.export_request(7, out)
        job = T.decode(T.private_read(out / "job.private.json"))
        self.assertFalse(client.fetch_export(job, self.base / "download")["ready"])
        self.assertEqual(transport.calls[-1], ("GET", f"/scans/42/export/{file_id}/status", None))
        self.assertEqual(T.decode(T.private_read(self.base / "request.receipt.private.json"))["file"], file_id)

    def test_invalid_returned_id_receipt_is_private_and_token_free(self):
        client, transport = self.client(details(), history(), {"file": "unsupported:shape", "token": "PRIVATE-TOKEN"})
        with self.assertRaises(T.Blocked):
            client.export_request(7, self.base / "request")
        receipt = self.base / "request.receipt.private.json"
        data = T.private_read(receipt)
        self.assertEqual(T.decode(data)["file"], "unsupported:shape")
        self.assertNotIn(b"PRIVATE-TOKEN", data)
        self.assertEqual(sum(c[0] == "POST" for c in transport.calls), 1)

    def test_existing_receipt_prevents_export_post(self):
        T.private_write(self.base / "request.receipt.private.json", b"already recorded")
        client, transport = self.client(details(), history())
        with self.assertRaises(T.Blocked):
            client.export_request(7, self.base / "request")
        self.assertTrue(all(c[0] == "GET" for c in transport.calls))

    def test_zero_export_identifier_remains_separate_from_scan_identifiers(self):
        client, transport = self.client({"status": "loading"})
        job = dict(self.job(), file_id="0")
        self.assertFalse(client.fetch_export(job, self.base / "download")["ready"])
        self.assertEqual(transport.calls, [("GET", "/scans/42/export/0/status", None)])
        self.assertEqual(T.export_identifier(0), "0")
        with self.assertRaises(T.Blocked):
            T.identifier(0)

    def test_invalid_export_identifiers_stop_before_transport(self):
        invalid = (True, None, -1, "", "../other", "1?other=2", "1\r\n", "a" * 129,
                   "12345678-1234-4abc-8def-123456789abc/extra", "a%2Fb", "a:b", " a", "é")
        for file_id in invalid:
            client, transport = self.client()
            with self.subTest(file_id=file_id), self.assertRaises(T.Blocked):
                client.fetch_export(dict(self.job(), file_id=file_id), self.base / "download")
            self.assertFalse(transport.calls)

    def test_export_uuid_does_not_expand_scan_or_history_scope(self):
        value = "12345678-1234-4abc-8def-123456789abc"
        with self.assertRaises(T.Blocked):
            T.Client(dict(SCOPE, scan_id=value), KEYS)
        client, transport = self.client()
        with self.assertRaises(T.Blocked):
            client.request("details", history=value)
        self.assertFalse(transport.calls)

    def test_existing_output_blocks_export_before_post(self):
        client, transport = self.client(details(), history())
        with self.assertRaises(T.Blocked): client.export_request(7, self.base)
        self.assertTrue(all(c[0] == "GET" for c in transport.calls))

    def job(self):
        return dict(schema=1, scan_id="42", history_id="7", file_id="9", scope_sha256=T.scope_digest(SCOPE))

    def test_loading_does_not_download_or_request_another_export(self):
        client, transport = self.client({"status": "loading"})
        self.assertFalse(client.fetch_export(self.job(), self.base / "fetch")["ready"])
        self.assertEqual(transport.calls, [("GET", "/scans/42/export/9/status", None)])

    def test_ready_download_hash_and_modes(self):
        payload = b"SYNTHETIC BYTES; not a real scan"
        client, _ = self.client({"status": "ready"}, payload)
        out = self.base / "download"; result = client.fetch_export(self.job(), out)
        self.assertTrue(result["readback_verified"])
        manifest = T.decode((out / "manifest.json").read_bytes())
        self.assertEqual(manifest["files"]["scan.nessus"], T.hashlib.sha256(payload).hexdigest())
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in out.iterdir()))
        self.assertIn("pending", manifest["parser_validation"])

    def test_mismatched_job_cannot_make_network_request(self):
        for key, value in (("scan_id", "43"), ("scope_sha256", "bad"), ("schema", True), ("file_id", "../other")):
            client, transport = self.client(); job = self.job(); job[key] = value
            with self.subTest(key=key), self.assertRaises(T.Blocked): client.fetch_export(job, self.base / "out")
            self.assertFalse(transport.calls)

    def test_failed_export_does_not_download(self):
        client, transport = self.client({"status": "error"})
        with self.assertRaises(T.Blocked): client.fetch_export(self.job(), self.base / "out")
        self.assertEqual(len(transport.calls), 1)

    def test_json_duplicate_and_nonfinite_fields_rejected(self):
        for data in (b'{"file":1,"file":2}', b'{"value":NaN}', b'{"value":Infinity}', b'not json'):
            with self.subTest(data=data), self.assertRaises(T.Blocked): T.decode(data)

    def test_private_storage_rejects_repository(self):
        with self.assertRaises(T.Blocked): T.private_write(ROOT / "forbidden.json", b"fixture")
        self.assertFalse((ROOT / "forbidden.json").exists())

    def test_private_storage_refuses_wrong_modes_and_links(self):
        path = self.base / "file"; path.write_bytes(b"fixture"); path.chmod(0o644)
        with self.assertRaises(T.Blocked): T.private_read(path)
        path.chmod(0o600); link = self.base / "link"; link.symlink_to(path)
        with self.assertRaises(OSError): T.private_read(link)
        directory_link = self.base / "dirlink"; directory_link.symlink_to(self.base)
        with self.assertRaises(T.Blocked): T.private_read(directory_link / "file")

    def test_private_storage_refuses_hardlinks_and_overwrite(self):
        path = self.base / "file"; T.private_write(path, b"original")
        with self.assertRaises(FileExistsError): T.private_write(path, b"replacement")
        os.link(path, self.base / "hardlink")
        with self.assertRaises(T.Blocked): T.private_read(path)

    def test_setup_refuses_noninteractive_secret_input(self):
        with patch.object(T.sys.stdin, "isatty", return_value=False), patch.object(T.getpass, "getpass", side_effect=AssertionError):
            with self.assertRaises(T.Blocked): T.setup(self.base / "scope", self.base / "credentials")

    def test_setup_hidden_entry_no_network_or_echo(self):
        config = dict(SCOPE, scan_id=None); source = self.base / "scope.json"
        T.private_write(source, T.json_bytes(config)); dest = self.base / "connection.json"
        with patch.object(T.sys.stdin, "isatty", return_value=True), patch("builtins.input", return_value="42"), \
                patch.object(T.getpass, "getpass", side_effect=list(KEYS.values())), \
                patch.object(T.http.client, "HTTPSConnection", side_effect=AssertionError):
            result = T.setup(source, dest)
        self.assertFalse(result["network_contacted"])
        self.assertNotIn(KEYS["secret_key"], json.dumps(result))
        self.assertEqual(T.decode(T.private_read(dest))["scope"]["scan_id"], "42")

    def test_https_fixed_origin_and_verified_tls(self):
        connection = Mock(); response = connection.getresponse.return_value
        response.status = 200; response.getheader.return_value = None; response.read.return_value = b'{}'
        with patch.object(T.http.client, "HTTPSConnection", return_value=connection) as factory:
            T.Client(SCOPE, KEYS).request("details")
        self.assertEqual(factory.call_args.args, ("cloud.tenable.com",))
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname); self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(connection.request.call_args.args[:2], ("GET", "/scans/42"))
        connection.close.assert_called_once()

    def test_redirect_auth_denial_and_rate_limit_never_read_body_or_retry(self):
        for status in (301, 302, 307, 401, 403, 429, 500):
            connection = Mock(); response = connection.getresponse.return_value; response.status = status
            with self.subTest(status=status), patch.object(T.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaisesRegex(T.Blocked, str(status)): T.Client(SCOPE, KEYS).request("details")
            response.read.assert_not_called(); self.assertEqual(connection.request.call_count, 1)

    def test_reflected_api_key_is_discarded(self):
        connection = Mock(); response = connection.getresponse.return_value
        response.status = 200; response.getheader.return_value = None; response.read.return_value = KEYS["secret_key"].encode()
        with patch.object(T.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(T.Blocked) as error: T.Client(SCOPE, KEYS).request("details")
        self.assertNotIn(KEYS["secret_key"], str(error.exception))

    def test_transport_error_does_not_echo_exception_or_retry(self):
        connection = Mock(); connection.request.side_effect = OSError(KEYS["secret_key"])
        with patch.object(T.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(T.Blocked) as error: T.Client(SCOPE, KEYS).request("details")
        self.assertNotIn(KEYS["secret_key"], str(error.exception))
        self.assertEqual(connection.request.call_count, 1)

    def test_oversize_response_stops_before_read(self):
        connection = Mock(); response = connection.getresponse.return_value
        response.status = 200; response.getheader.return_value = str(T.MAX_BYTES + 1)
        with patch.object(T.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(T.Blocked): T.Client(SCOPE, KEYS).request("details")
        response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()

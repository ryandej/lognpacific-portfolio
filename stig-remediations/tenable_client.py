"""Single-scan Tenable evidence client. Offline by default; no scan mutations.

Linux user-scoped credentials are entered with getpass, never command arguments.
Only scan details/history and export request/status/download routes are allowed.
Live details/history, export status and completed original-export download observed.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import warnings

ROOT = Path(__file__).resolve().parents[1]
HOST = "cloud.tenable.com"
MAX_BYTES = 16 * 1024 * 1024
SCOPE_KEYS = {"scan_id", "scan_name", "target", "scanner_name"}


class Blocked(ValueError):
    """Safe messages only: never interpolate remote bodies or credentials."""


def require(condition, message):
    if not condition:
        raise Blocked(message)


def identifier(value):
    require(type(value) in (str, int) and re.fullmatch(r"[1-9][0-9]{0,17}", str(value)),
            "A positive numeric identifier is required.")
    return str(value)


def export_identifier(value):
    """Keep opaque export IDs in one bounded, unescaped URL path segment."""
    require(type(value) in (str, int) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}",
        str(value)), "Unsupported export file identifier; review the private receipt before another export.")
    return str(value)


def decode(data):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "Duplicate JSON fields rejected.")
            result[k] = v
        return result
    def invalid_number(_):
        raise Blocked("Invalid JSON number.")
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=invalid_number)
    except (ValueError, UnicodeError):
        raise Blocked("Unsupported JSON response or configuration.") from None


def scope(value, allow_unbound=False):
    require(type(value) is dict and set(value) == SCOPE_KEYS, "Invalid scope fields.")
    if not (allow_unbound and value["scan_id"] is None):
        identifier(value["scan_id"])
    for key in ("scan_name", "scanner_name"):
        require(isinstance(value[key], str) and 1 <= len(value[key]) <= 200 and
                all(32 <= ord(c) < 127 for c in value[key]), "Invalid scope name.")
    require(isinstance(value["target"], str), "Scope requires one canonical IPv4 target.")
    try:
        target = ipaddress.ip_address(value["target"])
    except ValueError:
        raise Blocked("Scope requires one canonical IPv4 target.") from None
    require(target.version == 4 and str(target) == value["target"],
            "Scope requires one canonical IPv4 target.")
    return dict(value)


def scope_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


@contextmanager
def private_directory(path, create=False):
    """Use a pinned directory descriptor; reject links and repository storage."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "Private path must be absolute.")
    require(not path.resolve().is_relative_to(ROOT), "Private storage must be outside Git workspace.")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "Symlink storage is not permitted.")
    if create:
        path.mkdir(mode=0o700)  # Fresh directory only; never alter existing permissions.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "Private directory must be owned by this user with mode 0700.")
        yield fd
    finally:
        os.close(fd)


def private_read(path):
    path = Path(path)
    with private_directory(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    "Private input must be an owned, single-link regular file with mode 0600.")
            require(info.st_size <= MAX_BYTES, "Private input exceeds size limit.")
            data = stream.read(MAX_BYTES + 1)
            require(len(data) <= MAX_BYTES, "Private input exceeds size limit.")
            return data


def private_write(path, data):
    path = Path(path)
    require(isinstance(data, bytes) and len(data) <= MAX_BYTES, "Private output exceeds size limit.")
    with private_directory(path.parent) as directory:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    digest = hashlib.sha256(data).hexdigest()
    require(hashlib.sha256(private_read(path)).hexdigest() == digest, "Private readback integrity failure.")
    return digest


def json_bytes(data):
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()


def validate_keys(keys):
    require(type(keys) is dict and set(keys) == {"access_key", "secret_key"}, "Invalid credential fields.")
    require(all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", v)
                for v in keys.values()), "Invalid API credential format.")
    return keys


def setup(scope_path, connection_path):
    require(sys.stdin.isatty(), "Setup requires an interactive terminal; piped credentials are refused.")
    config = scope(decode(private_read(scope_path)), allow_unbound=True)
    if config["scan_id"] is None:
        config["scan_id"] = identifier(input("Numeric ID from the owned scan URL: ").strip())
    scope(config)
    require(not Path(connection_path).exists(), "Existing connection will not be overwritten.")
    with private_directory(Path(connection_path).parent):
        pass
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        keys = validate_keys({"access_key": getpass.getpass("Tenable access key (hidden): "),
                              "secret_key": getpass.getpass("Tenable secret key (hidden): ")})
    private_write(connection_path, json_bytes({"schema": 1, "scope": config, "keys": keys}))
    return {"configured": True, "network_contacted": False, "keys_printed": False}


class Client:
    def __init__(self, config, keys, transport=None):
        self.scope = scope(config)
        self.keys = validate_keys(keys)
        self.scan = identifier(config["scan_id"])
        self.transport = transport or self._https

    def _https(self, method, path, body):
        # Fixed TLS origin; no redirect, proxy-env, cookie jar, netrc or debug logging.
        connection = http.client.HTTPSConnection(HOST, timeout=30, context=ssl.create_default_context())
        header = "accessKey=" + self.keys["access_key"] + ";secretKey=" + self.keys["secret_key"] + ";"
        try:
            connection.request(method, path, body=body,
                               headers={"X-ApiKeys": header, "Accept": "application/json, application/octet-stream",
                                        "Content-Type": "application/json", "User-Agent": "logn-evidence-client/1"})
            response = connection.getresponse()
            require(response.status == 200, "API request stopped (HTTP " + str(response.status) + "). No automatic retry.")
            length = response.getheader("Content-Length")
            require(length is None or (length.isdigit() and int(length) <= MAX_BYTES), "Response exceeds size limit.")
            data = response.read(MAX_BYTES + 1)
            require(len(data) <= MAX_BYTES, "Response exceeds size limit.")
            require(not any(k.encode() in data for k in self.keys.values()),
                    "Response unexpectedly contains an API credential; discarded.")
            return data
        except (OSError, http.client.HTTPException):
            raise Blocked("Transport failed; an export POST may have been accepted. Do not blindly repeat it.") from None
        finally:
            connection.close()

    def request(self, action, history=None, file_id=None):
        base = "/scans/" + self.scan
        body = None
        if action == "details":
            method, path = "GET", base + ("?history_id=" + identifier(history) if history is not None else "")
        elif action == "history":
            method, path = "GET", base + "/history?limit=50&offset=0&exclude_rollover=false"
        elif action == "export":
            method, path = "POST", base + "/export?history_id=" + identifier(history)
            body = b'{"format":"nessus"}'
        elif action in ("status", "download"):
            method, path = "GET", base + "/export/" + export_identifier(file_id) + "/" + action
        else:
            raise Blocked("Operation outside evidence allowlist.")
        data = self.transport(method, path, body)
        require(isinstance(data, bytes) and len(data) <= MAX_BYTES, "Invalid transport data.")
        return data if action == "download" else decode(data)

    def details(self, history=None):
        value = self.request("details", history=history)
        require(type(value) is dict and type(value.get("info")) is dict, "Unsupported scan-details schema.")
        info = value["info"]
        require(info.get("name") == self.scope["scan_name"], "Scan name differs from approved scope.")
        require(info.get("targets") == self.scope["target"] and not info.get("tag_targets") and
                info.get("alt_targets_used") is False, "Target scope is expanded, alternate or unconfirmed.")
        require(info.get("scanner_name") == self.scope["scanner_name"], "Assigned scanner differs or is unknown.")
        hosts = value.get("hosts", [])
        require(type(hosts) is list and len(hosts) <= 1 and all(type(r) is dict and
                r.get("hostname") == self.scope["target"] for r in hosts),
                "Reported host identity is unsupported or outside scope.")
        compliance = value.get("comphosts", [])
        require(type(compliance) is list and len(compliance) <= 1 and
                all(type(r) is dict for r in compliance), "Unsupported compliance host list.")
        for row in compliance:
            # Actual TVM compliance rows can omit hostname. Bind their host_id
            # to the one IP-validated host in THIS response, never host_index,
            # DNS resolution, or a host from another scan/history.
            if row.get("hostname") is not None:
                require(row["hostname"] == self.scope["target"], "Compliance host name differs from scope.")
            else:
                require(len(hosts) == 1 and row.get("host_id") is not None and
                        hosts[0].get("host_id") is not None and
                        identifier(row["host_id"]) == identifier(hosts[0]["host_id"]),
                        "Unnamed compliance host cannot be bound to the scoped host.")
            if hosts:
                for key in ("host_id", "asset_id", "uuid"):
                    left, right = row.get(key), hosts[0].get(key)
                    if left is not None and right is not None:
                        if key == "host_id":
                            left, right = identifier(left), identifier(right)
                        require(left == right, "Conflicting compliance host identity.")
        return value

    def history(self):
        value = self.request("history")
        require(type(value) is dict and type(value.get("history")) is list and
                type(value.get("pagination")) is dict, "Unsupported history schema.")
        rows = value["history"]
        total = value["pagination"].get("total")
        require(type(total) is int and 0 <= total == len(rows) <= 50, "History incomplete; pagination needs explicit review.")
        require(all(type(row) is dict for row in rows), "Unsupported history entry.")
        ids = [identifier(row["id"]) for row in rows if row.get("id") is not None]
        require(len(ids) == len(set(ids)), "Duplicate history identifiers.")
        return value

    def inspect(self, output):
        details = self.details()
        history = self.history()
        return save_evidence(output, {"scan-details.private.json": json_bytes(details),
                                      "scan-history.private.json": json_bytes(history)},
                             {"claim": "unverified", "action": "inspect", "scope_sha256": scope_digest(self.scope)})

    def export_request(self, history_id, output):
        history_id = identifier(history_id)
        details = self.details(history_id)
        histories = self.history()
        matches = [r for r in histories["history"] if r.get("id") is not None and identifier(r["id"]) == history_id]
        require(len(matches) == 1 and matches[0].get("status") in ("completed", "aborted", "canceled"),
                "Requested history is absent or not a supported terminal run.")
        # Validate destination before a POST. Never auto-repeat an uncertain POST.
        with private_directory(Path(output).parent):
            pass
        require(not Path(output).exists(), "Evidence directory already exists.")
        receipt_path = Path(output).with_name(Path(output).name + ".receipt.private.json")
        require(not receipt_path.exists() and not receipt_path.is_symlink(), "Export receipt already exists.")
        job = self.request("export", history=history_id)
        # Retain only the file identifier before validation, never an export token.
        # This allows recovery from a new response format without guessing or
        # automatically repeating a POST whose result was discarded.
        returned_file = job.get("file") if type(job) is dict else None
        receipt = {"schema": 1, "scan_id": self.scan, "history_id": history_id,
                   "scope_sha256": scope_digest(self.scope),
                   "received_at_utc": datetime.now(timezone.utc).isoformat(),
                   "file_present": type(job) is dict and "file" in job}
        if type(returned_file) in (str, int) and len(str(returned_file)) <= 512:
            receipt["file"] = returned_file
        else:
            receipt["unsupported_file_type"] = type(returned_file).__name__
        private_write(receipt_path, json_bytes(receipt))
        require(type(job) is dict and "file" in job, "Export response has no supported file ID; do not repeat blindly.")
        job = {"schema": 1, "scan_id": self.scan, "history_id": history_id,
               "file_id": export_identifier(job["file"]), "scope_sha256": scope_digest(self.scope)}
        return save_evidence(output, {"job.private.json": json_bytes(job),
                                     "scan-details.private.json": json_bytes(details)},
                             {"claim": "unverified", "action": "export-request", "scan_launched": False})

    def fetch_export(self, job, output):
        require(type(job) is dict and set(job) == {"schema", "scan_id", "history_id", "file_id", "scope_sha256"} and
                type(job["schema"]) is int and job["schema"] == 1 and job["scan_id"] == self.scan and
                job["scope_sha256"] == scope_digest(self.scope), "Export job does not match the approved scope.")
        identifier(job["history_id"])
        status = self.request("status", file_id=job["file_id"])
        require(type(status) is dict and status.get("status") in ("ready", "loading"), "Export failed or has unknown status.")
        if status["status"] != "ready":
            return {"ready": False, "retry": "Fetch this same export job later; do not request another export."}
        data = self.request("download", file_id=job["file_id"])
        require(data, "Empty export response.")
        return save_evidence(output, {"scan.nessus": data, "job.private.json": json_bytes(job)},
                             {"claim": "unverified", "action": "export-download", "ready": True,
                              "parser_validation": "pending; downloading bytes does not verify XML or target results"})


def save_evidence(directory, files, metadata):
    directory = Path(directory)
    with private_directory(directory, create=True):
        pass
    manifest = dict(metadata, captured_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), files={})
    for name, data in files.items():
        require(Path(name).name == name, "Unsafe evidence filename.")
        manifest["files"][name] = private_write(directory / name, data)
    private_write(directory / "manifest.json", json_bytes(manifest))
    return {"saved": len(files), "readback_verified": True, "claim": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "setup", "inspect", "request-export", "fetch-export"))
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--connection", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--job", type=Path)
    parser.add_argument("--history-id")
    parser.add_argument("--execute", action="store_true", help="enable this specifically authorized network action")
    args = parser.parse_args(argv)
    try:
        if args.action == "plan" or (args.action != "setup" and not args.execute):
            result = {"network_contacted": False, "scan_launch_supported": False,
                      "allowed_actions": ["scan details/history", "existing-history export request/status/download"],
                      "requires": ["approved API access and protected setup", "exact owned scan ID", "explicit --execute"]}
        elif args.action == "setup":
            require(args.scope is not None and args.connection is not None, "Setup requires explicit scope and connection paths.")
            result = setup(args.scope, args.connection)
        else:
            require(args.connection is not None and args.output is not None, "Private connection and output paths required.")
            config = decode(private_read(args.connection))
            require(type(config) is dict and set(config) == {"schema", "scope", "keys"} and
                    type(config["schema"]) is int and config["schema"] == 1,
                    "Invalid connection schema.")
            client = Client(config["scope"], config["keys"])
            if args.action == "inspect":
                result = client.inspect(args.output)
            elif args.action == "request-export":
                result = client.export_request(args.history_id, args.output)
            else:
                require(args.job is not None, "Existing export job required.")
                result = client.fetch_export(decode(private_read(args.job)), args.output)
        print(json.dumps(result, indent=2))
        return 0
    except Blocked as error:
        print("Stopped: " + str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        print("Stopped: scope, access, transport or private-storage gate failed. No credentials or remote response printed. Review the gate privately; do not blindly retry an export request.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

"""Synthetic reference model for auth-sequence.kql; does not execute or parse KQL.

Accepts pseudonymous fixture rows only. No file, network, or response operations.
"""
from datetime import datetime, timedelta


def detect(events, start, end, devices, threshold=5, window=timedelta(minutes=10)):
    if not isinstance(start, datetime) or not isinstance(end, datetime) or start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ValueError("explicit ordered timezone-aware window required")
    if type(threshold) is not int or threshold < 1 or window <= timedelta(0):
        raise ValueError("positive threshold and window required")
    scoped, seen = [], set()
    for row in events:
        at = row["Timestamp"]
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise ValueError("event timestamp must be timezone-aware")
        if row["DeviceId"] not in devices or not start <= at < end:
            continue
        if any(not row.get(k) for k in ("AccountName", "AccountDomain", "RemoteIP", "LogonType")) or row.get("ReportId") is None:
            continue
        key = (row["DeviceId"], row["AccountName"].lower(), row["AccountDomain"].lower(), row["RemoteIP"], row["LogonType"])
        identity = (at, row["ReportId"], row["ActionType"], key)
        if identity not in seen:
            scoped.append((at, row["ReportId"], row["ActionType"], key))
            seen.add(identity)
    found = []
    for at, report_id, action, key in scoped:
        if action != "LogonSuccess":
            continue
        failures = [t for t, _, a, k in scoped if a == "LogonFailed" and k == key and at - window <= t < at]
        if len(failures) >= threshold:
            found.append(dict(key=key, success_at=at, success_report_id=report_id,
                              failure_count=len(failures), first_failure=min(failures), last_failure=max(failures)))
    return sorted(found, key=lambda r: (r["success_at"], r["key"], r["success_report_id"]))

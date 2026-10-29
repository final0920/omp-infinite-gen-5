"""Bounded local profile input. Pairing material never enters protocol output."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

def stable_read(filename, maximum):
    path = Path(filename)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Expected an absolute, non-linked profile input")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
        raise ValueError("Profile input size/type exceeds budget")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
    current = path.stat()
    # Windows Python can expose different ctime values through path stat and
    # descriptor fstat. Compare each clock within its own observation domain.
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if len(data) > maximum or any(identity(row) != identity(before) for row in (opened, after, current)) or before.st_ctime_ns != current.st_ctime_ns or opened.st_ctime_ns != after.st_ctime_ns:
        raise ValueError("Profile input changed during read")
    return data

def load_profile(filename, expected_sha256):
    data = stable_read(filename, 65536)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Guest profile digest changed")
    profile = json.loads(data.decode("utf-8"))
    if not isinstance(profile, dict) or set(profile) != {"schema", "guestCID", "port", "guestLabel", "bundleSha256", "pairingKeyRef", "targets"} or profile["schema"] != "ig5-vmci-guest-profile-v1":
        raise ValueError("Invalid guest profile schema")
    if type(profile["guestCID"]) is not int or not 3 <= profile["guestCID"] <= 0xfffffffe or type(profile["port"]) is not int or not 1024 <= profile["port"] <= 0xfffffffe or not isinstance(profile["guestLabel"], str) or not profile["guestLabel"].strip() or len(profile["guestLabel"]) > 128:
        raise ValueError("Invalid guest profile identity")
    digest = lambda value: isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None
    reference = profile["pairingKeyRef"]
    if not digest(profile["bundleSha256"]) or not isinstance(reference, dict) or set(reference) != {"path", "sha256"} or not digest(reference["sha256"]):
        raise ValueError("Invalid guest digest/key reference")
    key = stable_read(reference["path"], 32)
    if len(key) != 32 or hashlib.sha256(key).hexdigest() != reference["sha256"]:
        raise ValueError("Guest pairing key differs")
    targets = profile["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64 or any(not isinstance(row, dict) or set(row) != {"id", "sha256"} or not isinstance(row["id"], str) or re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", row["id"]) is None or not digest(row["sha256"]) for row in targets) or len({row["id"] for row in targets}) != len(targets) or len({row["sha256"] for row in targets}) != len(targets):
        raise ValueError("Invalid or ambiguous guest target catalog")
    return profile, key

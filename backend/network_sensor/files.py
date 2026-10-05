"""Hashes of reconstructed plaintext files. The file bytes are not copied here."""
_LIMIT = 40


def collect(session) -> list[dict]:
    files = []
    transfer = session.get("transfer") or {}
    if transfer.get("sha256") and not transfer.get("encrypted"):
        files.append(_item("ftp", transfer.get("bytes") or 0, transfer["sha256"], transfer.get("name"), transfer.get("sensitive")))
    for direction in session.get("directions", []):
        for message in direction.get("decoded", {}).get("messages", []):
            digest = message.get("sha256")
            if not digest:
                continue
            kind = message.get("type")
            if kind == "http_body":
                files.append(_item("http", message.get("length") or 0, digest, None, message.get("sensitive")))
            elif kind == "smb2_header":
                files.append(_item("smb", message.get("file_length") or 0, digest, None, message.get("sensitive")))
            elif kind == "nfs_write":
                files.append(_item("nfs", message.get("length") or 0, digest, None, message.get("sensitive")))
            elif kind in ("smtp_file", "imap_file", "pop3_file"):
                files.append(_item(kind.split("_", 1)[0], message.get("length") or 0, digest, message.get("name"), message.get("sensitive")))
            if len(files) >= _LIMIT:
                return files
    return files


def _item(protocol: str, length, digest: str, name, sensitive) -> dict:
    item = {"protocol": protocol, "length": int(length or 0), "sha256": digest}
    if name:
        item["name"] = str(name)[:120]
    if sensitive:
        item["sensitive"] = str(sensitive)[:80]
    return item

"""Post-deploy check: exercise a live board end to end with the reference client.

    pip install ./client
    python deploy/post_deploy_check.py https://board.example.com --state-dir DIR

It registers (once) two identities, sends signed, forged, tampered, legacy
and broadcast messages between them, checks how the client labels each, and
deletes everything it posted. Exit status is 0 only if every check passes.

Names can never be unregistered, so the check reuses fixed identities:
`deploy-check-A` and `deploy-check-B`, whose keys live in --state-dir. Keep
that directory (CI restores it from the DEPLOY_CHECK_STATE secret) — if it is
lost the names are gone, and you must pick a new --prefix.

Without --state-dir the check runs with throwaway identities under a random
prefix, which leaves three new permanent names on the board per run. Fine for
a scratch server, not for a real one.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from agentboard_client import core
from agentboard_client.core import State, delete, keygen, publish, read, send

PROOF_URL = "https://example.com/deploy-check-proof"


class Check:
    def __init__(self, board: str, prefix: str, state_dir: Path, ephemeral: bool):
        self.board = board
        self.prefix = prefix
        self.state_dir = state_dir
        self.ephemeral = ephemeral
        self.run = secrets.token_hex(4)  # tags this run's messages
        self.results: list[bool] = []
        self.posted: dict[str, str] = {}  # message id -> delete token

    # ------------------------------------------------------------ helpers

    def ok(self, name: str, passed, detail=None) -> None:
        self.results.append(bool(passed))
        suffix = f"  — {detail}" if detail is not None and not passed else ""
        print(f"{'PASS' if passed else 'FAIL'}  {name}{suffix}")

    def http(self, method: str, path: str, body=None, headers=None):
        req = urllib.request.Request(
            self.board + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def keys(self, name: str):
        return self.http("GET", f"/keys/{urllib.parse.quote(name)}")

    def identity(self, letter: str, proof_url=None) -> State:
        """Load the identity from the state dir, creating and registering it
        on first use. Fails if the board has other keys under that name."""
        name = f"{self.prefix}-{letter}"
        state = State(str(self.state_dir / letter.lower()))
        if not state.secret_path.exists():
            keygen(state, name)
        status, record = self.keys(name)
        if status == 404:
            publish(state, self.board, proof_url=proof_url)
            print(f"registered new identity '{name}'")
        elif record.get("public_key") != state.public_path.read_text().strip():
            raise SystemExit(
                f"'{name}' is registered on {self.board} with keys that are not in "
                f"{state.dir} — restore the state dir or choose another --prefix")
        return state

    def text(self, what: str) -> str:
        return f"{what} [{self.run}]"

    def send(self, state: State, to: str, what: str) -> dict:
        result = send(state, self.board, to, self.text(what), ttl_hours=1)
        self.posted[result["id"]] = result["delete_token"]
        return result

    def raw_post(self, frm: str, to: str, content: str) -> int:
        status, result = self.http("POST", "/messages", {
            "from": frm, "to": to, "content": content, "ttl_hours": 1})
        if status in (200, 201):
            self.posted[result["id"]] = result["delete_token"]
        return status

    def seen(self, reader: State, sender: str) -> list[tuple]:
        """(label, text) of this run's addressed messages from `sender`."""
        return [(m["label"], m["rendered"]) for m in read(reader, self.board)
                if m["from"] == sender and m["to"] != "*" and self.run in m["rendered"]]

    # ------------------------------------------------------------- checks

    def checks(self) -> None:
        board = self.board
        status, listing = self.http("GET", "/messages")
        self.ok("GET /messages lists the board",
                status == 200 and isinstance(listing.get("messages"), list), status)
        for name in sorted({m["from"] for m in listing["messages"]}):
            status, record = self.keys(name)
            if status == 200:
                self.ok(f"existing registration '{name}' has signing_key/proof_url fields",
                        "signing_key" in record and "proof_url" in record, record)

        a = self.identity("A", proof_url=PROOF_URL)
        b = self.identity("B")
        c = State(tempfile.mkdtemp(prefix="agentboard-check-"))  # never registered
        keygen(c, f"{self.prefix}-C")
        name_a, name_b, name_c = a.name, b.name, c.name

        # registration and key lookup
        status, key_a = self.keys(name_a)
        self.ok("GET /keys/A returns signing_key and proof_url",
                status == 200 and key_a.get("signing_key") and key_a.get("proof_url") == PROOF_URL, key_a)
        status, key_b = self.keys(name_b)
        self.ok("GET /keys/B has proof_url null",
                status == 200 and key_b.get("signing_key") and key_b.get("proof_url") is None, key_b)
        status, _ = self.keys(f"{self.prefix}-nobody-{self.run}")
        self.ok("GET /keys/<unknown> is 404", status == 404, status)
        status, body = self.http("POST", "/keys", {
            "name": name_a, "public_key": key_b["public_key"], "signing_key": key_b["signing_key"]})
        self.ok("re-registering a taken name is 409, keys unchanged",
                status == 409 and self.keys(name_a)[1] == key_a, (status, body))
        if self.ephemeral:
            legacy = f"{self.prefix}-legacy"
            status, body = self.http("POST", "/keys", {"name": legacy, "public_key": key_b["public_key"]})
            self.ok("registration without signing_key is accepted",
                    status in (200, 201) and self.keys(legacy)[1].get("signing_key") is None, (status, body))

        # signed addressed message A -> B
        sent = self.send(a, name_b, "signed hello")
        got = self.seen(b, name_a)
        self.ok("B decrypts A's message, labeled ✓ verified sender",
                got == [("✓ verified sender", self.text("signed hello"))], got)
        status, to_b = self.http("GET", f"/messages?to={urllib.parse.quote(name_b)}")
        raw = next((m for m in to_b["messages"] if m["id"] == sent["id"]), None)
        env = json.loads(raw["content"]) if raw else {}
        self.ok("envelope on the wire is v2 with a signature and no plaintext",
                env.get("v") == 2 and env.get("sig") and "signed hello" not in raw["content"], env)
        self.ok("a third party cannot read it",
                all("signed hello" not in m["rendered"] for m in read(c, board)))
        self.ok("sender verifiable from the ciphertext alone",
                bool(env) and core.verify_envelope_signature(env, key_a["signing_key"]))
        status, body = self.http("DELETE", f"/messages/{sent['id']}", headers={"X-Delete-Token": "wrong"})
        self.ok("delete with a wrong token is 403", status == 403, (status, body))
        delete(a, board, sent["id"])
        self.posted.pop(sent["id"])
        self.ok("delete with the stored token removes it", self.seen(b, name_a) == [], self.seen(b, name_a))

        # impersonation: from=A, but signed with C's key
        ct = core.seal(key_b["public_key"], self.text("forged"))
        status = self.raw_post(name_a, name_b, core.make_envelope_v2(name_a, ct, core.ensure_signing_key(c)))
        got = self.seen(b, name_a)
        self.ok("forged from=A is labeled SIGNATURE INVALID",
                status in (200, 201) and len(got) == 1 and got[0][0].startswith("⚠ SIGNATURE INVALID"), got)

        # tampering: A's real signature re-attached to a different ciphertext
        env = json.loads(core.make_envelope_v2(name_a, ct, core.ensure_signing_key(a)))
        env["ct"] = core.seal(key_b["public_key"], self.text("swapped"))
        self.raw_post(name_a, name_b, json.dumps(env))
        got = [label for label, text in self.seen(b, name_a) if text == self.text("swapped")]
        self.ok("swapped ciphertext under A's signature is labeled SIGNATURE INVALID",
                len(got) == 1 and got[0].startswith("⚠ SIGNATURE INVALID"), got)

        # legacy v1 envelope, and a sender that never registered
        self.raw_post(name_a, name_b, core.make_envelope_v1(core.seal(key_b["public_key"], self.text("v1"))))
        got = [label for label, text in self.seen(b, name_a) if text == self.text("v1")]
        self.ok("legacy v1 envelope is labeled [sender unverified]", got == ["[sender unverified]"], got)
        self.send(c, name_b, "from unregistered")
        got = self.seen(b, name_c)
        self.ok("message from an unregistered name decrypts, flagged unverified",
                len(got) == 1 and "unverified" in got[0][0] and got[0][1] == self.text("from unregistered"), got)

        # broadcast
        self.send(a, "*", "deploy check broadcast, will be deleted")
        got = [m for m in read(c, board) if m["to"] == "*" and self.run in m["rendered"]]
        self.ok("broadcast is plaintext with no label", len(got) == 1 and not got[0]["label"], got)

        # static pages
        with urllib.request.urlopen(board + "/how", timeout=20) as resp:
            how = resp.read().decode()
        self.ok("/how documents signing_key and proof_url", "signing_key" in how and "proof_url" in how)
        self.ok("/how is self-addressing (examples use this board's URL)",
                f"curl {board}/messages" in how and "{{" not in how and "127.0.0.1" not in how)
        with urllib.request.urlopen(board + "/llms.txt", timeout=20) as resp:
            llms = resp.read().decode()
        self.ok("/llms.txt links to this board's /how", f"({board}/how)" in llms and "{{" not in llms)
        with urllib.request.urlopen(board + "/", timeout=20) as resp:
            home = resp.read().decode()
            self.ok("/ serves the web UI", resp.status == 200 and "html" in resp.headers.get("content-type", ""))
        self.ok("/ has a description and canonical link for search engines",
                '<meta name="description"' in home and f'<link rel="canonical" href="{board}/">' in home
                and "{{" not in home)
        with urllib.request.urlopen(board + "/robots.txt", timeout=20) as resp:
            robots = resp.read().decode()
        self.ok("/robots.txt allows crawling and names the sitemap",
                "Allow: /" in robots and f"Sitemap: {board}/sitemap.xml" in robots)
        with urllib.request.urlopen(board + "/sitemap.xml", timeout=20) as resp:
            sitemap = resp.read().decode()
            self.ok("/sitemap.xml is XML listing this board's pages",
                    "xml" in resp.headers.get("content-type", "") and f"<loc>{board}/how</loc>" in sitemap)
        status, stats = self.http("GET", "/stats")
        self.ok("GET /stats returns the counters",
                status == 200 and {"messages_on_board", "total_posted", "total_deleted",
                                   "total_expired", "distinct_agents"} <= set(stats), stats)

    def cleanup(self) -> None:
        for message_id, token in list(self.posted.items()):
            status, _ = self.http("DELETE", f"/messages/{message_id}", headers={"X-Delete-Token": token})
            if status == 200:
                del self.posted[message_id]
        self.ok("cleanup: every message this run posted is deleted", not self.posted, self.posted)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="End-to-end check of a live agentboard")
    parser.add_argument("board", help="board base URL")
    parser.add_argument("--state-dir", help="directory holding the check identities (persistent)")
    parser.add_argument("--prefix", default=None,
                        help="name prefix (default: deploy-check, or a random one without --state-dir)")
    args = parser.parse_args(argv)

    ephemeral = args.state_dir is None
    prefix = args.prefix or (f"deploy-check-{secrets.token_hex(3)}" if ephemeral else "deploy-check")
    state_dir = Path(tempfile.mkdtemp(prefix="agentboard-check-")) if ephemeral else Path(args.state_dir).expanduser()

    check = Check(args.board.rstrip("/"), prefix, state_dir, ephemeral)
    print(f"checking {check.board} as {prefix}-* (run {check.run})\n")
    try:
        check.checks()
    finally:
        check.cleanup()
    passed = sum(check.results)
    print(f"\n{passed}/{len(check.results)} passed")
    return 0 if all(check.results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

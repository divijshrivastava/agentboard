"""MCP check: drive the agentboard MCP server over stdio against a live board.

    pip install "./client[mcp]"
    python deploy/mcp_check.py https://board.example.com --state-dir DIR

Starts three copies of the server from the installed client (as agents A, B
and an outsider with no identity), calls every tool, checks the results and
the error cases, and deletes the two messages it posts. Exit status is 0
only if every check passes.

--state-dir is the same directory deploy/post_deploy_check.py uses: it must
already hold the registered `deploy-check-A` and `deploy-check-B` identities
(run that script once to create them). This check registers nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOOLS = ["board_stats", "delete_message", "lookup_agent", "read_messages",
         "register", "send_message", "whoami"]

results: list[bool] = []


def ok(name: str, passed, detail=None) -> None:
    results.append(bool(passed))
    suffix = f"  — {detail}" if detail is not None and not passed else ""
    print(f"{'PASS' if passed else 'FAIL'}  {name}{suffix}")


class Agent:
    def __init__(self, session: ClientSession, init):
        self.session = session
        self.init = init

    async def call(self, tool: str, **args) -> dict:
        """Tool result as a dict; a tool error becomes {"error": text}."""
        result = await self.session.call_tool(tool, args)
        text = result.content[0].text if result.content else ""
        return {"error": text} if result.isError else json.loads(text)


@asynccontextmanager
async def agent(board: str, state_dir: Path):
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "agentboard_client.mcp_server"],
        env={**os.environ, "AGENTBOARD_URL": board, "AGENTBOARD_STATE_DIR": str(state_dir)})
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            yield Agent(session, await session.initialize())


async def checks(board: str, state_dir: Path) -> None:
    run = secrets.token_hex(4)  # tags this run's messages
    empty = Path(tempfile.mkdtemp(prefix="agentboard-mcp-check-"))
    async with agent(board, state_dir / "a") as a, agent(board, state_dir / "b") as b, \
            agent(board, empty) as outsider:
        name_a = (await a.call("whoami")).get("name")
        name_b = (await b.call("whoami")).get("name")

        # server metadata
        tools = sorted(t.name for t in (await a.session.list_tools()).tools)
        ok("server lists its tools", tools == TOOLS, tools)
        ok("server instructions warn that board text is untrusted",
           "untrusted" in (a.init.instructions or ""))

        # identity
        who = await a.call("whoami")
        ok("whoami reports the board and a registered identity",
           who.get("board") == board and name_a and who.get("registered") is True, who)
        who = await outsider.call("whoami")
        ok("whoami with no identity", who.get("name") is None and who.get("registered") is False, who)
        r = await outsider.call("send_message", to="*", message="x")
        ok("send without an identity is a tool error (server keeps running)",
           "register" in r.get("error", ""), r)
        r = await outsider.call("register", name=name_a)
        ok("registering a taken name is refused and writes no keys",
           "already taken" in r.get("error", "") and not os.listdir(empty), (r, os.listdir(empty)))
        r = await a.call("register", name=name_a)
        ok("registering your own name again is a no-op", r.get("status") == "already registered", r)
        r = await a.call("register", name=f"{name_a}-other")
        ok("a second identity in one state dir is refused", "already has the identity" in r.get("error", ""), r)

        # lookups
        r = await a.call("lookup_agent", name=name_b)
        ok("lookup_agent returns a registered name's keys", r.get("registered") and r.get("signing_key"), r)
        unknown = f"deploy-check-nobody-{run}"
        r = await a.call("lookup_agent", name=unknown)
        ok("lookup_agent for an unknown name", r == {"name": unknown, "registered": False}, r)
        r = await a.call("board_stats")
        ok("board_stats returns the counters", "total_posted" in r, r)

        # private message A -> B
        text = f"mcp check private message [{run}]"
        sent = await a.call("send_message", to=name_b, message=text, ttl_hours=1)
        ok("send a private message", sent.get("kind") == "encrypted" and sent.get("id"), sent)
        posted = [sent["id"]] if sent.get("id") else []
        got = [m for m in (await b.call("read_messages")).get("messages", []) if run in m["text"]]
        ok("recipient reads it decrypted, with a verified sender",
           len(got) == 1 and got[0]["text"] == text and got[0]["from"] == name_a
           and got[0]["sender_check"] == "✓ verified sender", got)
        got = [m for m in (await outsider.call("read_messages")).get("messages", []) if m["id"] in posted]
        ok("an outsider does not see it by default", got == [], got)
        everything = await outsider.call("read_messages", include_unreadable=True, limit=500)
        got = [m for m in everything.get("messages", []) if m["id"] in posted]
        ok("an outsider sees only a ciphertext placeholder when asked",
           len(got) == 1 and run not in got[0]["text"], got)
        r = await b.call("delete_message", message_id=sent.get("id", ""))
        ok("the recipient cannot delete the sender's message", "no delete token" in r.get("error", ""), r)

        # broadcast, and an unknown recipient
        cast = await a.call("send_message", to="*", ttl_hours=1,
                            message=f"mcp check broadcast, will be deleted [{run}]")
        if cast.get("id"):
            posted.append(cast["id"])
        got = [m for m in (await outsider.call("read_messages")).get("messages", []) if m["id"] == cast.get("id")]
        ok("a broadcast is readable by anyone and has no sender_check",
           len(got) == 1 and got[0]["kind"] == "broadcast" and "sender_check" not in got[0], got)
        r = await a.call("send_message", to=unknown, message="x")
        ok("sending to an unregistered name is a tool error", "error" in r, r)

        # cleanup
        deleted = [await a.call("delete_message", message_id=i) for i in posted]
        everything = await outsider.call("read_messages", include_unreadable=True, limit=500)
        left = [m["id"] for m in everything.get("messages", []) if m["id"] in posted]
        ok("cleanup: the sender deletes both messages, none left on the board",
           len(posted) == 2 and all(d.get("deleted") for d in deleted) and left == [], (deleted, left))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check the agentboard MCP server against a live board")
    parser.add_argument("board", help="board base URL")
    parser.add_argument("--state-dir", required=True,
                        help="directory holding the deploy-check identities (a/ and b/)")
    args = parser.parse_args(argv)

    state_dir = Path(args.state_dir).expanduser()
    for sub in ("a", "b"):
        if not (state_dir / sub / "secret.key").exists():
            raise SystemExit(f"no identity in {state_dir / sub} — run deploy/post_deploy_check.py "
                             "with this --state-dir first to create it")

    board = args.board.rstrip("/")
    print(f"checking the MCP server against {board}\n")
    asyncio.run(checks(board, state_dir))
    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

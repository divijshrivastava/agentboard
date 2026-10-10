from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


def post(client, content="hello", frm="alice", to="*", **extra):
    body = {"from": frm, "to": to, "content": content, **extra}
    return client.post("/messages", json=body)


# ---------------- key registration ----------------


def test_register_and_fetch_key(client):
    r = client.post("/keys", json={"name": "alice", "public_key": "pk-alice"})
    assert r.status_code == 201
    assert r.json()["name"] == "alice"
    assert r.json()["public_key"] == "pk-alice"

    r = client.get("/keys/alice")
    assert r.status_code == 200
    assert r.json()["public_key"] == "pk-alice"


def test_register_duplicate_name_conflicts(client):
    assert client.post("/keys", json={"name": "alice", "public_key": "a"}).status_code == 201
    r = client.post("/keys", json={"name": "alice", "public_key": "b"})
    assert r.status_code == 409
    # The original key is not overwritten.
    assert client.get("/keys/alice").json()["public_key"] == "a"


@pytest.mark.parametrize("name", ["has space", "semi;colon", "dot.name", "x" * 65, ""])
def test_register_rejects_bad_names(client, name):
    r = client.post("/keys", json={"name": name, "public_key": "pk"})
    assert r.status_code == 422


def test_register_rejects_oversized_public_key(client):
    r = client.post("/keys", json={"name": "alice", "public_key": "k" * 257})
    assert r.status_code == 422


def test_get_unknown_key_404(client):
    assert client.get("/keys/nobody").status_code == 404


# ---------------- posting ----------------


def test_post_message_returns_id_token_and_expiry(client, clock):
    r = post(client)
    assert r.status_code == 201
    body = r.json()
    assert body["id"]
    assert body["delete_token"]
    assert body["expires_at"] == pytest.approx(clock.now + 168 * 3600)


def test_post_custom_ttl(client, clock):
    r = post(client, ttl_hours=2)
    assert r.json()["expires_at"] == pytest.approx(clock.now + 2 * 3600)


@pytest.mark.parametrize("ttl", [-1, 169])
def test_post_rejects_ttl_out_of_range(client, ttl):
    assert post(client, ttl_hours=ttl).status_code == 422


def test_post_content_size_cap_is_in_utf8_bytes(client):
    assert post(client, content="a" * 4096).status_code == 201
    assert post(client, content="a" * 4097).status_code == 413
    # 1366 three-byte characters = 4098 bytes, though only 1366 chars.
    assert post(client, content="€" * 1366).status_code == 413


def test_post_requires_from(client):
    r = client.post("/messages", json={"content": "hi"})
    assert r.status_code == 422


# ---------------- listing ----------------


def test_list_returns_newest_first_without_delete_token(client, clock):
    post(client, content="first")
    clock.advance(1)
    post(client, content="second")

    msgs = client.get("/messages").json()["messages"]
    assert [m["content"] for m in msgs] == ["second", "first"]
    assert set(msgs[0]) == {"id", "from", "to", "content", "created_at", "expires_at"}


def test_list_filter_by_recipient_includes_broadcasts(client):
    post(client, content="broadcast", to="*")
    post(client, content="for bob", to="bob")
    post(client, content="for carol", to="carol")

    for_bob = {m["content"] for m in client.get("/messages", params={"to": "bob"}).json()["messages"]}
    assert for_bob == {"broadcast", "for bob"}

    only_broadcasts = client.get("/messages", params={"to": "*"}).json()["messages"]
    assert [m["content"] for m in only_broadcasts] == ["broadcast"]


def test_list_since_filter(client, clock):
    post(client, content="old")
    cutoff = clock.now
    clock.advance(5)
    post(client, content="new")

    msgs = client.get("/messages", params={"since": cutoff}).json()["messages"]
    assert [m["content"] for m in msgs] == ["new"]


def test_list_is_capped_at_page_limit(client, server, monkeypatch):
    monkeypatch.setattr(server, "PAGE_LIMIT", 3)
    for i in range(5):
        post(client, content=str(i))
    assert len(client.get("/messages").json()["messages"]) == 3


# ---------------- deleting ----------------


def test_delete_with_token(client):
    created = post(client).json()
    r = client.delete(f"/messages/{created['id']}", headers={"X-Delete-Token": created["delete_token"]})
    assert r.status_code == 200
    assert r.json() == {"deleted": created["id"]}
    assert client.get("/messages").json()["messages"] == []


def test_delete_with_wrong_or_missing_token_forbidden(client):
    created = post(client).json()
    assert client.delete(f"/messages/{created['id']}").status_code == 403
    r = client.delete(f"/messages/{created['id']}", headers={"X-Delete-Token": "wrong"})
    assert r.status_code == 403
    assert len(client.get("/messages").json()["messages"]) == 1


def test_delete_unknown_message_404(client):
    r = client.delete("/messages/nope", headers={"X-Delete-Token": "x"})
    assert r.status_code == 404


# ---------------- expiry ----------------


def test_messages_expire_after_seven_days_by_default(client, clock):
    post(client, content="ephemeral")
    clock.advance(168 * 3600 - 1)
    assert len(client.get("/messages").json()["messages"]) == 1

    clock.advance(1)
    assert client.get("/messages").json()["messages"] == []


def test_custom_ttl_expires_early(client, clock):
    post(client, content="short", ttl_hours=1)
    post(client, content="long")
    clock.advance(3600)
    msgs = client.get("/messages").json()["messages"]
    assert [m["content"] for m in msgs] == ["long"]


def test_zero_ttl_is_expired_immediately(client):
    post(client, ttl_hours=0)
    assert client.get("/messages").json()["messages"] == []


def test_expired_message_cannot_be_deleted(client, clock):
    created = post(client, ttl_hours=1).json()
    clock.advance(3600)
    client.get("/messages")  # triggers the lazy purge
    r = client.delete(f"/messages/{created['id']}", headers={"X-Delete-Token": created["delete_token"]})
    assert r.status_code == 404


# ---------------- rate limiting ----------------


def test_rate_limit_on_posts(client):
    for i in range(30):
        assert post(client, content=str(i)).status_code == 201
    r = post(client, content="one too many")
    assert r.status_code == 429
    assert "rate limit" in r.json()["detail"]


def test_rate_limit_shared_between_keys_and_messages(client):
    for i in range(30):
        assert client.post("/keys", json={"name": f"agent{i}", "public_key": "pk"}).status_code == 201
    assert post(client).status_code == 429


def test_rate_limit_window_slides(client, clock):
    for i in range(30):
        post(client, content=str(i))
    assert post(client).status_code == 429
    clock.advance(61)
    assert post(client).status_code == 201


def test_reads_are_not_rate_limited(client):
    for i in range(30):
        post(client, content=str(i))
    for _ in range(5):
        assert client.get("/messages").status_code == 200
        assert client.get("/stats").status_code == 200


# ---------------- /stats ----------------


def test_stats_empty_board(client):
    assert client.get("/stats").json() == {
        "messages_on_board": 0,
        "total_posted": 0,
        "total_deleted": 0,
        "total_expired": 0,
        "distinct_agents": 0,
    }


def test_stats_track_posts_deletes_expiry_and_agents(client, clock):
    a = post(client, frm="alice").json()
    post(client, frm="alice")
    post(client, frm="bob", ttl_hours=1)
    post(client, frm="carol")

    client.delete(f"/messages/{a['id']}", headers={"X-Delete-Token": a["delete_token"]})
    clock.advance(3600)
    client.get("/messages")  # purges bob's message

    assert client.get("/stats").json() == {
        "messages_on_board": 2,
        "total_posted": 4,
        "total_deleted": 1,
        "total_expired": 1,
        "distinct_agents": 3,
    }


def test_failed_delete_does_not_count(client):
    created = post(client).json()
    client.delete(f"/messages/{created['id']}", headers={"X-Delete-Token": "wrong"})
    assert client.get("/stats").json()["total_deleted"] == 0


def test_stats_persist_across_restart(server):
    with TestClient(server.app) as c:
        post(c, frm="alice")
        post(c, frm="bob")

    # Re-importing the module against the same database simulates a restart.
    server._db.close()
    sys.modules.pop("main", None)
    restarted = importlib.import_module("main")
    with TestClient(restarted.app) as c:
        stats = c.get("/stats").json()
    restarted._db.close()
    assert stats["total_posted"] == 2
    assert stats["distinct_agents"] == 2


# ---------------- static pages ----------------


def test_index_and_how_pages(client):
    assert client.get("/").status_code == 200
    r = client.get("/how")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")

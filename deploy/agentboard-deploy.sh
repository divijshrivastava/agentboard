#!/bin/bash
# agentboard deploy script — installed on the server as
# /usr/local/bin/agentboard-deploy (root-owned) and wired up as the SSH
# *forced command* for the CI deploy key, i.e. in ~/.ssh/authorized_keys:
#
#   command="/usr/local/bin/agentboard-deploy",restrict ssh-ed25519 AAAA... github-actions-agentboard-deploy
#
# The key can therefore do exactly one thing: deploy the current tip of
# main from GitHub. It takes no input from the caller (whatever command the
# client sends is ignored), so a leaked key cannot run arbitrary commands
# or deploy arbitrary code.
#
# Layout it maintains (see agentboard.service):
#   /opt/agentboard/app   server/, requirements.txt, README.md, REVISION
#   /opt/agentboard/venv  virtualenv running uvicorn
set -euo pipefail

REPO=divijshrivastava/agentboard
BRANCH=main
APP=/opt/agentboard/app
VENV=/opt/agentboard/venv
SERVICE=agentboard
HEALTH_URL=http://127.0.0.1:8000/stats

exec 9>/tmp/agentboard-deploy.lock
flock -w 300 9 || { echo "another deploy is still running" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Ask the git endpoint (what `git ls-remote` reads) rather than the REST API,
# which can still report the previous tip for a few seconds after a push.
sha=$(curl -fsSL --retry 3 "https://github.com/$REPO.git/info/refs?service=git-upload-pack" \
	| sed -n "s|^[0-9a-f]\{4\}\([0-9a-f]\{40\}\) refs/heads/$BRANCH\$|\1|p")
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo "could not resolve $BRANCH: $sha" >&2; exit 1; }
rev=${sha:0:7}

if [[ $(cat "$APP/REVISION" 2>/dev/null) == "$rev" ]]; then
	echo "already at $rev, nothing to do"
	exit 0
fi

echo "deploying $REPO@$rev (was $(cat "$APP/REVISION" 2>/dev/null || echo unknown))"
curl -fsSL --retry 3 "https://github.com/$REPO/archive/$sha.tar.gz" \
	| tar -xz -C "$work" --strip-components=1
echo "$rev" > "$work/REVISION"

healthy() {
	for _ in $(seq 1 20); do
		curl -fsS -o /dev/null "$HEALTH_URL" && return 0
		sleep 1
	done
	return 1
}

sync_app() {	# $1 = source tree
	sudo rsync -rlt --delete --chown=root:root --chmod=D755,F644 "$1/server/" "$APP/server/"
	sudo install -o root -g root -m 644 "$1/requirements.txt" "$1/README.md" "$1/REVISION" "$APP/"
}

# Keep the running tree so a release that fails its health check can be undone.
mkdir "$work/prev"
cp -a "$APP/." "$work/prev/"

sync_app "$work"
sudo "$VENV/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
sudo systemctl restart "$SERVICE"

if healthy; then
	echo "deployed $rev"
	exit 0
fi

echo "health check failed for $rev, rolling back" >&2
sudo journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
sync_app "$work/prev"
sudo systemctl restart "$SERVICE"
healthy && echo "rolled back to $(cat "$APP/REVISION")" >&2 \
	|| echo "ROLLBACK ALSO UNHEALTHY — service needs attention" >&2
exit 1

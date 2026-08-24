#!/bin/sh
set -eu

# Copy the two narrowly mounted credentials while privileged, then permanently
# drop to appuser before Supervisor or any application code starts.
install -d -m 0700 -o appuser -g appuser /home/appuser/.ssh /home/appuser/.docker
install -m 0400 -o appuser -g appuser \
    /run/secrets/monitoring_ssh_key /home/appuser/.ssh/id_ed25519
install -m 0400 -o appuser -g appuser \
    /run/secrets/docker_config.json /home/appuser/.docker/config.json

exec gosu appuser "$@"

# SPDX-License-Identifier: AGPL-3.0-or-later
# Source preparation only. Building/running requires the bounded runtime approval.
# Fixed linux/amd64 Debian bookworm-slim manifest, observed 2026-10-01.
FROM --platform=linux/amd64 docker.io/library/debian@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b

ARG SOURCE_DATE_EPOCH=1790564896
# No package download, credential copy, service, VOLUME or workspace bind.
# Debian's Bash/coreutils supply the foreground command and inert canonical sleep.
# Keep OCI WorkingDir at /sandbox. Pinned OpenShell rejects a tmpfs that covers
# that directory, so execution uses the owned child mount /sandbox/work.
RUN set -eu; \
    test -x /bin/bash; test -x /bin/sleep; test -x /usr/bin/env; test -x /usr/bin/sha256sum; \
    test -x /usr/bin/id; test -x /bin/pwd; test -x /usr/bin/printf; \
    ! getent passwd 1000; ! getent group 1000; \
    printf 'sandbox:x:1000:1000::/sandbox:/bin/bash\n' >> /etc/passwd; \
    printf 'sandbox:x:1000:\n' >> /etc/group; \
    install -d -m 0700 -o 1000 -g 1000 /sandbox /sandbox/work /sandbox/.dsh; \
    install -d -m 1777 -o 0 -g 0 /tmp

ENV HOME=/sandbox
WORKDIR /sandbox
USER 1000:1000
ENTRYPOINT ["/bin/bash"]
CMD ["-c", "exit 0"]

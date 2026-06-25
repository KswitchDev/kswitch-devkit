# syntax=docker/dockerfile:1.7

ARG SPIRE_VERSION=1.10.0
FROM ghcr.io/spiffe/spire-server:${SPIRE_VERSION} AS server-binary
FROM ghcr.io/spiffe/spire-agent:${SPIRE_VERSION} AS agent-binary

FROM alpine:3.20@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d AS runtime

RUN apk add --no-cache bash

COPY --from=server-binary /opt/spire/bin/spire-server /opt/spire/bin/spire-server
COPY --from=agent-binary  /opt/spire/bin/spire-agent  /opt/spire/bin/spire-agent
COPY devkit/images/spire-agent-wrapper/entrypoint.sh /usr/local/bin/spire-agent-entrypoint.sh

RUN chmod 0555 /usr/local/bin/spire-agent-entrypoint.sh \
    && chmod 0555 /opt/spire/bin/spire-server /opt/spire/bin/spire-agent

ENTRYPOINT ["/usr/local/bin/spire-agent-entrypoint.sh"]

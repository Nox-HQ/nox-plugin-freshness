# Base image pinned by digest so a rebuild cannot silently pick up a different
# toolchain. Bump the tag and digest together.
#
# A nox:ignore directive must sit on the line IMMEDIATELY above the finding it
# waives — prose may precede the directive, but not separate it from its target.
# nox:ignore IAC-121 -- HEALTHCHECK needs a binary to poll; the runtime stage is scratch, holding one static plugin and no shell.
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src
# nox:ignore IAC-123 -- build stage; the layer is discarded, and chowning the sources away from root would break the compile that follows.
COPY go.mod go.sum ./
RUN go mod download
# nox:ignore IAC-123 -- build stage; as above.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /plugin .

# nox:ignore IAC-002 -- scratch is the empty image; there is no digest to pin.
FROM scratch

# Maintainer as a profile URL, not an email: this label ships inside a public
# image, and a personal address there is PII in a published artifact.
LABEL maintainer="https://github.com/felixgeelhaar" \
      org.opencontainers.image.title="nox-plugin-freshness" \
      org.opencontainers.image.description="Flags dependencies by suspicious provenance rather than by published advisory" \
      org.opencontainers.image.source="https://github.com/nox-hq/nox-plugin-freshness" \
      org.opencontainers.image.licenses="Apache-2.0"

# Owned by, and run as, an unprivileged uid. A scratch image has no
# /etc/passwd, so the numeric form is required — but numeric works, which is
# why running as root here was a real gap rather than an unavoidable one.
COPY --from=build --chown=65532:65532 /plugin /plugin
USER 65532:65532

ENTRYPOINT ["/plugin"]

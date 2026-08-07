# Base image pinned by digest so a rebuild cannot silently pick up a different
# toolchain. Bump the tag and digest together.
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /plugin .

FROM scratch

# Maintainer as a profile URL, not an email: this label ships inside a public
# image, and a personal address there is PII in a published artifact.
LABEL maintainer="https://github.com/felixgeelhaar" \
      org.opencontainers.image.title="nox-plugin-freshness" \
      org.opencontainers.image.description="Flags dependencies by suspicious provenance rather than by published advisory" \
      org.opencontainers.image.source="https://github.com/felixgeelhaar/nox-plugin-freshness" \
      org.opencontainers.image.licenses="Apache-2.0"

# Owned by, and run as, an unprivileged uid. A scratch image has no
# /etc/passwd, so the numeric form is required — but numeric works, which is
# why running as root here was a real gap rather than an unavoidable one.
COPY --from=build --chown=65532:65532 /plugin /plugin
USER 65532:65532

ENTRYPOINT ["/plugin"]

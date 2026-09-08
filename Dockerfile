# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Multi-stage build:
#   1) compile a static, CGO-free binary in a full Go toolchain image;
#   2) copy it into a minimal Alpine image that runs as an unprivileged user.
# ---------------------------------------------------------------------------
FROM golang:1.26-alpine AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64
ARG APP=server
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/app ./cmd/${APP}

FROM alpine:3.20
# ca-certificates for potential HTTPS outbound; dedicated non-root uid/gid.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10001 app \
 && adduser -S -u 10001 -G app -H app
COPY --from=build /out/app /usr/local/bin/app
# Default rule set baked as a fallback so the image works standalone; compose
# mounts rules/rules.json over this path to keep rules editable without a
# rebuild (rules are data, decoupled from code).
COPY rules/rules.json /rules/rules.json
USER 10001:10001
ENTRYPOINT ["app"]

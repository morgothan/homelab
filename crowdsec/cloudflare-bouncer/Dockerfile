FROM golang:1.26-alpine AS build
RUN apk add --no-cache curl python3
WORKDIR /src
RUN curl -fsSL https://codeload.github.com/crowdsecurity/cs-cloudflare-bouncer/tar.gz/e89a390f3284432de730f7799d5082f385b5e1c7 -o /tmp/source.tar.gz \
 && echo '44f1593ee8edbcd7dc25e2aaa8455ee6202598b8b13ca0c5f357226f6da17523  /tmp/source.tar.gz' | sha256sum -c - \
 && tar -xzf /tmp/source.tar.gz --strip-components=1 -C /src
COPY patch.py /tmp/patch.py
RUN python3 /tmp/patch.py
COPY rulesets*.go pkg/cf/
RUN gofmt -w pkg/cf/rulesets*.go pkg/cf/cloudflare.go \
 && API_KEY=test CF_ACC_ID=test CF_ZONE_ID=test CF_TOKEN=test go test ./pkg/... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/crowdsecurity/go-cs-lib/version.Version=v0.3.0-rulesets.1" -o /bouncer .
FROM alpine:3.24.1
RUN apk add --no-cache ca-certificates
COPY --from=build /bouncer /usr/local/bin/crowdsec-cloudflare-bouncer
ENTRYPOINT ["/usr/local/bin/crowdsec-cloudflare-bouncer", "-c", "/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml"]

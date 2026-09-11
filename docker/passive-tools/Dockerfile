# passive-tools: locally built image for the Go passive tools (REM6 pattern;
# REM13 naming fix after run #18: tomnomnom/hacks and puredns/puredns do NOT
# exist on Docker Hub - "pull access denied ... repository does not exist").
#
# Pinned in tools.lock as moirax-asm/passive-tools:v1 (empty digest):
#   gau         github.com/lc/gau/v2/cmd/gau   (package lives under cmd/gau)
#   puredns     github.com/d3mondev/puredns/v2 (main package at module root)
#   assetfinder github.com/tomnomnom/hacks/assetfinder (no go.mod in repo ->
#               clone + minimal go.mod + build; stdlib-only package)
#   waybackurls github.com/tomnomnom/waybackurls (same no-go.mod treatment)
FROM golang:1.23-alpine AS build
RUN apk add --no-cache git
RUN go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/d3mondev/puredns/v2@latest
# puredns v2 shells out to massdns (run #25: 'exec: massdns not found in
# $PATH' -> primary always failed, fallback served the contract); build the
# pinned massdns from source so the spec-named puredns path works natively.
RUN apk add --no-cache build-base \
 && git clone --depth 1 https://github.com/blechschmidt/massdns /src/massdns \
 && make -C /src/massdns \
 && mkdir -p /out \
 && cp /src/massdns/bin/massdns /out/massdns
RUN mkdir -p /out \
 && cp /go/bin/gau /out/gau \
 && cp /go/bin/puredns /out/puredns
RUN git clone --depth 1 https://github.com/tomnomnom/hacks /src/hacks \
 && cd /src/hacks/assetfinder \
 && { test -f go.mod || go mod init assetfinder; } \
 && go build -trimpath -o /out/assetfinder . \
 && git clone --depth 1 https://github.com/tomnomnom/waybackurls /src/waybackurls \
 && cd /src/waybackurls \
 && { test -f go.mod || go mod init waybackurls; } \
 && go build -trimpath -o /out/waybackurls .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/gau /usr/local/bin/gau
COPY --from=build /out/puredns /usr/local/bin/puredns
COPY --from=build /out/massdns /usr/local/bin/massdns
COPY --from=build /out/assetfinder /usr/local/bin/assetfinder
COPY --from=build /out/waybackurls /usr/local/bin/waybackurls
ENTRYPOINT ["gau"]

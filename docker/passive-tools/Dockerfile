# passive-tools: locally built image for the gau archive harvester (PSV-4).
# REM6 pattern (same as docker/ffuf): the runner has no preinstalled recon
# images; locally built images are pinned in tools.lock as
# recon-pipeline/passive-tools:v1 with an empty digest (local build).
# gau v2 has a go.mod (installable via `go install ...@latest`); the tomnomnom
# hacks tools (assetfinder, waybackurls) come from their documented Docker Hub
# per-tool images (tomnomnom/hacks:<tool>).
FROM golang:1.23-alpine AS build
RUN go install github.com/lc/gau/v2@latest

FROM alpine:3.20
COPY --from=build /go/bin/gau /usr/local/bin/gau
ENTRYPOINT ["gau"]

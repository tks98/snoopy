# For GoReleaser, which builds the image from the binaries it built
# (.goreleaser.yaml, dockers_v2); `docker build .` here has no binary to copy.
# snoopy is static and needs nothing else: run it with --privileged
# --pid=host (docs/usage.md, "Containers and Kubernetes").
FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/snoopy /usr/bin/snoopy
ENTRYPOINT ["/usr/bin/snoopy"]

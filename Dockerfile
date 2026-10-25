# For GoReleaser, which builds the image from the binaries it built
# (.goreleaser.yaml, dockers_v2); `docker build .` here has no binary to copy.
# snoopy is static and needs nothing else (but its Java agent's jars, which
# are platform-independent): run it with --privileged
# --pid=host (docs/usage.md, "Containers and Kubernetes").
FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/snoopy /usr/bin/snoopy
# The Java agent (--java), where snoopy looks for it: ../share/snoopy/java.
COPY java/out/snoopy-agent.jar java/out/snoopy-hooks.jar /usr/share/snoopy/java/
ENTRYPOINT ["/usr/bin/snoopy"]

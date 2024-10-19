# Use a multi-arch base image
FROM --platform=$BUILDPLATFORM ubuntu:22.04

# Install essential packages and kernel headers
RUN apt-get update && apt-get install -y \
    bison \
    build-essential \
    cmake \
    flex \
    git \
    libedit-dev \
    libllvm14 \
    llvm-14-dev \
    libclang-14-dev \
    python3 \
    zlib1g-dev \
    libelf-dev \
    libfl-dev \
    python3-setuptools \
    liblzma-dev \
    libdebuginfod-dev \
    arping \
    netperf \
    iperf \
    wget \
    curl \
    kmod \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install Go (architecture-independent method)
RUN curl -L https://go.dev/dl/go1.20.5.linux-$(dpkg --print-architecture).tar.gz | tar -C /usr/local -xzf -

# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install BCC
RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    libbpfcc \
    libbpfcc-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up kernel headers
RUN apt-get update && apt-get install -y linux-headers-$(uname -r) \
    && ln -s /usr/src/linux-headers-$(uname -r) /lib/modules/$(uname -r)/build \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Build the Go application
RUN go build -o snoopy

# Command to run the executable
CMD ["./snoopy"]

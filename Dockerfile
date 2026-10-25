# syntax=docker/dockerfile:1.7
# =============================================================================
# Layered Multi-Stage Build for ASUS RT-BE92U (Broadcom BCM6765 - linux/arm64)
# =============================================================================
# Usage (with QEMU binfmt registered):
#   docker buildx build --platform linux/arm64 --target export --output type=local,dest=./dist .
#   docker buildx build --platform linux/arm64 --target test .
# =============================================================================

# -----------------------------------------------------------------------------
# Layer 1: Base Toolchain (Cached permanently unless Alpine version bumps)
# -----------------------------------------------------------------------------
FROM --platform=linux/arm64 alpine:3.20 AS base-toolchain

RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    pkgconfig \
    linux-headers \
    file \
    git

WORKDIR /workspace

# -----------------------------------------------------------------------------
# Layer 2: OTel Embedded Core Library Build
# Pre-compiles libotel_embedded_core.a so collector iterations in Layer 3 never
# recompile OTel wire encoding, batching, HTTP sender, or subprocess runner.
# -----------------------------------------------------------------------------
FROM base-toolchain AS build-otel-layer

COPY CMakeLists.txt /workspace/
COPY include/otel/ /workspace/include/otel/
COPY include/platform/ /workspace/include/platform/
COPY include/Config.h /workspace/include/Config.h
COPY src/Config.cpp /workspace/src/Config.cpp
COPY src/otel/ /workspace/src/otel/
COPY src/platform/ /workspace/src/platform/

RUN cmake -B /workspace/build -G Ninja \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DMOTEL_BUILD_STATIC=ON \
      -DMOTEL_BUILD_COLLECTORS=OFF && \
    cmake --build /workspace/build --target otel_embedded_core --parallel

# -----------------------------------------------------------------------------
# Layer 3: Collector & Daemon Incremental Build
# Only recompiles src/collectors/* and links the static aarch64 binary.
# -----------------------------------------------------------------------------
FROM build-otel-layer AS builder

COPY include/collectors/ /workspace/include/collectors/
COPY src/collectors/ /workspace/src/collectors/
COPY src/main.cpp /workspace/src/main.cpp
COPY tests/ /workspace/tests/

RUN cmake -B /workspace/build -G Ninja \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DMOTEL_BUILD_STATIC=ON \
      -DMOTEL_BUILD_COLLECTORS=ON \
      -DMOTEL_BUILD_TESTS=ON && \
    cmake --build /workspace/build --parallel && \
    strip --strip-all /workspace/build/merlin-otel-agent && \
    ls -lh /workspace/build/merlin-otel-agent && \
    file /workspace/build/merlin-otel-agent

# -----------------------------------------------------------------------------
# Layer 4a: QEMU Verification Stage (Runs unit tests inside linux/arm64 container)
# -----------------------------------------------------------------------------
FROM builder AS test

WORKDIR /workspace/build
RUN ctest --output-on-failure -V

# -----------------------------------------------------------------------------
# Layer 4b: Artifact Export Stage (Extracts static binary + config scripts)
# -----------------------------------------------------------------------------
FROM scratch AS export

COPY --from=builder /workspace/build/merlin-otel-agent /merlin-otel-agent
COPY config/motel.conf.example /motel.conf.example
COPY config/services-start /services-start

# -----------------------------------------------------------------------------
# Layer 5: Static Code Security Analysis (cppcheck, clang-tidy, flawfinder)
# Analyzes codebase against CERT C++ standards, CWE vulnerabilities & bounds
# Usage:
#   docker buildx build --target security-scan .
# -----------------------------------------------------------------------------
FROM builder AS security-scan

RUN apk add --no-cache \
    cppcheck \
    clang-extra-tools \
    flawfinder

WORKDIR /workspace

# 1. Cppcheck: memory leaks, out-of-bounds, uninitialized vars, null pointers
RUN echo "=== [1/3] Running cppcheck ===" && \
    cppcheck --enable=warning,portability,performance \
             --std=c++17 \
             --suppress=normalCheckLevelMaxBranches \
             --suppress=missingIncludeSystem \
             --suppress=functionStatic \
             --suppress=uselessOverride \
             --suppress=functionConst \
             --inline-suppr \
             --error-exitcode=1 \
             -I include/ src/

# 2. Clang-Tidy: CERT C++ rules, bugprone checks, and Clang security analyzer
RUN echo "=== [2/3] Running clang-tidy ===" && \
    run-clang-tidy -p build/ \
      -checks='-*,clang-analyzer-security.*,bugprone-use-after-move,bugprone-dangling-handle,cert-msc*' \
      -quiet \
      'src/.*\.cpp'

# 3. Flawfinder: CWE vulnerability scan (shell injection, buffer safety)
RUN echo "=== [3/3] Running flawfinder ===" && \
    flawfinder --minlevel=2 --error-level=4 src/ include/

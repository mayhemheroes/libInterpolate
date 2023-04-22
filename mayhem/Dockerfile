# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake git libomp-dev libboost-all-dev libeigen3-dev

## Add source code to the build stage.
ADD . /src

## Build
WORKDIR /src/build
RUN cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF -DBUILD_FUZZER=ON .. && make -j$(nproc)

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /src/build/mayhem/fuzz_interpolate /fuzz_interpolate

# Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_interpolate

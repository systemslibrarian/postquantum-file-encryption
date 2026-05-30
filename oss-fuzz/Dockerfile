# OSS-Fuzz build image for the Rust .pqfe parser fuzz target.
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/systemslibrarian/postquantum-file-encryption \
    $SRC/postquantum-file-encryption

WORKDIR $SRC/postquantum-file-encryption/samples/pqfe-wasm
COPY build.sh $SRC/

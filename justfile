setup:
    git submodule update --init --recursive
    go env -w GO111MODULE=on
    cd gnark-circuit-gen && go mod download
    cd demo && cargo check

build-gnark:
    cd gnark-circuit-gen && go build ./main.go

test: build-gnark
    cd demo && cargo test --release
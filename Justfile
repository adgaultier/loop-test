set export

# List available targets
default:
    just --list


build-ebpf:
    cd loop-ebpf && RUST_BACKTRACE=1 cargo +nightly build   --release

build:
    just build-ebpf
    cargo build --release

run:
    RUST_LOG=info sudo -E target/release/loop

test:
    sudo bpftool prog show id 2  >/dev/null 2>&1
set export

# List available targets
default:
    just --list


build-ebpf:
    cd loop-ebpf && RUST_BACKTRACE=1 cargo +nightly build   --release

run:
    just build-ebpf
    RUST_BACKTRACE=1 RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E" ' -- 

test:
    sudo bpftool prog show id 2
# loop in bpf debug 

## Problem
random behavior when doing 500 iterations , loops finish randomly
- `just run` to build
- `just test` to trigger a test

### branches
- bpf_loop: bpf_loop impl
- bpf_tail_jump: loop with batches of 10its

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_cmd,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

struct LoopContext<'a> {
    ctx: &'a TracePointContext,
    global_idx: u32,
}
#[map]
static MMAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(32, 0); //used for batching with bpf_tail_call
#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(1, 0);

unsafe fn loop_body(loop_ctx: &mut LoopContext) -> i64 {
    info!(loop_ctx.ctx, "in loop {}", loop_ctx.global_idx);
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    loop_ctx.global_idx += 1;
    let ret = MMAP.insert(&caller_pid, &loop_ctx.global_idx, 0);
    if let Err(_) = ret {
        return -1;
    }
    0
}

#[tracepoint]
pub fn _loop(ctx: TracePointContext) -> u32 {
    match try_loop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_loop(ctx: TracePointContext) -> Result<u32, u32> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 0u32)? };

    if cmd == bpf_cmd::BPF_PROG_GET_FD_BY_ID {
        info!(&ctx, "------tracepoint  called------");
        let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let global_idx = match unsafe { MMAP.get(&caller_pid) } {
            Some(v) => *v,
            _ => 0,
        };

        let mut loop_ctx = LoopContext {
            ctx: &ctx,
            global_idx: global_idx,
        };

        for _ in 0..10 {
            if unsafe { loop_body(&mut loop_ctx) } == -1 {
                info!(&ctx, "error in loop");
                return Ok(0);
            } else {
                let global_idx = match unsafe { MMAP.get(&caller_pid) } {
                    Some(v) => *v,
                    _ => 0,
                };
                info!(
                    &ctx,
                    "loop next idx: {} (= {})", loop_ctx.global_idx, global_idx
                );
            }
        }

        info!(&ctx, "out of loop");

        if global_idx < 500 {
            if let Err(_) = unsafe { JUMP_TABLE.tail_call(loop_ctx.ctx, 0) } {
                info!(&ctx, "error in jmp");
                return Ok(0);
            }
        }
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

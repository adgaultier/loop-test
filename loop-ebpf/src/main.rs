#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_cmd, cty::c_void, helpers::bpf_loop, macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

struct LoopContext<'a> {
    ctx: &'a TracePointContext,
}

const MAX_ITER: u32 = 500u32;
unsafe fn loop_body(index: u64, data: *mut c_void) -> i64 {
    if index >= MAX_ITER.into() {
        return 1;
    }
    info!((*(data as *mut LoopContext)).ctx, "{}", index);
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
        let mut loop_ctx = LoopContext { ctx: &ctx };
        let fn_ptr = loop_body as *mut fn(u64, *mut c_void) -> i64 as *mut c_void;
        let ctx_ptr = &mut loop_ctx as *mut LoopContext as *mut c_void;
        unsafe { bpf_loop(MAX_ITER, fn_ptr, ctx_ptr, 0) };
        info!(&ctx, "out of loop");
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

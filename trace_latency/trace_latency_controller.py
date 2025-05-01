from . import trace_latency_userspace

async def load_ebpf_program(ifname):
    return await trace_latency_userspace.load_ebpf_program(ifname)

async def unload_ebpf_program(ifname):
    await trace_latency_userspace.unload_ebpf_program(ifname)
from . import loadbalancer_userspace

async def load_ebpf_program(upfs_config,ifname):
    await loadbalancer_userspace.load_ebpf_program(upfs_config, ifname)

async def unload_ebpf_program(ifname):
    await loadbalancer_userspace.unload_ebpf_program(ifname)
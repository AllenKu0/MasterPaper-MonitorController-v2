import time
import ctypes
import socket
import struct
from pyroute2 import NetlinkError
from bcc import BPF
from pyroute2 import IPRoute, AsyncIPRoute

# upf_configs = [
#     {
#         "ip": "10.244.0.162",
#         "mac": "8e:87:b7:f8:9c:67"
#     },
#     {
#         "ip": "10.245.0.250",
#         "mac": "ca:6a:e7:38:e2:a7"
#     }
# ]

# gnb 網卡
# IFNAME = "lxc7d088855cc6d"
def mac_str_to_ubyte_array(mac_str):
    return (ctypes.c_ubyte * 6)(*map(lambda x: int(x, 16), mac_str.split(':')))

def ip_str_to_u32(ip_str):
    ip_packed = socket.inet_aton(ip_str)
    # 解包並保留大端字節序的整數值
    return struct.unpack("<I", ip_packed)[0]
# 鏡像map init
class LoadBalancerConfig(ctypes.Structure):
    _fields_ = [
        ("ip", ctypes.c_uint),
        ("mac", ctypes.c_ubyte * 6),
    ]
    
async def load_ebpf_program(upfs_config, IFNAME):
    async with AsyncIPRoute() as ipr:
        # 載入 BPF C 程式
        b = BPF(src_file="loadbalancer/loadbalancer_kernalspace.c")
        fn_loadbalancer = b.load_func("loadbalancer", BPF.SCHED_CLS)
        idx_list = await ipr.link_lookup(ifname=IFNAME)

        if not idx_list:
            raise Exception(f"Interface {IFNAME} not found.")
        idx = idx_list[0]
        
        try:
            await ipr.tc("add", "clsact", idx)
        except NetlinkError as e:
            if e.code == 17:  # File exists
                print("clsact already exists, skipping...")
            else:
                raise
            
        await ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_loadbalancer.fd,
            name=fn_loadbalancer.name, parent="ffff:fff2", action="ok", classid=1)

        print(f"BPF program loaded on {IFNAME}. Press Ctrl+C to exit...")

        lb_map = b.get_table("upf_lb_map")

        for i, cfg in enumerate(upfs_config):
            key = ctypes.c_uint(i)
            value = LoadBalancerConfig(
                ip=ip_str_to_u32(cfg["ip"]),
                mac=mac_str_to_ubyte_array(cfg["mac"])
            )
            lb_map[key] = value
            print(f"[Control] Added UPF {i} → IP {cfg['ip']} MAC {cfg['mac']}")
            
        print(f"[Control] Loadbalancer enabled to ifindex {idx} ({IFNAME})")

    
    
async def unload_ebpf_program(_ifname):
    async with AsyncIPRoute() as ipr:
        idx_list = await ipr.link_lookup(ifname=_ifname)
        if not idx_list:
            raise Exception(f"Interface {_ifname} not found.")
        idx = idx_list[0]
        
        try:
            await ipr.tc("del", "clsact", idx)
            print("clsact successfully removed.")
        except Exception as e:
            print(f"Failed to delete clsact: {e}")
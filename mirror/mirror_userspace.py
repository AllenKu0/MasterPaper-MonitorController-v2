import time
import ctypes
import socket
import struct
import argparse
from bcc import BPF
from pyroute2 import IPRoute, AsyncIPRoute
from pyroute2 import NetlinkError

def mac_str_to_ubyte_array(mac_str):
    return (ctypes.c_ubyte * 6)(*map(lambda x: int(x, 16), mac_str.split(':')))

def ip_str_to_ubyte_array(ip_str):
    ip_packed = socket.inet_aton(ip_str)
    # 解包並保留大端字節序的整數值
    return struct.unpack("<I", ip_packed)[0]
# 鏡像map init
class MirrorConfig(ctypes.Structure):
    _fields_ = [
        ("enable", ctypes.c_uint),
        ("mirror_index", ctypes.c_uint), # gnb的網卡
        ("mirror_dst_ip", ctypes.c_uint),
        ("mirror_dst_mac", ctypes.c_ubyte * 6),
    ]

async def load_ebpf_program(_mirror_ip_str, _mirror_mac, _ifname, _mirror_ifname):
    async with AsyncIPRoute() as ipr:
        # 載入 BPF C 程式
        b = BPF(src_file="mirror/mirror_kernalspace.c")
        
        fn_mirror = b.load_func("mirror_traffic", BPF.SCHED_CLS)
        idx_list = await ipr.link_lookup(ifname=_ifname)
        mirror_list = await ipr.link_lookup(ifname=_mirror_ifname)

        if not idx_list:
            raise Exception(f"Interface {_ifname} not found.")
        if not mirror_list:
            raise Exception(f"Interface {_ifname} not found.")

        idx = idx_list[0]
        mirror_idx = mirror_list[0]

        try:
            await ipr.tc("add", "clsact", idx)
        except NetlinkError as e:
            if e.code == 17:  # File exists
                print("clsact already exists, skipping...")
            else:
                raise
            
        await ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_mirror.fd,
            name=fn_mirror.name, parent="ffff:fff2", action="ok", classid=1)

        # ipr.tc("add-filter", "bpf", idx, ":2", fd=fn_drop_mirror.fd,
        #        name=fn_drop_mirror.name, parent="ffff:fff3", action="ok", classid=1)

        print(f"BPF program loaded on {_ifname}. Press Ctrl+C to exit...")

        mirror_map = b.get_table("mirror_config_map")

        key = ctypes.c_uint(0)  # 固定 key 為 0
        value = MirrorConfig(enable=1,mirror_index=mirror_idx, mirror_dst_ip=ip_str_to_ubyte_array(_mirror_ip_str), mirror_dst_mac=mac_str_to_ubyte_array(_mirror_mac))
        mirror_map[key] = value

        print(f"[Control] Mirror enabled to ifindex {idx} ({_ifname})")

    return "Loaded successfully"

async def unload_ebpf_program(_ifname):
    async with AsyncIPRoute() as ipr:
        idx_list = await ipr.link_lookup(ifname=_ifname)
        if not idx_list:
            raise Exception(f"Interface {_ifname} not found.")
        idx = idx_list[0]

        try:
            await ipr.tc("del", "clsact", idx)
            print(f"[Control] clsact successfully removed from {_ifname}.")
        except Exception as e:
            print(f"[Error] Failed to delete clsact: {e}")
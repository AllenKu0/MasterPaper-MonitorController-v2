import ipaddress
import os
import json
import re

cluster1_pod_cidr = "10.244.0.0/16"
cluster2_pod_cidr = "10.245.0.0/16"

cluster1_ip = "10.1.0.24"
cluster2_ip = "10.1.0.25"

CLUSTER1="cluster1"
CLUSTER2="cluster2"

def determine_cluster(client_host: str) -> str:
    # 將 client_host 轉換為 IP 地址
    client_ip = ipaddress.ip_address(client_host)

    # 檢查 client_ip 是否屬於 cluster1 或 cluster2 的 pod CIDR 範圍
    if client_ip in ipaddress.ip_network(cluster1_pod_cidr) or client_host == cluster1_ip:
        return CLUSTER1
    elif client_ip in ipaddress.ip_network(cluster2_pod_cidr) or client_host == cluster2_ip:
        return CLUSTER2
    else:
        return "unknown"
    
def get_pod_info_by_lable(cluster, label):
    jsonpath = r"{range .items[*]}{.metadata.name} /{.status.podIP} /{.metadata.labels.enable}{end}"
    cmd = f"kubectl --context={cluster} get pods -l {label} -o jsonpath=\"{jsonpath}\""
    pod_info = os.popen(cmd).read().strip().split("/")
    print("pod_info: ", pod_info)
    # 分別取得 Pod 名稱、IP 和啟用狀態
    pod_name = pod_info[0].strip()
    pod_ip = pod_info[1].strip()
    enable = pod_info[2].strip()
    
    pod_mac = ""
    iface_info = ""
    veth_name = ""
    cmd = f"kubectl --context={cluster} exec {pod_name} -- sh -c \"ip link show eth0 | awk '/link\\/ether/ {{mac=\\$2}} /eth0/ {{split(\\$2,a,\\\":\\\"); iface=a[1]}} END {{print mac, iface}}'\""
    result = os.popen(cmd).read().strip()

    # 拆分為 MAC 與 iface 名稱
    parts = result.split()
    if len(parts) == 2:
        pod_mac, iface_info = parts
        print(f"MAC: {pod_mac}")
        print(f"iface_info: {iface_info}")
    else:
        print("無法正確取得 MAC 與 iface 資訊")

    # 從 eth0@ifxxx 中取出數字 index
    match = re.search(r'@if(\d+)', iface_info)
    if match:
        veth_index = match.group(1)
        print(f"Pod {pod_name} 的 veth index 為 {veth_index}")

        # 用 index 查宿主機上的 veth 名稱
        cmd_get_veth = f"ip link | awk -v idx={veth_index} '$1 ~ idx\":\" {{print $2}}' | cut -d@ -f1"
        veth_name = os.popen(cmd_get_veth).read().strip()
        print(f"Pod {pod_name} 的 veth 名稱為 {veth_name}")
    else:
        print("未找到 eth0 的對應 host veth index。")
        
    data = {
        "pod_name": pod_name,
        "pod_ip": pod_ip,
        "pod_mac": pod_mac,
        "veth_name": veth_name,
        "enable": enable
    }

    return data

def get_pod_info_by_name(cluster, pod_name):
    jsonpath = r"{.status.podIP}/{.metadata.labels.enable}"
    cmd = f"kubectl --context={cluster} get pod {pod_name} -o jsonpath=\"{jsonpath}\""
    output = os.popen(cmd).read().strip()
    
    if not output:
        raise Exception(f"No output received for pod {pod_name} in cluster {cluster}")

    pod_info = output.split("/")
    print("pod_info: ", pod_info)

    if len(pod_info) != 2:
        raise Exception(f"Unexpected output format: {output}")

    pod_ip = pod_info[0].strip()
    enable = pod_info[1].strip()
    
    pod_mac = ""
    iface_info = ""
    veth_name = ""
    cmd = f"kubectl --context={cluster} exec {pod_name} -- sh -c \"ip link show eth0 | awk '/link\\/ether/ {{mac=\\$2}} /eth0/ {{split(\\$2,a,\\\":\\\"); iface=a[1]}} END {{print mac, iface}}'\""
    result = os.popen(cmd).read().strip()

    # 拆分為 MAC 與 iface 名稱
    parts = result.split()
    if len(parts) == 2:
        pod_mac, iface_info = parts
        print(f"MAC: {pod_mac}")
        print(f"iface_info: {iface_info}")
    else:
        print("無法正確取得 MAC 與 iface 資訊")

    # 從 eth0@ifxxx 中取出數字 index
    match = re.search(r'@if(\d+)', iface_info)
    if match:
        veth_index = match.group(1)
        print(f"Pod {pod_name} 的 veth index 為 {veth_index}")

        # 用 index 查宿主機上的 veth 名稱
        cmd_get_veth = f"ip link | awk -v idx={veth_index} '$1 ~ idx\":\" {{print $2}}' | cut -d@ -f1"
        veth_name = os.popen(cmd_get_veth).read().strip()
        print(f"Pod {pod_name} 的 veth 名稱為 {veth_name}")
    else:
        print("未找到 eth0 的對應 host veth index。")
        
    data = {
        "pod_name": pod_name,
        "pod_ip": pod_ip,
        "pod_mac": pod_mac,
        "veth_name": veth_name,
        "enable": enable
    }

    return data
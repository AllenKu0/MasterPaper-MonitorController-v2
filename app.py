import os
import uvicorn
import upf_repository
import kubernetes as k
import loadbalancer.loadbalancer_repository as lb_repository
import loadbalancer.loadbalancer_controller as lb_controller
import circuit_breaker.circuit_breaker_controller as cb_controller
import mirror.mirror_controller as mirror_controller
import mirror.mirror_repository as mirror_repository
import trace_latency.trace_latency_controller as trace_controller

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Union

# POST /mirror
class MirrorRequest(BaseModel):
    mirror_pod_name: str

# DELETE /mirror
class MirrorDeleteRequest(BaseModel):
    mirror_pod_name: str

# POST /loadbalancer
class LoadBalancerRequest(BaseModel):
    name: str
    upf_pod_names: Union[str, List[str]]  # 支援單個 string 或 list of string

# DELETE /loadbalancer
class LoadBalancerDeleteRequest(BaseModel):
    name: str
    upf_pod_names: Union[str, List[str]] 

# POST /trace-latency
class TraceLatencyRequest(BaseModel):
    pod_name: str
    cluster: str

# DELETE /trace-latency
class TraceLatencyDeleteRequest(BaseModel):
    pod_name: str
    cluster: str
    
app = FastAPI()

CLUSTER1="cluster1"
CLUSTER2="cluster2"

monitor_tasks = {}

@app.post("/alert")
async def alert(request: Request):
    alert_data = await request.json()
    client_host = request.client.host
    cluster = k.determine_cluster(client_host)
    print("收到警報：", alert_data)
    await c.circuit(alert_data, cluster, client_host)
    return {"status": "circuit breaker triggered"}

@app.post("/mirror")
async def mirror(request: MirrorRequest):
    # mirror_data = await request.json()
    mirror_pod_name = request.mirror_pod_name
    query = {"pod_name": mirror_pod_name}  
    fields = ["pod_ip", "pod_mac"]
    
    data = upf_repository.mongodb_get(query, fields)
    print("data:",data)
    mirror_ip_str = data[0]["pod_ip"]
    mirror_mac = data[0]["pod_mac"]
    
    ifname = k.get_pod_info_by_lable(CLUSTER2, "app=ueransim-gnb")['veth_name'] 
    await mirror_controller.load_ebpf_program(mirror_ip_str, mirror_mac, ifname, "cilium_host")
    mirror_repository.mongodb_insert(CLUSTER2, mirror_pod_name, ifname)
    
    return {"status": "mirror setup completed"}

@app.delete("/mirror")
async def _delete_mirror(request: MirrorDeleteRequest):
    mirror_pod_name = request.mirror_pod_name
    query = {"mirror_pod_name": mirror_pod_name}
    fields = ["ifname"]
    data = mirror_repository.mongodb_get(query, fields)
    print("data:",data)
    ifname = data[0]["ifname"]
    await mirror_controller.unload_ebpf_program(ifname)
    mirror_repository.mongodb_remove({"mirror_pod_name": mirror_pod_name, "ifname": ifname})

    return {"status": "mirror remove completed"}

@app.post("/loadbalancer")
async def loadbalancer(request: LoadBalancerRequest):
    name = request.name
    upf_pod_names = request.upf_pod_names
    # 如果只有單一名稱也支援
    if isinstance(upf_pod_names, str):
        upf_pod_names = [upf_pod_names]

    query = {"pod_name": {"$in": upf_pod_names}}  # 使用 $in 查詢多個 pod
    fields = ["pod_ip", "pod_mac"]
    data = upf_repository.mongodb_get(query, fields)
    print("data:",data)
    upf_configs = []
    for i in range(len(data)):
        upf_config = {}
        upf_config["ip"] = data[i]["pod_ip"]
        upf_config["mac"] = data[i]["pod_mac"]
        upf_configs.append(upf_config)

    ifname = k.get_pod_info_by_lable(CLUSTER2, "app=ueransim-gnb")['veth_name']
    await lb_controller.load_ebpf_program(upf_configs, ifname)
    
    lb_repository.mongodb_insert(name, upf_pod_names)
    return {"status": "load balancer setup completed"}

@app.delete("/loadbalancer")
async def _delete_loadbalancer(request: LoadBalancerDeleteRequest):
    name = request.name
    upf_pod_names = request.upf_pod_names
    query = {"name": name,"upf_pod_names": upf_pod_names}
    
    # gnb veth name
    ifname = k.get_pod_info_by_lable(CLUSTER2, "app=ueransim-gnb")['veth_name']
    await lb_controller.unload_ebpf_program(ifname)
    lb_repository.mongodb_remove(query)

    return {"status": "loadbalancer remove completed"}
       

@app.post("/trace-latency")
async def _trace_latency(request: TraceLatencyRequest):    
    pod_name = request.pod_name
    query = {"pod_name": pod_name}  
    fields = ["cluster"]
    data = upf_repository.mongodb_get(query, fields)
    cluster = data[0]["cluster"]
    
    pod_info = k.get_pod_info_by_name(cluster, pod_name)
    ifname = pod_info['veth_name']
    
    latency_task, idx = await trace_controller.load_ebpf_program(ifname)
    monitor_tasks[ifname] = {"task": latency_task, "idx": idx}
    return {"message": "Latency monitoring started in the background."}
    
@app.delete("/trace-latency")
async def _delete_trace_latency(request: TraceLatencyDeleteRequest):
    pod_name = request.pod_name
    
    query = {"pod_name": pod_name}  
    fields = ["cluster"]
    data = upf_repository.mongodb_get(query, fields)
    cluster = data[0]["cluster"]
    
    ifname = k.get_pod_info_by_name(cluster, pod_name)['veth_name']
    print("monitor_tasks:", monitor_tasks)
    
    if ifname not in monitor_tasks:
        raise HTTPException(status_code=400, detail=f"No tracing task running on {ifname}.")

    task = monitor_tasks[ifname]["task"]
    idx = monitor_tasks[ifname]["idx"]

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print(f"[{ifname}] Monitor task cancelled.")

    await trace_controller.unload_ebpf_program(ifname)
    del monitor_tasks[ifname]
    
    return {"message": "Latency tracing stopped and BPF program unloaded."}


if __name__ == "__main__":
    upf_repository.mongodb_clear_all()
    print(upf_repository.init([CLUSTER1, CLUSTER2]))
    uvicorn.run("app:app", host="0.0.0.0", port=8080)
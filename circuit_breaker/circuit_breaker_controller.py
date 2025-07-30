import os
import kubernetes as k
import upf_repository as repository
import asyncio

async def circuit(alert_data, cluster):
    print("circuit start")
    if "High GTP-U Latency" in alert_data.get("alertname", ""):    
        # cmd = "kubectl --context {cluster} get pods -o wide --all-namespaces | grep {client_host} | awk '{print $2}'"
        # cmd = (
        #     f"kubectl --context {cluster} get pods -o wide --all-namespaces "
        #     f"| grep {client_host} | awk '{{print $2}}'"
        # )
        # pod_name = os.popen(cmd).read().strip()
        # pod_name = "free5gc-upf-deployment-985f98f84-4gb8j"
        pod_name = alert_data.get("pod_name", "")
        print(f"Pod name: {pod_name}")
        
        query = {"pod_name": pod_name}  # 查詢條件
        fields = ["enable"]  # 只查詢 enable 欄位
        result = repository.mongodb_get(query, fields)
        if result != "false":
            circuit_breaker_pool_control(cluster, pod_name, "false")
            repository.mongodb_update(cluster, pod_name, "false")
            # 掛起20s
            asyncio.create_task(resume_after_delay(cluster, pod_name)) 
    return {"status": "ok"}

def circuit_breaker_pool_control(cluster, pod_name, _enable):
    # patch_cmd = f"kubectl --context {cluster} patch pod {pod_name} -p '{{\"metadata\":{{\"labels\":{{\"enable\":\"{_enable}\"}}}}}}'"
    if _enable == "false":
        patch_cmd = f"kubectl --context {cluster} annotate service free5gc-upf-svc service.cilium.io/affinity=remote --overwrite"
    else:
        patch_cmd = f"kubectl --context {cluster} annotate service free5gc-upf-svc service.cilium.io/affinity=local --overwrite"    
    return os.popen(patch_cmd).read().strip()

async def resume_after_delay(cluster, pod_name):
    await asyncio.sleep(20)
    circuit_breaker_pool_control(cluster, pod_name, "true")
    repository.mongodb_update(cluster, pod_name, "true")
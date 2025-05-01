import os
import kubernetes as k

async def circuit(alert_data, client_host, cluster):
    if "High GTP-U Latency" in alert_data:    
        cmd = "kubectl --context {cluster} get pods -o wide --all-namespaces | grep {client_host} | awk '{print $2}'"
        pod_name = os.popen(cmd).read().strip()
        query = {"pod_name": pod_name}  # 查詢條件
        fields = ["enable"]  # 只查詢 enable 欄位
        result = repository.mongodb_get(query, fields)
        if result != "false":
            circuit_breaker_pool_control(cluster, pod_name, "false")
            repository.mongodb_update(cluster, pod_name, client_host, "false")
            # 掛起20s
            asyncio.create_task(resume_after_delay(cluster, pod_name, client_host)) 
    return {"status": "ok"}

def circuit_breaker_pool_control(pod_name, _enable):
    patch_cmd = f"kubectl --context {cluster} patch pod {pod_name} -p '{{\"metadata\":{{\"labels\":{{\"enable\":\"{_enable}\"}}}}}}'"
    return os.popen(patch_cmd).read().strip()

async def resume_after_delay(cluster, pod_name, client_host):
    await asyncio.sleep(20)
    circuit_breaker_pool_control(cluster, pod_name, "true")
    repository.mongodb_update(cluster, pod_name, client_host, "true")
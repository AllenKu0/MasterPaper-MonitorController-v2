# import subprocess
# import time
# import threading
from . import mirror_userspace

# def read_output(pipe, label):
#     for line in iter(pipe.readline, ''):
#         print(f"{label}: {line.strip()}")
#     pipe.close()

async def load_ebpf_program(mirror_ip_str,mirror_mac,ifname,mirror_ifname):
    await mirror_userspace.load_ebpf_program(mirror_ip_str, mirror_mac, ifname, mirror_ifname)
    # # 執行本地的 .sh 腳本
    # python_interpreter = "/usr/bin/python3"
    # # ifname 是 gnb的網卡，mirror_ifname cilium_host
    
    # process = subprocess.Popen(
    #     ["sudo", python_interpreter, "mirror/mirror_userspace.py", 
    #      "--mirror_ip_str", mirror_ip_str, 
    #      "--mirror_mac", mirror_mac, 
    #      "--ifname", ifname, 
    #      "--mirror_ifname", mirror_ifname], 
    #     stdout=subprocess.PIPE, 
    #     stderr=subprocess.PIPE, 
    #     text=True
    # )
    
    # # 打印 PID
    # print(f"Started mirror_userspace.py with PID: {process.pid}")
    
    # stdout_thread = threading.Thread(target=read_output, args=(process.stdout, "STDOUT"))
    # stderr_thread = threading.Thread(target=read_output, args=(process.stderr, "STDERR"))
    # stdout_thread.start()
    # stderr_thread.start()

    # # 等待子进程和线程结束
    # process.wait()
    # stdout_thread.join()
    # stderr_thread.join()
    # return process.pid
        
async def unload_ebpf_program(ifname):
    # kill process
    # result = subprocess.run(["kill","-9",pid], capture_output=True, text=True)
    # if result.stderr == "":
    #     print(f"Process {pid} killed successfully.")
    # else:
    #     print(f"Failed to kill process {pid}: {result.stderr}")
        
    # remove qdisc
    # result = subprocess.run(["sudo","tc","qdisc","del","dev",ifname,"clsact"], capture_output=True, text=True) 
    # if result.stderr == "":
        # print(f"ifname: {ifname} qdisc remove successfully.")  
    # else:
        # print(f"Failed to remove qdisc: {result.stderr}")   
    await mirror_userspace.unload_ebpf_program(ifname)    
    
if __name__ == "__main__":
    # 測試函數
    pid = mirror("10.244.0.162", "8e:87:b7:f8:9c:67", "lxc7d088855cc6d", "cilium_host")
    time.sleep(5)
    kill_mirror_process(str(pid),"lxc7d088855cc6d")  # 替換為實際的 PID
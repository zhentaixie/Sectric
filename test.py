import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def main():
    # 读取数字 x
    x = input("请输入一个数字 x：")
    try:
        # 尝试将输入的内容转换为整数
        x = int(x)
    except ValueError:
        # 如果无法转换为整数，则打印错误信息并退出程序
        print("请输入查询的节点编号")
        return

    # 读取文件并打印内容
    neighbors = []
    nt = "64"
    file_name=input("Please enter the filename:")
    # num_d=input("Please enter the MAX_DEGREE:")
    # num_v=input("Please enter the NUM_VERTEX:")
    MAX_DEGREE=(file_name.split('_')[3])
    NUM_VERTEX=(file_name.split('_')[1])
    filename = f"./data/neighbor_files_"+file_name+f"/neighbor_{x}.txt"
    try:
        with open(filename, 'r') as file:
            for line in file:
                neighbors.append(int(line.strip()))
    except FileNotFoundError:
        # 如果文件不存在，则打印错误信息
        print(f"文件 {filename} 不存在。")
        return

    processes = []
    print("此节点的邻居数为：", len(neighbors))

    # 启动初始角色1的命令
    command = ["./bin/gcf_psi", "--idx", str(x), "--role", str(1),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]
    process = subprocess.Popen(command)
    processes.append(process)
    print(file_name)
    # 分批处理邻居命令
    batch_size = 50
    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        future_to_command = {executor.submit(subprocess.Popen, ["./bin/gcf_psi", "--neighbor", str(neighbor), "--role", str(2),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]): neighbor for neighbor in neighbors[:batch_size]}

        for future in as_completed(future_to_command):
            try:
                process = future.result()
                process.wait()
            except Exception as exc:
                print(f'生成的进程出现异常: {exc}')

        remaining_neighbors = neighbors[batch_size:]
        while remaining_neighbors:
            future_to_command = {executor.submit(subprocess.Popen, ["./bin/gcf_psi", "--neighbor", str(neighbor), "--role", str(2),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]): neighbor for neighbor in remaining_neighbors[:batch_size]}

            for future in as_completed(future_to_command):
                try:
                    process = future.result()
                    process.wait()
                except Exception as exc:
                    print(f'生成的进程出现异常: {exc}')

            remaining_neighbors = remaining_neighbors[batch_size:]

    # 启动角色0的命令
    command = ["./bin/gcf_psi", "--idx", str(x), "--role", str(0),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]
    process = subprocess.Popen(command)
    processes.append(process)

    # 等待所有进程完成
    for process in processes[:-1]:
        process.wait()

    processes[-1].wait()

if __name__ == "__main__":
    main()

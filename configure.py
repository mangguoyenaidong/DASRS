import os
import sys
import subprocess

try:
    from ruamel.yaml import YAML
except ImportError:
    print("错误: 未找到 ruamel.yaml 库。")
    print("请先执行: pip install ruamel.yaml")
    sys.exit(1)

def get_input(prompt, default_value):
    user_input = input(f"{prompt} [{default_value}]: ").strip()
    return user_input if user_input else default_value

def get_network_interfaces():
    try:
        output = subprocess.check_output(['ip', '-o', 'link', 'show']).decode()
        interfaces = []
        for line in output.split('\n'):
            if line:
                parts = line.split(':')
                if len(parts) > 1:
                    name = parts[1].strip()
                    if name != 'lo':
                        interfaces.append(name)
        return interfaces
    except:
        return ["eth0", "ens33"]

def configure_suricata():
    print("\n--- 正在配置 Suricata (IDS 引擎) ---")
    interfaces = get_network_interfaces()
    print(f"检测到网卡: {', '.join(interfaces)}")
    default_iface = interfaces[0] if interfaces else "eth0"
    iface = get_input("  请输入要监控的网卡名称", default_iface)
    
    # 新增：询问是否开启 Payload 捕获
    enable_payload = get_input("  是否开启详细攻击报文捕获 (Payload)? (y/n)", "y").lower() == 'y'

    suricata_yaml = "/etc/suricata/suricata.yaml"
    if os.path.exists(suricata_yaml):
        print(f"  正在自动修改 {suricata_yaml} ...")
        
        # 1. 修改网卡绑定
        cmd_iface = f"sudo sed -i 's/interface: .*/interface: {iface}/g' {suricata_yaml}"
        os.system(cmd_iface)
        
        # 2. 修改 Payload 配置 (在 alert 块中定位并修改)
        if enable_payload:
            # 定位到 alert 类型并开启 payload 输出
            # 我们使用 sed 的范围匹配功能，在 - alert: 之后寻找最近的 payload 并修改
            os.system(f"sudo sed -i '/- alert:/,/payload:/ s/payload: .*/payload: yes/' {suricata_yaml}")
            # 顺便开启可打印字符模式，增强审计可读性
            os.system(f"sudo sed -i '/- alert:/,/payload-printable:/ s/payload-printable: .*/payload-printable: yes/' {suricata_yaml}")
            print("  ✅ 已开启详细报文捕获 (Payload: yes)")
        else:
            os.system(f"sudo sed -i '/- alert:/,/payload:/ s/payload: .*/payload: no/' {suricata_yaml}")
            print("  ℹ️ 已关闭详细报文捕获。")

        print(f"  ✅ Suricata 网卡已绑定到: {iface}")
        print("  🔄 正在重启 Suricata 服务...")
        os.system("sudo systemctl restart suricata")
    else:
        print(f"  ❌ 未在 {suricata_yaml} 找到配置文件，请手动确认。")

def configure_interactive():
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    
    print("="*40)
    print("   🛡️  DASRS 交互式配置助手")
    print("="*40)
    
    mode = input("请选择配置目标 (1: Master, 2: Agent, 3: 全部, 4: 仅配置 Suricata) [3]: ") or "3"
    
    if mode == "4":
        configure_suricata()
        return

    # --- 配置 Master (config.yaml) ---
    if mode in ["1", "3"]:
        path = 'configs/config.yaml'
        if os.path.exists(path):
            print(f"\n--- 正在配置 Master ({path}) ---")
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.load(f)
            
            db = data['master']['database']
            db['host'] = get_input("  MySQL 地址", db['host'])
            db['password'] = get_input("  MySQL 密码", db['password'])
            
            redis = data['master']['redis']
            redis['host'] = get_input("  Redis 地址", redis['host'])
            
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f)
            print("✅ Master 配置已更新。")

    # --- 配置 Agent (agent.yaml) ---
    if mode in ["2", "3"]:
        path = 'configs/agent.yaml'
        if os.path.exists(path):
            print(f"\n--- 正在配置 Agent ({path}) ---")
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.load(f)
            
            agent = data['agent']
            current_addr = agent['master_address']
            current_ip = current_addr.split(':')[0] if ':' in current_addr else current_addr
            
            new_ip = get_input("  Master IP 地址", current_ip)
            agent['master_address'] = f"{new_ip}:50051"
            agent['agent_name'] = get_input("  Agent 节点名称", agent['agent_name'] or "agent-01")
            
            # 自动探测 Suricata 日志路径
            default_log = "/var/log/suricata/eve.json"
            if not os.path.exists(default_log) and os.path.exists("./suricata_logs/eve.json"):
                default_log = "./suricata_logs/eve.json"
            agent['suricata_log_path'] = get_input("  Suricata 日志路径", default_log)
            
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f)
            print("✅ Agent 配置已更新。")
            
            if input("\n是否需要配置本地 Suricata 引擎 (网卡绑定)? [y/N]: ").lower() == 'y':
                configure_suricata()

    print("\n" + "="*40)
    print("🎉 配置完成！你可以现在启动服务了。")
    print("="*40)

if __name__ == '__main__':
    try:
        configure_interactive()
    except KeyboardInterrupt:
        print("\n\n已取消配置。")
        sys.exit(0)

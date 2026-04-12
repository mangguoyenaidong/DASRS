import os
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    print("错误: 未找到 ruamel.yaml 库。")
    print("请先执行: pip install ruamel.yaml")
    sys.exit(1)

def get_input(prompt, default_value):
    """辅助函数：带默认值的输入提示"""
    user_input = input(f"{prompt} [{default_value}]: ").strip()
    return user_input if user_input else default_value

def configure_interactive():
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    
    print("="*40)
    print("   🛡️  DASRS 交互式配置助手")
    print("="*40)
    
    mode = input("请选择配置目标 (1: Master, 2: Agent, 3: 全部) [3]: ") or "3"
    
    # --- 配置 Master (config.yaml) ---
    if mode in ["1", "3"]:
        path = 'configs/config.yaml'
        if os.path.exists(path):
            print(f"\n--- 正在配置 Master ({path}) ---")
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.load(f)
            
            # 数据库配置
            db = data['master']['database']
            db['host'] = get_input("  MySQL 地址", db['host'])
            db['password'] = get_input("  MySQL 密码", db['password'])
            
            # Redis 配置
            redis = data['master']['redis']
            redis['host'] = get_input("  Redis 地址", redis['host'])
            
            # 情报引擎配置
            intel = data['master']['intelligence']
            intel['block_threshold'] = int(get_input("  IP 封禁阈值 (分数)", intel['block_threshold']))
            
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f)
            print("✅ Master 配置已更新。")
        else:
            print(f"警告: 未找到 {path}，跳过 Master 配置。")

    # --- 配置 Agent (agent.yaml) ---
    if mode in ["2", "3"]:
        path = 'configs/agent.yaml'
        if os.path.exists(path):
            print(f"\n--- 正在配置 Agent ({path}) ---")
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.load(f)
            
            agent = data['agent']
            # 从 master_address 分离 IP
            current_addr = agent['master_address']
            current_ip = current_addr.split(':')[0] if ':' in current_addr else current_addr
            
            new_ip = get_input("  Master IP 地址", current_ip)
            agent['master_address'] = f"{new_ip}:50051"
            
            agent['agent_name'] = get_input("  Agent 节点名称", agent['agent_name'] or "agent-01")
            agent['suricata_log_path'] = get_input("  Suricata 日志路径", agent['suricata_log_path'])
            
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f)
            print("✅ Agent 配置已更新。")
        else:
            print(f"警告: 未找到 {path}，跳过 Agent 配置。")

    print("\n" + "="*40)
    print("🎉 配置完成！你可以现在启动服务了。")
    print("="*40)

if __name__ == '__main__':
    try:
        configure_interactive()
    except KeyboardInterrupt:
        print("\n\n已取消配置。")
        sys.exit(0)

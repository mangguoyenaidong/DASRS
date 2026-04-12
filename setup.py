import sys
import argparse
import os
from ruamel.yaml import YAML

def setup_config():
    parser = argparse.ArgumentParser(description='DASRS 一键配置脚本')
    
    # 共同参数
    parser.add_argument('--master-ip', type=str, help='Master 服务器的公网/局域网 IP')
    
    # Agent 特定参数
    parser.add_argument('--agent-name', type=str, help='当前 Agent 的名称 (例如: agent-01)')
    parser.add_argument('--suricata-log', type=str, help='Suricata eve.json 的绝对路径')
    
    # Master 特定参数
    parser.add_argument('--db-host', type=str, help='MySQL 数据库地址')
    parser.add_argument('--db-pass', type=str, help='MySQL 数据库密码')
    parser.add_argument('--redis-host', type=str, help='Redis 地址')

    args = parser.parse_args()
    
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    # 1. 配置 configs/config.yaml (Master 核心配置)
    master_cfg_path = 'configs/config.yaml'
    if os.path.exists(master_cfg_path):
        with open(master_cfg_path, 'r', encoding='utf-8') as f:
            master_data = yaml.load(f)
        
        if args.master_ip:
            # 修改 Master 监听 (通常设为 0.0.0.0)
            master_data['master']['host'] = "0.0.0.0"
        
        if args.db_host:
            master_data['master']['database']['host'] = args.db_host
        if args.db_pass:
            master_data['master']['database']['password'] = args.db_pass
        if args.redis_host:
            master_data['master']['redis']['host'] = args.redis_host
            
        with open(master_cfg_path, 'w', encoding='utf-8') as f:
            yaml.dump(master_data, f)
        print(f"宸叉洿鏂 {master_cfg_path}")

    # 2. 配置 configs/agent.yaml (Agent 远程部署配置)
    agent_cfg_path = 'configs/agent.yaml'
    if os.path.exists(agent_cfg_path):
        with open(agent_cfg_path, 'r', encoding='utf-8') as f:
            agent_data = yaml.load(f)
        
        if args.master_ip:
            agent_data['agent']['master_address'] = f"{args.master_ip}:50051"
        
        if args.agent_name:
            agent_data['agent']['agent_name'] = args.agent_name
            
        if args.suricata_log:
            agent_data['agent']['suricata_log_path'] = args.suricata_log
            
        with open(agent_cfg_path, 'w', encoding='utf-8') as f:
            yaml.dump(agent_data, f)
        print(f"宸叉洿鏂 {agent_cfg_path}")

if __name__ == '__main__':
    setup_config()

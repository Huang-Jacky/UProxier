#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
发布到 PyPI 的脚本
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """运行命令并处理错误"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} 成功")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} 失败")
        print(f"错误: {e.stderr}")
        return False


def main():
    """主函数"""
    print("🚀 开始发布 UProxier 到 PyPI")

    # 检查当前目录
    if not Path("pyproject.toml").exists():
        print("❌ 请在项目根目录运行此脚本")
        sys.exit(1)

    # 1. 清理旧的构建文件
    if not run_command("rm -rf dist/ build/ *.egg-info/", "清理旧的构建文件"):
        sys.exit(1)

    # 2. 安装构建工具
    if not run_command("python3 -m pip install --user --upgrade build twine", "安装构建工具"):
        sys.exit(1)

    # 3. 构建包
    if not run_command("python3 -m build", "构建包"):
        sys.exit(1)

    # 4. 检查包
    if not run_command("python3 -m twine check dist/*", "检查包"):
        sys.exit(1)

    # 5. 询问是否发布
    print("\n📦 包已构建完成，文件:")
    for file in Path("dist").glob("*"):
        print(f"  - {file}")

    choice = input("\n是否发布到 PyPI? (y/N): ").strip().lower()
    if choice != 'y':
        print("❌ 取消发布")
        sys.exit(0)

    # 6. 发布到 PyPI
    if not run_command("python3 -m twine upload dist/*", "发布到 PyPI"):
        sys.exit(1)

    print("\n🎉 发布成功!")
    print("用户现在可以通过以下命令安装:")
    print("  pip install uproxier")
    print("  uproxier --help")


if __name__ == "__main__":
    main()

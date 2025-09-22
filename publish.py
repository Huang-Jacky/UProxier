#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
发布到 PyPI 的脚本
"""

import subprocess
import sys
import re
from pathlib import Path


def run_command(cmd, description, check=True):
    """运行命令并处理错误"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr and not check:
            print(result.stderr)
        print(f"✅ {description} 成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} 失败")
        print(f"错误: {e.stderr}")
        return False


def check_version_sync():
    """检查版本号同步"""
    print("🔍 检查版本号同步...")
    
    # 读取 version.py
    version_file = Path("uproxier/version.py")
    if not version_file.exists():
        print("❌ uproxier/version.py 不存在")
        return False
    
    version_content = version_file.read_text()
    version_match = re.search(r'__version__ = "([^"]+)"', version_content)
    if not version_match:
        print("❌ 无法从 uproxier/version.py 中提取版本号")
        return False
    
    version_py_version = version_match.group(1)
    print(f"✅ uproxier/version.py: {version_py_version}")
    
    # 读取 pyproject.toml
    pyproject_file = Path("pyproject.toml")
    if not pyproject_file.exists():
        print("❌ pyproject.toml 不存在")
        return False
    
    pyproject_content = pyproject_file.read_text()
    pyproject_match = re.search(r'version = "([^"]+)"', pyproject_content)
    if not pyproject_match:
        print("❌ 无法从 pyproject.toml 中提取版本号")
        return False
    
    pyproject_version = pyproject_match.group(1)
    print(f"✅ pyproject.toml: {pyproject_version}")
    
    if version_py_version != pyproject_version:
        print(f"❌ 版本号不一致: {version_py_version} vs {pyproject_version}")
        return False
    
    print("✅ 版本号同步检查通过")
    return True


def check_readme_sync():
    """检查 README 同步"""
    print("🔍 检查 README 同步...")
    
    readme_file = Path("README.md")
    readme_pypi_file = Path("README_PYPI.md")
    
    if not readme_file.exists():
        print("❌ README.md 不存在")
        return False
    
    if not readme_pypi_file.exists():
        print("❌ README_PYPI.md 不存在")
        return False
    
    readme_content = readme_file.read_text()
    readme_pypi_content = readme_pypi_file.read_text()
    
    # 检查功能特性部分
    features_match = re.search(r'## 功能特性\n(.*?)\n##', readme_content, re.DOTALL)
    features_pypi_match = re.search(r'## 功能特性\n(.*?)\n##', readme_pypi_content, re.DOTALL)
    
    if not features_match or not features_pypi_match:
        print("❌ 无法提取功能特性部分")
        return False
    
    features = features_match.group(1).strip()
    features_pypi = features_pypi_match.group(1).strip()
    
    if features != features_pypi:
        print("❌ 功能特性部分不一致")
        print("README.md 功能特性:")
        print(features[:200] + "..." if len(features) > 200 else features)
        print("\nREADME_PYPI.md 功能特性:")
        print(features_pypi[:200] + "..." if len(features_pypi) > 200 else features_pypi)
        return False
    
    # 检查是否包含源码相关内容
    if "python3 cli.py" in readme_pypi_content:
        print("❌ README_PYPI.md 包含源码相关内容")
        return False
    
    if "从源码安装" in readme_pypi_content:
        print("❌ README_PYPI.md 包含源码安装相关内容")
        return False
    
    print("✅ README 同步检查通过")
    return True


def check_build_files():
    """检查构建文件"""
    print("🔍 检查构建文件...")
    
    required_files = [
        "pyproject.toml",
        "uproxier/__init__.py",
        "uproxier/version.py",
        "README_PYPI.md"
    ]
    
    for file_path in required_files:
        if not Path(file_path).exists():
            print(f"❌ 必需文件不存在: {file_path}")
            return False
        print(f"✅ {file_path}")
    
    print("✅ 构建文件检查通过")
    return True


def run_pre_release_checks():
    """运行发布前检查"""
    print("🚀 开始发布前检查...\n")
    
    checks = [
        check_version_sync,
        check_readme_sync,
        check_build_files
    ]
    
    all_passed = True
    for check in checks:
        if not check():
            all_passed = False
    
    print("\n" + "="*50)
    if all_passed:
        print("🎉 所有检查通过！可以发布版本了。")
        return True
    else:
        print("❌ 检查失败！请修复问题后重新运行。")
        return False


def main():
    """主函数"""
    print("🚀 开始发布 UProxier 到 PyPI")

    # 检查当前目录
    if not Path("pyproject.toml").exists():
        print("❌ 请在项目根目录运行此脚本")
        sys.exit(1)

    # 1. 运行发布前检查
    if not run_pre_release_checks():
        print("❌ 发布前检查失败，请修复问题后重新运行")
        sys.exit(1)

    # 2. 清理旧的构建文件
    if not run_command("rm -rf dist/ build/ *.egg-info/", "清理旧的构建文件"):
        sys.exit(1)

    # 3. 安装构建工具
    if not run_command("python3 -m pip install --user --upgrade build twine", "安装构建工具"):
        sys.exit(1)

    # 4. 构建包
    if not run_command("python3 -m build", "构建包"):
        sys.exit(1)

    # 5. 检查包
    if not run_command("python3 -m twine check dist/*", "检查包"):
        sys.exit(1)

    # 6. 询问是否发布
    print("\n📦 包已构建完成，文件:")
    for file in Path("dist").glob("*"):
        print(f"  - {file}")

    choice = input("\n是否发布到 PyPI? (y/N): ").strip().lower()
    if choice != 'y':
        print("❌ 取消发布")
        sys.exit(0)

    # 7. 发布到 PyPI
    if not run_command("python3 -m twine upload dist/*", "发布到 PyPI"):
        sys.exit(1)

    print("\n🎉 发布成功!")
    print("用户现在可以通过以下命令安装:")
    print("  pip install uproxier")
    print("  uproxier --version")
    
    # 8. 显示 PyPI 链接
    version = None
    try:
        with open("uproxier/version.py", "r") as f:
            content = f.read()
            match = re.search(r'__version__ = "([^"]+)"', content)
            if match:
                version = match.group(1)
    except:
        pass
    
    if version:
        print(f"\n📋 PyPI 链接: https://pypi.org/project/uproxier/{version}/")


if __name__ == "__main__":
    main()

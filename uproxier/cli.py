#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import signal
import subprocess
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from uproxier.certificate_manager import CertificateManager
from uproxier.proxy_server import ProxyServer
from uproxier.rules_engine import RulesEngine, default_config_path
from uproxier.version import get_version, get_author
from uproxier.exceptions import ConfigInheritanceError, RuleValidationError, ProxyStartupError
from uproxier.config_validator import ConfigValidator, ConfigAnalyzer
from uproxier.network_utils import get_display_host
from uproxier.examples import list_examples as get_examples, get_example_content, get_readme_content
console = Console()

try:
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"mitmproxy\.certs")


def get_pid_file() -> Path:
    """获取 PID 文件路径"""
    pid_dir = Path.home() / '.uproxier'
    pid_dir.mkdir(exist_ok=True)
    return pid_dir / 'uproxier.pid'


def save_pid(pid: int) -> bool:
    """保存 PID 到文件"""
    pid_file = get_pid_file()
    try:
        with open(pid_file, 'w') as f:
            f.write(str(pid))
        return True
    except Exception:
        return False


def load_pid() -> Optional[int]:
    """从文件读取 PID"""
    pid_file = get_pid_file()
    try:
        if pid_file.exists():
            with open(pid_file, 'r') as f:
                return int(f.read().strip())
    except Exception:
        pass
    return None


def is_process_running(pid: int) -> bool:
    """检查进程是否在运行"""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def cleanup_pid_file() -> None:
    """清理 PID 文件"""
    pid_file = get_pid_file()
    try:
        if pid_file.exists():
            pid_file.unlink()
    except Exception:
        pass


def is_service_ready(host: str, port: int, timeout: int = 1) -> bool:
    """检查服务是否真正就绪"""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='详细输出')
@click.version_option(version=get_version(), prog_name='UProxier')
def cli(verbose: bool) -> None:
    """代理服务器命令行工具"""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        # 没有 --verbose 时，只输出 WARNING 及以上级别的日志
        logging.basicConfig(level=logging.WARNING)


@cli.command()
@click.option('--port', default=8001, help='代理服务端口')
@click.option('--web-port', default=8002, help='Web 界面端口')
@click.option('--config', default=None, help='配置文件路径')
@click.option('--save', 'save_path', default=None, help='保存请求数据到文件（jsonl）')
@click.option('--enable-https/--disable-https', 'https_flag', default=None, help='启用/禁用 HTTPS 解密（覆盖配置）')
@click.option('--silent', '-s', is_flag=True, help='静默模式，不输出任何信息')
@click.option('--daemon', '-d', is_flag=True, help='后台模式启动')
def start(port: int, web_port: int, config: str, save_path: Optional[str],
          https_flag: Optional[bool], silent: bool, daemon: bool):
    """启动代理服务器"""
    if silent:
        logging.basicConfig(level=logging.ERROR)
        # 抑制所有第三方库的日志
        logging.getLogger('mitmproxy').setLevel(logging.ERROR)
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        logging.getLogger('flask').setLevel(logging.ERROR)
        logging.getLogger('asyncio').setLevel(logging.ERROR)

        # 设置环境变量抑制输出
        os.environ['MITMPROXY_QUIET'] = '1'
        os.environ['MITMPROXY_TERMLOG_VERBOSITY'] = 'error'
        os.environ['FLASK_DEBUG'] = '0'

    host = '0.0.0.0'  # 固定监听所有网络接口
    display_host = get_display_host(host)

    if not silent:
        # 准备证书信息的文本行
        cert_lines = []
        try:
            cert_manager = CertificateManager()
            cert_manager.ensure_certificates()
            cert_info = cert_manager.get_certificate_info()
            if 'error' not in cert_info:
                cert_lines.append(f"证书: {cert_info['cert_path']}")
                pem_path = Path(cert_info['cert_path'])
                # 有效期
                try:
                    res = subprocess.run(["openssl", "x509", "-in", str(pem_path), "-noout", "-dates"], check=True,
                                         capture_output=True, text=True)
                    not_before = None
                    not_after = None
                    for line in res.stdout.splitlines():
                        if line.startswith("notBefore="):
                            not_before = line.split("=", 1)[1].strip()
                        elif line.startswith("notAfter="):
                            not_after = line.split("=", 1)[1].strip()

                    def parse_dt(_s: str) -> datetime:
                        return datetime.strptime(_s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

                    if not_before and not_after:
                        nb = parse_dt(not_before)
                        na = parse_dt(not_after)
                        now = datetime.now(timezone.utc)
                        remain_days = int((na - now).total_seconds() // 86400)
                        status_s = "有效" if now < na else "[red]已过期[/red]"
                        nb_s = nb.strftime("%Y-%m-%d %H:%M:%S")
                        na_s = na.strftime("%Y-%m-%d %H:%M:%S")
                        cert_lines.append(
                            f"证书有效期：[green]{nb_s}  ~  {na_s}  (" + f"{status_s}, 剩余 {max(remain_days, 0)} 天)[/green]")
                except Exception:
                    pass
                # 指纹（SHA-256）
                try:
                    fres = subprocess.run(
                        ["openssl", "x509", "-in", str(pem_path), "-noout", "-fingerprint", "-sha256"], check=True,
                        capture_output=True, text=True)
                    fp = None
                    for line in fres.stdout.splitlines():
                        if "Fingerprint=" in line:
                            fp = line.split("=", 1)[1].strip().replace(":", "")
                            break
                    if fp:
                        cert_lines.append(f"证书指纹(SHA-256): [cyan]{fp}[/cyan]")
                except Exception:
                    pass
            else:
                cert_lines.append(f"证书错误: [red]{cert_info['error']}[/red]")
        except Exception:
            pass

        panel_text = (
            f"代理地址: [green]{display_host}:{port}[/green]\n"
            f"Web 界面: [green]http://{display_host}:{web_port}[/green]\n"
            f"配置文件: [yellow]{config}[/yellow]"
        )
        if cert_lines:
            panel_text += "\n" + "\n".join(cert_lines)
        console.print(Panel.fit(panel_text, title="🚀 UProxier"))

    existing_pid = load_pid()
    if existing_pid and is_process_running(existing_pid):
        if not silent:
            console.print(f"[yellow]服务器已在运行 (PID: {existing_pid})[/yellow]")
            console.print("使用 [cyan]uproxier stop[/cyan] 停止现有服务器")
        return

    if daemon:
        # 后台模式启动，构建启动命令
        cmd = [sys.executable, '-m', 'uproxier.cli', 'start', '--port', str(port),
               '--web-port', str(web_port), '--silent']
        
        if config is not None:
            cmd.extend(['--config', config])

        if save_path:
            cmd.extend(['--save', save_path])

        if https_flag is not None:
            if https_flag:
                cmd.append('--enable-https')
            else:
                cmd.append('--disable-https')

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=os.getcwd()
            )

            max_wait = 5.0
            wait_interval = 0.2
            waited = 0.0
            service_ready = False

            while waited < max_wait:
                time.sleep(wait_interval)
                waited += wait_interval

                if process.poll() is not None:
                    # 进程已退出，获取错误信息
                    stdout, stderr = process.communicate()
                    if not silent:
                        console.print(f"[red]后台进程启动失败[/red]")
                        if stderr:
                            console.print(f"[red]错误信息: {stderr.decode()}[/red]")
                        if stdout:
                            console.print(f"[red]输出信息: {stdout.decode()}[/red]")
                    sys.exit(1)

                if waited >= 0.5 and is_service_ready(host, web_port):
                    service_ready = True
                    if not silent:
                        console.print(f"[green]服务已就绪 (等待时间: {waited:.1f}s)[/green]")
                    break

                if waited >= 3.0 and not silent:
                    console.print(f"[yellow]服务启动较慢，继续等待... (已等待 {waited:.1f}s)[/yellow]")

            if not service_ready:
                if not silent:
                    console.print(f"[red]服务启动超时 (等待时间: {waited:.1f}s)[/red]")
                    console.print("[yellow]请检查配置和端口是否可用[/yellow]")
                process.terminate()
                sys.exit(1)

            # 再次检查进程状态
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                if not silent:
                    console.print(f"[red]后台进程启动失败[/red]")
                    if stderr:
                        console.print(f"[red]错误信息: {stderr.decode()}[/red]")
                    if stdout:
                        console.print(f"[red]输出信息: {stdout.decode()}[/red]")
                sys.exit(1)

            # 保存 PID
            if save_pid(process.pid):
                if not silent:
                    console.print(f"[green]服务器已在后台启动 (PID: {process.pid})[/green]")
                    console.print("使用 [cyan]uproxier stop[/cyan] 停止服务器")
            else:
                if not silent:
                    console.print("[red]启动失败: 无法保存 PID 文件[/red]")
                process.terminate()
                sys.exit(1)

        except Exception as e:
            if not silent:
                console.print(f"[red]启动失败: {e}[/red]")
            sys.exit(1)
    else:
        try:
            config_path = config or default_config_path()
            proxy = ProxyServer(config_path, save_path=save_path, silent=silent,
                                enable_https=https_flag)
            proxy.start(port, web_port)
        except KeyboardInterrupt:
            if not silent:
                console.print("\n[yellow]用户中断，正在停止服务器...[/yellow]")
        except (ConfigInheritanceError, RuleValidationError) as e:
            if not silent:
                console.print(f"[red]配置错误: {e}[/red]")
                if hasattr(e, 'suggestions') and e.suggestions:
                    console.print("[yellow]修复建议:[/yellow]")
                    for suggestion in e.suggestions:
                        console.print(f"  - {suggestion}")
            sys.exit(1)
        except ProxyStartupError as e:
            if not silent:
                console.print(f"[red]代理启动失败: {e}[/red]")
                if hasattr(e, 'details') and e.details:
                    if 'port' in e.details:
                        console.print(f"[yellow]端口: {e.details['port']}[/yellow]")
                    if 'web_port' in e.details:
                        console.print(f"[yellow]Web端口: {e.details['web_port']}[/yellow]")
            sys.exit(1)
        except Exception as e:
            if not silent:
                console.print(f"[red]启动失败: {e}[/red]")
            sys.exit(1)


@cli.command()
@click.option('--config', default=None, help='配置文件路径')
def init(config: str) -> None:
    """初始化代理服务器配置"""
    console.print(Panel.fit(
        "[bold blue]初始化代理服务器配置[/bold blue]\n"
        "这将创建默认配置文件和证书",
        title="⚙️ 初始化"
    ))

    try:
        cert_manager = CertificateManager()
        cert_manager.ensure_certificates()

        config_path = config or default_config_path()
        rules_engine = RulesEngine(config_path)

        console.print("[green]✓ 配置初始化完成[/green]")

        instructions = cert_manager.get_installation_instructions()
        console.print(Panel(instructions, title="📋 证书安装说明"))

    except Exception as e:
        console.print(f"[red]初始化失败: {e}[/red]")
        sys.exit(1)


@cli.command()
def cert() -> None:
    """证书管理"""
    cert_manager = CertificateManager()

    while True:
        console.clear()
        console.print(Panel.fit("[bold blue]证书管理[/bold blue]", title="🔐 证书管理"))

        cert_info = cert_manager.get_certificate_info()
        if 'error' not in cert_info:
            console.print(f"[green]证书路径: {cert_info['cert_path']}[/green]")
            console.print(f"[green]私钥路径: {cert_info['key_path']}[/green]")
        else:
            console.print(f"[red]证书错误: {cert_info['error']}[/red]")

        console.print("\n[bold]操作:[/bold]")
        console.print("1. 生成新证书")
        console.print("2. 安装证书到系统")
        console.print("3. 显示安装说明")
        console.print("4. 验证证书")
        console.print("5. 清理证书")
        console.print("0. 返回")

        choice = Prompt.ask("请选择操作", choices=["0", "1", "2", "3", "4", "5"])

        if choice == "0":
            break
        elif choice == "1":
            try:
                cert_manager.ensure_certificates()
                console.print("[green]证书生成成功[/green]")
            except Exception as e:
                console.print(f"[red]证书生成失败: {e}[/red]")
        elif choice == "2":
            try:
                cert_manager.install_certificate()
                console.print("[green]证书安装成功[/green]")
            except Exception as e:
                console.print(f"[red]证书安装失败: {e}[/red]")
        elif choice == "3":
            instructions = cert_manager.get_installation_instructions()
            console.print(Panel(instructions, title="📋 证书安装说明"))
            input("按回车键继续...")
        elif choice == "4":
            try:
                cert_manager.verify_certificate()
                console.print("[green]证书验证通过[/green]")
            except Exception as e:
                console.print(f"[red]证书验证失败: {e}[/red]")
        elif choice == "5":
            if Confirm.ask("确定要清理证书文件吗"):
                cert_manager.cleanup()
                console.print("[green]证书文件已清理[/green]")


@cli.command()
def stop() -> None:
    """停止后台运行的服务器"""
    pid = load_pid()
    if not pid:
        console.print("[yellow]服务器未运行[/yellow]")
        return

    if not is_process_running(pid):
        console.print("[yellow]服务器未运行[/yellow]")
        cleanup_pid_file()
        return

    try:
        # 发送 SIGTERM 信号
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]已发送停止信号到进程 {pid}[/green]")

        # 等待进程结束
        for i in range(30):  # 最多等待3秒
            if not is_process_running(pid):
                break
            time.sleep(0.1)

        if is_process_running(pid):
            # 如果进程还在运行，发送 SIGKILL
            console.print("[yellow]进程未响应，强制终止...[/yellow]")
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.2)  # 等待系统更新进程状态

        if not is_process_running(pid):
            console.print("[green]服务器已停止[/green]")
            cleanup_pid_file()
        else:
            console.print("[red]无法停止服务器[/red]")

    except (OSError, ProcessLookupError):
        console.print("[yellow]进程不存在[/yellow]")
        cleanup_pid_file()
    except Exception as e:
        console.print(f"[red]停止失败: {e}[/red]")


@cli.command()
def status() -> None:
    """查看服务器状态"""
    pid = load_pid()
    if not pid:
        console.print("[yellow]服务器未运行[/yellow]")
        return

    if is_process_running(pid):
        console.print(f"[green]服务器正在运行 (PID: {pid})[/green]")
        console.print(f"PID 文件: [cyan]{get_pid_file()}[/cyan]")
    else:
        console.print("[yellow]服务器未运行[/yellow]")
        console.print("[yellow]清理过期的 PID 文件...[/yellow]")
        cleanup_pid_file()


@cli.command()
def info() -> None:
    """显示版本信息"""
    console.print(Panel.fit(
        f"[bold blue]UProxier[/bold blue]\n"
        f"版本: [green]{get_version()}[/green]\n"
        f"作者: [yellow]{get_author()}[/yellow]\n\n"
        "基于 mitmproxy 实现的网络代理和抓包工具\n"
        "支持 HTTP/HTTPS 代理、规则配置、Web 界面",
        title="ℹ️ 版本信息"
    ))


@cli.command()
@click.option('--list', '-l', 'list_examples', is_flag=True, help='列出所有可用的示例')
@click.option('--show', '-s', 'example_name', help='显示指定示例的内容')
@click.option('--copy', '-c', 'copy_example', help='复制指定示例到当前目录')
@click.option('--readme', is_flag=True, help='显示示例说明文档')
def examples(list_examples: bool, example_name: Optional[str], copy_example: Optional[str], readme: bool) -> None:
    """管理规则示例"""
    try:
        if readme:
            readme_content = get_readme_content()
            if readme_content:
                console.print(Panel(readme_content, title="📚 规则示例说明"))
            else:
                console.print("[red]未找到示例说明文档[/red]")
            return

        if list_examples:
            _examples = get_examples()
            if not _examples:
                console.print("[yellow]未找到任何示例文件[/yellow]")
                return

            table = Table(title="📋 可用示例")
            table.add_column("文件名", style="cyan")
            table.add_column("描述", style="green")

            for example in _examples:
                table.add_row(example['filename'], example['description'])

            console.print(table)
            return

        if example_name:
            content = get_example_content(example_name)
            if content:
                console.print(Panel(content, title=f"📄 {example_name}"))
            else:
                console.print(f"[red]未找到示例文件: {example_name}[/red]")
            return

        if copy_example:
            content = get_example_content(copy_example)
            if not content:
                console.print(f"[red]未找到示例文件: {copy_example}[/red]")
                return

            target_path = Path(copy_example)
            if target_path.exists():
                if not Confirm.ask(f"文件 {copy_example} 已存在，是否覆盖？"):
                    return

            target_path.write_text(content, encoding='utf-8')
            console.print(f"[green]✓ 示例已复制到: {target_path.absolute()}[/green]")
            return

        console.print(Panel.fit(
            "[bold blue]规则示例管理[/bold blue]\n\n"
            "可用命令:\n"
            "• [cyan]uproxier examples --list[/cyan] - 列出所有示例\n"
            "• [cyan]uproxier examples --show <文件名>[/cyan] - 显示示例内容\n"
            "• [cyan]uproxier examples --copy <文件名>[/cyan] - 复制示例到当前目录\n"
            "• [cyan]uproxier examples --readme[/cyan] - 显示示例说明文档",
            title="📚 示例管理"
        ))

    except ImportError:
        console.print("[red]示例模块未找到，请检查安装[/red]")
    except Exception as e:
        console.print(f"[red]操作失败: {e}[/red]")


@cli.command()
@click.argument('config_file', type=click.Path(exists=True))
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text', help='输出格式')
@click.option('--output', type=click.Path(), help='输出文件路径（可选）')
@click.option('--validate-only', is_flag=True, help='只进行验证，不生成完整报告')
def validate(config_file: str, output_format: str, output: Optional[str], validate_only: bool) -> None:
    """验证和分析配置文件"""
    try:
        analyzer = ConfigAnalyzer(config_file)
        
        if validate_only:
            # 只进行验证
            if analyzer.is_valid():
                console.print("[green]✅ 配置验证通过[/green]")
            else:
                console.print("[red]❌ 配置验证失败[/red]")
                for error in analyzer.get_validation_errors():
                    console.print(f"[red]  ❌ {error}[/red]")
                for warning in analyzer.get_validation_warnings():
                    console.print(f"[yellow]  ⚠️  {warning}[/yellow]")
        else:
            # 生成完整报告
            report = analyzer.generate_report(output_format)
            
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(report)
                console.print(f"[green]报告已保存到: {output}[/green]")
            else:
                if output_format == 'json':
                    console.print_json(report)
                else:
                    console.print(report)
                    
    except Exception as e:
        console.print(f"[red]验证失败: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()

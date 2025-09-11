#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class CertificateManager:
    """证书管理器"""

    def __init__(self, cert_dir: str = str(Path.home() / ".uproxier"), silent: bool = False):
        self.cert_dir = Path(cert_dir).expanduser()
        self.silent = silent
        self.ca_cert_path = self.cert_dir / "mitmproxy-ca-cert.pem"
        self.ca_key_path = self.cert_dir / "mitmproxy-ca-key.pem"
        self.ca_combined_pem_path = self.cert_dir / "mitmproxy-ca.pem"
        self.ca_cert_der_path = self.cert_dir / "mitmproxy-ca-cert.der"

    def ensure_certificates(self):
        """确保证书存在，如果不存在则生成"""
        try:
            self.cert_dir.mkdir(exist_ok=True)

            if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
                if not self.silent:
                    logger.info("生成新的 CA 证书...")
                self.generate_ca_certificate()

            self.verify_certificate()
            try:
                self.convert_to_der()
                self._write_combined_pem()
                self._cleanup_extra_artifacts()
            except Exception as _:
                pass
        except Exception as e:
            if not self.silent:
                logger.error(f"证书管理失败: {e}")
            raise

    def generate_ca_certificate(self):
        """生成 CA 证书（优先使用 OpenSSL，避免 mitmproxy 内部 API 兼容性问题）"""
        try:
            self.generate_ca_certificate_with_openssl()
        except Exception:
            # 作为兜底，尝试 mitmproxy 的证书存储（不同版本 API 可能变化，不再首选）
            try:
                from mitmproxy.certs import CertStore
                cert_store = CertStore.from_store(str(self.cert_dir), "mitmproxy", 2048)
                if not self.ca_cert_path.exists():
                    with open(self.ca_cert_path, 'wb') as f:
                        # 新版本接口：default_ca.cert / default_ca.key → to_pem()
                        try:
                            f.write(cert_store.default_ca.cert.to_pem())
                        except Exception:
                            f.write(cert_store.default_ca.get_cert())
                if not self.ca_key_path.exists():
                    with open(self.ca_key_path, 'wb') as f:
                        try:
                            f.write(cert_store.default_ca.key.to_pem())
                        except Exception:
                            f.write(cert_store.default_ca.get_private_key())
                if not self.ca_cert_der_path.exists():
                    self.convert_to_der()
                if not self.silent:
                    logger.info("CA 证书生成成功")
            except Exception as e2:
                if not self.silent:
                    logger.error(f"生成 CA 证书失败(兜底也失败): {e2}")
                raise

    def generate_ca_certificate_with_openssl(self):
        """使用 OpenSSL 生成 CA 证书（备用方法）"""
        try:
            # 1) 生成私钥
            subprocess.run([
                'openssl', 'genrsa', '-out', str(self.ca_key_path), '2048'
            ], check=True, capture_output=True)

            # 2) 生成带 v3_ca 扩展的自签名根证书
            cnf_path = self.cert_dir / 'openssl_uproxier_ca.cnf'
            cnf_content = (
                "[ req ]\n"
                "default_bits = 2048\n"
                "distinguished_name = req_dn\n"
                "x509_extensions = v3_ca\n"
                "prompt = no\n"
                "[ req_dn ]\n"
                "C = CN\n"
                "ST = Beijing\n"
                "L = Beijing\n"
                "O = mitmproxy\n"
                "OU = mitmproxy\n"
                "CN = mitmproxy\n"
                "[ v3_ca ]\n"
                "basicConstraints = critical, CA:TRUE\n"
                "keyUsage = critical, keyCertSign, cRLSign\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always,issuer\n"
            )
            cnf_path.write_text(cnf_content, encoding='utf-8')

            subprocess.run([
                'openssl', 'req', '-new', '-x509', '-days', '3650',
                '-key', str(self.ca_key_path),
                '-out', str(self.ca_cert_path),
                '-config', str(cnf_path),
                '-extensions', 'v3_ca'
            ], check=True, capture_output=True)

            self.convert_to_der()

            if not self.silent:
                logger.info("使用 OpenSSL 生成 CA 证书成功")

        except subprocess.CalledProcessError as e:
            if not self.silent:
                logger.error(f"OpenSSL 命令执行失败: {e}")
            raise
        except FileNotFoundError:
            if not self.silent:
                logger.error("未找到 OpenSSL，请安装 OpenSSL")
            raise

    def convert_to_der(self):
        """将 PEM 证书转换为 DER 格式"""
        try:
            subprocess.run([
                'openssl', 'x509', '-inform', 'PEM', '-outform', 'DER',
                '-in', str(self.ca_cert_path),
                '-out', str(self.ca_cert_der_path)
            ], check=True, capture_output=True)

        except (subprocess.CalledProcessError, FileNotFoundError):
            if not self.silent:
                logger.warning("无法转换证书为 DER 格式")

    def _get_fingerprint(self, path: Path, is_der: bool) -> Optional[str]:
        try:
            args = ['openssl', 'x509', '-noout', '-fingerprint', '-sha256']
            if is_der:
                args += ['-inform', 'DER']
            args += ['-in', str(path)]
            res = subprocess.run(args, check=True, capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if 'Fingerprint=' in line:
                    return line.split('=', 1)[1].strip().replace(':', '')
        except Exception:
            return None
        return None

    def _force_sync_if_mismatch(self):
        """若检测到 PEM vs DER 指纹不一致，强制从 PEM 重建 DER。"""
        try:
            if not self.ca_cert_path.exists():
                return
            pem_fp = self._get_fingerprint(self.ca_cert_path, is_der=False)
            der_fp = self._get_fingerprint(self.ca_cert_der_path,
                                           is_der=True) if self.ca_cert_der_path.exists() else None
            if der_fp is None or pem_fp != der_fp:
                self.convert_to_der()
        except Exception as e:
            if not self.silent:
                logger.warning(f"指纹自检/修复失败: {e}")

    def _write_combined_pem(self):
        """生成 mitmproxy 习惯的合并 PEM（证书在前，私钥在后），方便其读取。"""
        try:
            if self.ca_cert_path.exists() and self.ca_key_path.exists():
                cert_bytes = Path(self.ca_cert_path).read_bytes()
                key_bytes = Path(self.ca_key_path).read_bytes()
                Path(self.ca_combined_pem_path).write_bytes(cert_bytes + b"\n" + key_bytes)
        except Exception as e:
            if not self.silent:
                logger.warning(f"写入合并 PEM 失败: {e}")

    def _cleanup_extra_artifacts(self):
        """删除非预期文件"""
        try:
            keep = {
                str(self.ca_cert_path),
                str(self.ca_key_path),
                str(self.ca_cert_der_path),
                str(self.ca_combined_pem_path),
                str(self.cert_dir / 'openssl_uproxier_ca.cnf'),
            }
            extra_candidates = [
                'mitmproxy-ca.p12',
                'mitmproxy-ca-cert.p12',
                'mitmproxy-dhparam.pem',
            ]
            for name in extra_candidates:
                p = self.cert_dir / name
                if str(p) not in keep and p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass
        except Exception as e:
            if not self.silent:
                logger.warning(f"清理多余证书产物失败: {e}")

    def verify_certificate(self):
        """验证证书有效性"""
        try:
            with open(self.ca_cert_path, 'r') as f:
                cert_data = f.read()

            ssl.PEM_cert_to_DER_cert(cert_data)

        except Exception as e:
            if not self.silent:
                logger.error(f"证书验证失败: {e}")
            raise

    def get_certificate_info(self) -> dict:
        """获取证书信息"""
        try:
            if not self.ca_cert_path.exists():
                return {"error": "证书不存在"}

            # 使用 OpenSSL 获取证书信息
            result = subprocess.run([
                'openssl', 'x509', '-in', str(self.ca_cert_path), '-text', '-noout'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                return {
                    "cert_path": str(self.ca_cert_path),
                    "key_path": str(self.ca_key_path),
                    "info": result.stdout
                }
            else:
                return {"error": "无法读取证书信息"}

        except Exception as e:
            return {"error": str(e)}

    def install_certificate(self, system: str = "auto"):
        """安装证书到系统"""
        if system == "auto":
            system = self.detect_system()

        try:
            if system == "macos":
                self.install_certificate_macos()
            elif system == "windows":
                self.install_certificate_windows()
            elif system == "linux":
                self.install_certificate_linux()
            else:
                if not self.silent:
                    logger.warning(f"不支持的系统: {system}")

        except Exception as e:
            if not self.silent:
                logger.error(f"安装证书失败: {e}")

    def detect_system(self) -> str:
        """检测操作系统"""
        if sys.platform == "darwin":
            return "macos"
        elif sys.platform == "win32":
            return "windows"
        elif sys.platform.startswith("linux"):
            return "linux"
        else:
            return "unknown"

    def install_certificate_macos(self):
        """在 macOS 上安装证书"""
        try:
            # 复制证书到系统证书目录
            cert_dest = Path.home() / "Library/Application Support/mitmproxy"
            cert_dest.mkdir(parents=True, exist_ok=True)

            # 使用 security 命令安装证书
            subprocess.run([
                'security', 'add-trusted-cert', '-d', '-r', 'trustRoot',
                '-k', str(Path.home() / "Library/Keychains/login.keychain"),
                str(self.ca_cert_path)
            ], check=True)

            if not self.silent:
                logger.info("证书已安装到 macOS 系统")

        except subprocess.CalledProcessError as e:
            if not self.silent:
                logger.error(f"macOS 证书安装失败: {e}")
            raise

    def install_certificate_windows(self):
        """在 Windows 上安装证书"""
        try:
            # 使用 certutil 安装证书
            subprocess.run([
                'certutil', '-addstore', '-f', 'ROOT', str(self.ca_cert_path)
            ], check=True)

            if not self.silent:
                logger.info("证书已安装到 Windows 系统")

        except subprocess.CalledProcessError as e:
            if not self.silent:
                logger.error(f"Windows 证书安装失败: {e}")
            raise

    def install_certificate_linux(self):
        """在 Linux 上安装证书"""
        try:
            # 复制证书到系统证书目录
            cert_dest = Path("/usr/local/share/ca-certificates/mitmproxy-ca.crt")
            cert_dest.parent.mkdir(parents=True, exist_ok=True)

            import shutil
            shutil.copy2(self.ca_cert_path, cert_dest)

            # 更新证书存储
            subprocess.run(['update-ca-certificates'], check=True)

            if not self.silent:
                logger.info("证书已安装到 Linux 系统")

        except Exception as e:
            if not self.silent:
                logger.error(f"Linux 证书安装失败: {e}")
            raise

    def get_installation_instructions(self) -> str:
        """获取证书安装说明"""
        system = self.detect_system()

        instructions = {
            "macos": f"""
在 macOS 上安装证书：

1. 双击证书文件: {self.ca_cert_path}
2. 在钥匙串访问中，找到 "mitmproxy" 证书
3. 双击证书，展开 "信任" 部分
4. 将 "使用此证书时" 设置为 "始终信任"
5. 关闭窗口并输入密码确认

或者使用命令行：
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain {self.ca_cert_path}
""",
            "windows": f"""
在 Windows 上安装证书：

1. 双击证书文件: {self.ca_cert_path}
2. 点击 "安装证书"
3. 选择 "本地计算机"
4. 选择 "将所有证书放入下列存储"
5. 点击 "浏览"，选择 "受信任的根证书颁发机构"
6. 点击 "确定" 完成安装

或者使用命令行：
certutil -addstore -f ROOT {self.ca_cert_path}
""",
            "linux": f"""
在 Linux 上安装证书：

1. 复制证书到系统目录：
   sudo cp {self.ca_cert_path} /usr/local/share/ca-certificates/mitmproxy-ca.crt

2. 更新证书存储：
   sudo update-ca-certificates

3. 重启浏览器或应用程序
""",
            "unknown": f"""
请手动安装证书：

证书文件位置: {self.ca_cert_path}

请根据您的操作系统查找相应的证书安装方法。
"""
        }

        return instructions.get(system, instructions["unknown"])

    def cleanup(self):
        """清理证书文件"""
        try:
            if self.ca_cert_path.exists():
                self.ca_cert_path.unlink()
            if self.ca_key_path.exists():
                self.ca_key_path.unlink()
            if self.ca_cert_der_path.exists():
                self.ca_cert_der_path.unlink()

            if not self.silent:
                logger.info("证书文件已清理")

        except Exception as e:
            if not self.silent:
                logger.error(f"清理证书文件失败: {e}")

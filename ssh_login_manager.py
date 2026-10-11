#!/usr/bin/env python3
"""SSHLoginManager —— 交互式 SSH 登录引导（基于 Paramiko）。

单一职责：**收集服务器信息 → 选择登录方式 → 建立连接**。
连接成功后把已就绪的 ``paramiko.SSHClient`` 交还给调用方，后续执行命令由调用方负责。

安全设计：
  * 密码/口令一律用 :func:`getpass.getpass` 读取，不回显、不落盘、不写日志；
    标准输入不是真实终端（管道 / cron / 部分 IDE 伪终端）时直接中止，
    绝不降级成明文输入；
  * 首次遇到未知主机密钥时，先展示 SHA256 指纹并要求二次确认；
  * 已知主机密钥不匹配时立即中止连接（防中间人攻击）；
  * 本机 known_hosts 按 OpenSSH 语义处理：``@revoked`` 命中的密钥一律拒绝
    （撤销规则解析不了就安全失败，绝不降级成"未知密钥"再让用户手动接受）；
    撤销/信任记录的主机名支持 OpenSSH 的匹配规则——逗号分隔、``!`` 否定项否决、
    只有 ``*`` 和 ``?`` 是通配符（``[abc]`` 按字面量处理）；
    ``@cert-authority`` 无法校验时会明确告知，而不是静默忽略安全语义；
  * 同时读取**系统级**信任库（``/etc/ssh/ssh_known_hosts``、
    ``%ProgramData%\\ssh\\ssh_known_hosts``），但只读不写；所有信任文件里的
    ``@revoked`` 规则统一汇总后再加载条目，避免"一个文件撤销、另一个文件信任"
    把撤销绕过去；信任文件存在却读不了时安全失败，而不是当成文件不存在；
  * 用户确认过的密钥只以 **追加一行** 的方式写入 ``~/.ssh/known_hosts``，
    不使用 ``paramiko.SSHClient.save_host_keys()``（它会用内存里的数据重写整个文件，
    抹掉 @cert-authority / @revoked 等它不认识的行）；
  * 不使用 ``paramiko.AutoAddPolicy`` 这类“无条件信任”的策略。

依赖：``pip install "paramiko>=5"``
（paramiko 4.0.0 存在 CVE-2026-44405，5.0.0 已修复；
 本模块在 Windows + Python 3.13 + paramiko 5.0.0 上验证）。

快速示例::

    from ssh_login_manager import SSHLoginManager

    with SSHLoginManager(port=None, username=None) as manager:   # 端口/用户名也交互询问
        client = manager.run()
        if client is not None:
            print(client.exec_command("whoami")[1].read().decode())
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import locale
import math
import os
import re
import socket
import sys
from contextlib import suppress
from getpass import getpass
from pathlib import Path
from typing import Callable, Final, Iterable, Mapping, NamedTuple, Sequence

import paramiko
from paramiko.hostkeys import HostKeyEntry, HostKeys
# NoValidConnectionsError 没有导出到 paramiko 顶层命名空间，必须从 ssh_exception 导入；
# 注意它在 paramiko 5 里继承自 OSError（不是 SSHException），所以 _report() 的分支顺序要留意。
from paramiko.ssh_exception import NoValidConnectionsError

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_PORT: Final[int] = 22
DEFAULT_USERNAME: Final[str] = "root"
MAX_ATTEMPTS: Final[int] = 3  # 最多允许的“选方式 + 连接”轮次

# 连接/认证超时的上限。实测 socket.settimeout() 在 1e9 秒以上会抛
# OverflowError: timestamp out of range for C PyTime_t，1 小时足够宽松又远低于该阈值。
MAX_TIMEOUT: Final[float] = 3600.0

# 菜单序号 -> 内部登录方式标识
LOGIN_METHODS: Final[dict[str, str]] = {"1": "password", "2": "key", "3": "auto"}

# 视为“确认”的回答（中英文都接受）
YES_ANSWERS: Final[frozenset[str]] = frozenset({"y", "yes", "是", "好", "确认", "确定"})

# 默认私钥文件名（按优先级）。不包含 id_dsa：DSA 已被 OpenSSH 弃用。
DEFAULT_KEY_NAMES: Final[tuple[str, ...]] = ("id_ed25519", "id_ecdsa", "id_rsa")

# 私钥解析顺序：先试最安全/最常见的算法，失败再换下一种。
KEY_TYPES: Final[tuple[type[paramiko.PKey], ...]] = (
    paramiko.Ed25519Key,
    paramiko.ECDSAKey,
    paramiko.RSAKey,
)


# ---------------------------------------------------------------------------
# 多语言文案：两份字典的键必须完全一致（见文件末尾的自检）
# ---------------------------------------------------------------------------

ZH: Final[dict[str, str]] = {
    "host_prompt": "请输入服务器IP地址（本机测试填127.0.0.1）：",
    "port_prompt": "请输入 SSH 端口（直接回车使用默认 {default}）：",
    "username_prompt": "请输入登录用户名（直接回车使用默认 {default}）：",
    "invalid_host": "❌ IP 地址不能为空，请重新输入。",
    "invalid_port": "❌ 端口必须是 1~65535 之间的整数，请重新输入。",
    "menu_title": "\n即将连接 {user}@{host}:{port}，请选择登录方式：",
    "menu_password": "  1. 密码登录（输入时不会显示任何字符）",
    "menu_key": "  2. SSH 密钥登录（自己指定私钥路径，支持 ~ 写法）",
    "menu_auto": "  3. 自动查找本机默认密钥（~/.ssh/id_ed25519 等）",
    "menu_prompt": "请输入选项序号 [1/2/3]：",
    "invalid_choice": "❌ 无效的选项，请输入 1、2 或 3。",
    "invalid_argument": (
        "❌ 构造参数不合法：{detail}\n"
        "   要求：host 为非空字符串（或 None 表示交互询问）、port 为 1~65535 的整数"
        "（或 None 表示交互询问）、username 为非空字符串（或 None）、"
        "timeout 为 0~{max_timeout} 之间的有限正数（不含 inf / nan）。"
    ),
    "password_prompt": "请输入密码（输入过程中不会显示任何字符）：",
    "not_interactive": "❌ 当前环境不是交互式终端，无法安全地读取密码，已中止。",
    "key_path_prompt": "请输入私钥文件路径（例如 ~/.ssh/id_ed25519）：",
    "key_path_required": "❌ 私钥路径不能为空，请重新输入。",
    "key_not_found": "❌ 找不到文件：{path}，请确认路径是否正确。",
    "key_permission_denied": (
        "❌ 没有权限读取私钥文件：{path}\n"
        "   Linux/macOS 可执行 chmod 600 {path}；Windows 请确认当前用户对该文件有读取权限。"
    ),
    "key_read_failed": "❌ 读取私钥文件失败：{path}（{detail}）",
    "key_passphrase_prompt": "私钥 {path} 已加密，请输入私钥口令（passphrase）：",
    "key_passphrase_wrong": "❌ 私钥口令错误，请重试。",
    "key_unreadable": (
        "❌ 无法解析私钥文件：{path}（格式不受支持，或口令始终不正确）。\n"
        "   请确认它是 OpenSSH/PEM 格式的私钥，而不是 .pub 公钥或 PuTTY 的 .ppk 文件。"
    ),
    "known_hosts_partial": (
        "⚠️ known_hosts 里有 {count} 行无法解析或含未知标记，"
        "已跳过这些行并继续加载其余记录。"
    ),
    "known_hosts_loaded": "🔑 已从 {path} 加载 {count} 条已知主机记录。",
    "known_hosts_read_failed": (
        "❌ 无法读取主机信任文件：{path}（{detail}）。\n"
        "   出于安全考虑已中止连接——读不了的信任文件不能被当成不存在。"
    ),
    "known_hosts_revoked_skipped": "🛑 known_hosts 里有 {count} 条记录命中 @revoked 撤销规则，已从信任库中剔除。",
    "known_hosts_revoked_unparsed": (
        "❌ known_hosts 第 {line} 行的 @revoked 规则无法解析，无法判断密钥是否已被撤销。\n"
        "   出于安全考虑已中止连接（宁可连不上，也不能放过已撤销的密钥）。\n"
        "   请手动检查该文件：{path}；若确认已无需要，可用 ssh-keygen -R <主机名或IP> 清理。"
    ),
    "known_hosts_ca_note": (
        "⚠️ known_hosts 里有 @cert-authority 行：paramiko 无法校验 CA 签发的主机证书，\n"
        "   所以这些主机的身份不会被自动信任，仍然会要求你逐个核对指纹。"
    ),
    "key_auto_found": "🔑 已找到本机默认密钥：{path}",
    "key_try_next": "⚠️ 密钥 {path} 无法使用，继续检查下一个候选文件。",
    "key_auto_missing": (
        "❌ 在 {directory} 下没有找到默认密钥（{names}）。\n"
        "   请改用选项 2 手动指定私钥路径；若还没有密钥，可先执行：ssh-keygen -t ed25519"
    ),
    "connecting": "\n⏳ 正在连接 {user}@{host}:{port} ...",
    "connected": "✅ 连接成功：{host}:{port}",
    "host_key_unknown": (
        "\n⚠️ 首次连接 {host}，未知主机密钥（{algorithm}），SHA256 指纹：\n"
        "   {fingerprint}\n"
        "   ⚠️ 看到指纹本身不能证明连接安全，必须通过可信渠道核对：\n"
        "     · 云服务商控制台里该实例的 SSH 主机密钥；\n"
        "     · 服务器管理员；或在服务器上直接执行：\n"
        "       ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub"
    ),
    "host_key_confirm": (
        "只有核对一致才输入 yes；核对不了或不一致，请直接回车拒绝：[y/N]："
    ),
    "host_key_revoked": (
        "❌ 服务器提供的密钥在 known_hosts 中被 @revoked 标记为已撤销，已拒绝连接。\n"
        "   这通常意味着该密钥曾泄露或被轮换。请先与服务器管理员确认新密钥，\n"
        "   再用 ssh-keygen -R <主机名或IP> 清理旧记录后重试。"
    ),
    "host_key_rejected": "用户拒绝信任该主机密钥。",
    "host_key_saved": "🔒 已把该主机密钥追加到 {path}，下次连接会自动比对。",
    "host_key_save_failed": (
        "⚠️ 无法把主机密钥写入 {path}：{detail}\n"
        "   本次连接仍然建立，但下次仍需重新核对指纹。"
    ),
    "err_auth": "❌ 认证失败：用户名、密码或密钥不正确。",
    "hint_auth": (
        "排错建议：\n"
        "  1. 确认用户名是否正确（本机测试通常是当前登录用户名，而不是 root）；\n"
        "  2. 用密码登录要求服务器开启 PasswordAuthentication yes；\n"
        "  3. 用密钥登录要求服务器 ~/.ssh/authorized_keys 中已写入对应的公钥；\n"
        "  4. 确认该账号没有被禁用或锁定。"
    ),
    "err_timeout": "❌ 连接超时（超过 {timeout} 秒没有响应）。",
    "hint_timeout": (
        "排错建议：请检查 IP 是否正确，或服务器防火墙是否放行端口；\n"
        "  1. 先 ping 或 telnet 目标 IP:端口，确认网络可达；\n"
        "  2. 云服务器还需检查安全组 / 网络 ACL 是否放行该端口；\n"
        "  3. 如果连接的是本机 127.0.0.1，请确认系统已开启 SSH 服务；\n"
        "     Linux: sudo systemctl start sshd；Windows: 启动 OpenSSH Server 服务；\n"
        "  4. 确认端口号是否正确（默认 22）。"
    ),
    "err_unknown_host": "❌ 无法解析主机名：{detail}",
    "hint_unknown_host": "排错建议：检查主机名是否拼写错误，或直接改用 IP 地址。",
    "err_refused": "❌ 目标主机拒绝连接（端口未开放或被主动拒绝）。",
    "hint_refused": (
        "排错建议：确认该端口上确实有 SSH 服务在监听；\n"
        "  本机测试请先安装并启动 OpenSSH Server（Windows: 可选功能里添加）。"
    ),
    "err_no_valid_conn": "❌ 所有地址均连接失败（IP 不可达、端口被防火墙拦截，或云安全组未放行）。",
    "hint_no_valid_conn": (
        "排错建议：\n"
        "  1. 确认 IP/域名拼写正确，且服务器确实在运行；\n"
        "  2. 检查服务器防火墙（iptables / ufw / Windows 防火墙）是否放行该端口；\n"
        "  3. 云服务器请检查安全组、网络 ACL 规则；\n"
        "  4. 目标是本机时，也要确认 SSH 服务已启动（127.0.0.1 同理）。"
    ),
    "err_host_key_mismatch": "⚠️ 主机密钥与 known_hosts 中的记录不一致，出于安全考虑已中止连接。",
    "hint_host_key_mismatch": (
        "处理建议：这可能是中间人攻击，也可能是服务器重装/更换了密钥。\n"
        "  请先与管理员核对指纹；确认无误后删除旧记录再重连：ssh-keygen -R <主机名或IP>"
    ),
    "err_protocol": "❌ SSH 协议错误：{detail}",
    "hint_protocol": (
        "排错建议：确认该端口上跑的确实是 SSH 服务（而不是 Web/数据库端口）；\n"
        "  必要时用 ssh -v user@host 查看握手细节以定位问题。"
    ),
    "err_generic": "❌ 出现未预期的错误：{detail}",
    "hint_generic": "排错建议：确认已安装 paramiko（pip install paramiko），并检查网络与服务端状态。",
    "retry_prompt": "是否重试？[y/N]：",
    "give_up": "\n已退出登录流程。",
    "cancelled": "\n⏹️ 已取消操作。",
}

EN: Final[dict[str, str]] = {
    "host_prompt": "Please enter the server IP address (use 127.0.0.1 for local testing): ",
    "port_prompt": "Please enter the SSH port (press Enter for default {default}): ",
    "username_prompt": "Please enter the login username (press Enter for default {default}): ",
    "invalid_host": "❌ The IP address cannot be empty. Please try again.",
    "invalid_port": "❌ The port must be an integer between 1 and 65535. Please try again.",
    "menu_title": "\nConnecting to {user}@{host}:{port}. Choose a login method:",
    "menu_password": "  1. Password login (input is never displayed)",
    "menu_key": "  2. SSH key login (you provide the private key path, ~ is supported)",
    "menu_auto": "  3. Auto-discover the local default key (~/.ssh/id_ed25519, ...)",
    "menu_prompt": "Enter the option number [1/2/3]: ",
    "invalid_choice": "❌ Invalid option. Please enter 1, 2 or 3.",
    "invalid_argument": (
        "❌ Invalid constructor argument: {detail}\n"
        "   Expected: host a non-empty string (or None to prompt), port an integer in "
        "1~65535 (or None to prompt), username a non-empty string (or None), timeout a "
        "finite positive number in 0~{max_timeout} (no inf / nan)."
    ),
    "password_prompt": "Please enter the password (nothing will be displayed): ",
    "not_interactive": (
        "❌ This environment is not an interactive terminal, so the password cannot be "
        "read safely. Aborted."
    ),
    "key_path_prompt": "Please enter the private key path (e.g. ~/.ssh/id_ed25519): ",
    "key_path_required": "❌ The private key path cannot be empty. Please try again.",
    "key_not_found": "❌ File not found: {path}. Please check the path.",
    "key_permission_denied": (
        "❌ Permission denied while reading the private key: {path}\n"
        "   On Linux/macOS run chmod 600 {path}; on Windows make sure your account can "
        "read the file."
    ),
    "key_read_failed": "❌ Could not read the private key file: {path} ({detail})",
    "key_passphrase_prompt": "The private key {path} is encrypted. Please enter its passphrase: ",
    "key_passphrase_wrong": "❌ Wrong passphrase. Please try again.",
    "key_unreadable": (
        "❌ Cannot parse the private key file: {path} (unsupported format, or the "
        "passphrase was never correct).\n"
        "   Make sure it is an OpenSSH/PEM private key, not a .pub public key or a "
        "PuTTY .ppk file."
    ),
    "known_hosts_partial": (
        "⚠️ {count} line(s) in known_hosts cannot be parsed or hold unknown markers; "
        "they were skipped and the rest was loaded."
    ),
    "known_hosts_loaded": "🔑 Loaded {count} known host entries from {path}.",
    "known_hosts_read_failed": (
        "❌ Could not read host trust file: {path} ({detail}).\n"
        "   Aborted for safety: a trust file that cannot be read must not be treated "
        "as absent."
    ),
    "known_hosts_revoked_skipped": (
        "🛑 {count} known_hosts entr(ies) matched a @revoked rule and were removed from "
        "the trust store."
    ),
    "known_hosts_revoked_unparsed": (
        "❌ The @revoked rule on line {line} of known_hosts cannot be parsed, so it is "
        "impossible to tell whether a key was revoked.\n"
        "   The connection was aborted for safety (failing closed beats trusting a "
        "revoked key).\n"
        "   Inspect the file manually: {path}; if it is obsolete, clean it with "
        "ssh-keygen -R <host>."
    ),
    "known_hosts_ca_note": (
        "⚠️ known_hosts contains @cert-authority lines: paramiko cannot validate "
        "CA-signed host certificates,\n"
        "   so those hosts are not trusted automatically and you will still be asked to "
        "verify each fingerprint."
    ),
    "key_auto_found": "🔑 Local default key found: {path}",
    "key_try_next": "⚠️ Key {path} is unusable; checking the next candidate.",
    "key_auto_missing": (
        "❌ No default key ({names}) found under {directory}.\n"
        "   Use option 2 to provide a private key path, or create one with: "
        "ssh-keygen -t ed25519"
    ),
    "connecting": "\n⏳ Connecting to {user}@{host}:{port} ...",
    "connected": "✅ Connected: {host}:{port}",
    "host_key_unknown": (
        "\n⚠️ First connection to {host}. Unknown host key ({algorithm}), SHA256 fingerprint:\n"
        "   {fingerprint}\n"
        "   ⚠️ Seeing a fingerprint does not prove the connection is safe; verify it "
        "through a trusted channel:\n"
        "     - the host key shown for this instance in your cloud provider console;\n"
        "     - the server administrator; or directly on the server:\n"
        "       ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub"
    ),
    "host_key_confirm": (
        "Type yes only if it matches; if you cannot verify it or it differs, press "
        "Enter to reject: [y/N]: "
    ),
    "host_key_revoked": (
        "❌ The key offered by the server is marked @revoked in known_hosts; the "
        "connection was refused.\n"
        "   This usually means the key leaked or was rotated. Confirm the new key with "
        "the server administrator,\n"
        "   then clean the stale record with ssh-keygen -R <host> and retry."
    ),
    "host_key_rejected": "The user rejected the host key.",
    "host_key_saved": (
        "🔒 The host key was appended to {path}; the next connection verifies it "
        "automatically."
    ),
    "host_key_save_failed": (
        "⚠️ Could not write the host key to {path}: {detail}\n"
        "   The connection stays up, but the fingerprint must be verified again next time."
    ),
    "err_auth": "❌ Authentication failed: wrong username, password or key.",
    "hint_auth": (
        "Troubleshooting:\n"
        "  1. Check the username (for local testing it is usually your own account, "
        "not root);\n"
        "  2. Password login requires PasswordAuthentication yes on the server;\n"
        "  3. Key login requires the matching public key in the server's "
        "~/.ssh/authorized_keys;\n"
        "  4. Make sure the account is not disabled or locked."
    ),
    "err_timeout": "❌ Connection timed out (no response within {timeout} seconds).",
    "hint_timeout": (
        "Troubleshooting: check whether the IP is correct and whether the server "
        "firewall allows the port;\n"
        "  1. Ping or telnet the target IP:port to confirm reachability;\n"
        "  2. On cloud servers also check the security group / network ACL;\n"
        "  3. If you are connecting to 127.0.0.1, make sure the SSH service is "
        "running on this machine:\n"
        "     Linux: sudo systemctl start sshd; Windows: start the OpenSSH Server "
        "service;\n"
        "  4. Confirm the port number (default 22)."
    ),
    "err_unknown_host": "❌ Cannot resolve the host name: {detail}",
    "hint_unknown_host": "Troubleshooting: check the spelling, or use the IP address directly.",
    "err_refused": "❌ The target host refused the connection (port closed or rejected).",
    "hint_refused": (
        "Troubleshooting: confirm an SSH service is listening on that port;\n"
        "  for local testing install and start OpenSSH Server first."
    ),
    "err_no_valid_conn": (
        "❌ All addresses failed to connect (unreachable IP, port blocked by a firewall, "
        "or a restrictive cloud security group)."
    ),
    "hint_no_valid_conn": (
        "Troubleshooting:\n"
        "  1. Check the IP/host name spelling and that the server is running;\n"
        "  2. Check the server firewall (iptables / ufw / Windows Firewall) for this port;\n"
        "  3. On cloud servers check the security group and network ACL rules;\n"
        "  4. For a local target, make sure the SSH service is running (including 127.0.0.1)."
    ),
    "err_host_key_mismatch": (
        "⚠️ The host key does not match the known_hosts record; the connection was "
        "aborted for safety."
    ),
    "hint_host_key_mismatch": (
        "What to do: this may be a man-in-the-middle attack, or the server was "
        "rebuilt and has a new key.\n"
        "  Verify the fingerprint with the administrator first, then remove the old "
        "record and reconnect: ssh-keygen -R <host>"
    ),
    "err_protocol": "❌ SSH protocol error: {detail}",
    "hint_protocol": (
        "Troubleshooting: make sure the port really serves SSH (not HTTP/MySQL);\n"
        "  use ssh -v user@host to inspect the handshake when needed."
    ),
    "err_generic": "❌ Unexpected error: {detail}",
    "hint_generic": (
        "Troubleshooting: make sure paramiko is installed (pip install paramiko) and "
        "check the network and the server side."
    ),
    "retry_prompt": "Retry? [y/N]: ",
    "give_up": "\nLogin flow aborted.",
    "cancelled": "\n⏹️ Cancelled.",
}

MESSAGES: Final[dict[str, Mapping[str, str]]] = {"zh": ZH, "en": EN}


def _check_translations() -> None:
    """导入即自检：两份文案的键必须一致，避免线上 KeyError。"""
    if ZH.keys() != EN.keys():
        raise RuntimeError(f"i18n keys mismatch: {sorted(set(ZH) ^ set(EN))}")


_check_translations()


# ---------------------------------------------------------------------------
# 语言环境检测
# ---------------------------------------------------------------------------


def _language_from_locale(name: str) -> str | None:
    """把各种 locale 写法（zh_CN.UTF-8 / Chinese (Simplified)_China / en_US）归一化。"""
    lowered = name.strip().lower()
    if not lowered or lowered in {"c", "posix", "c.utf-8", "c.utf8"}:
        return None  # 无法判断，交给下一个来源
    if lowered.startswith(("zh", "chinese", "chi")) or "china" in lowered:
        return "zh"
    return "en"


def _windows_ui_language() -> str:
    """Windows 上 locale.getlocale() 可能返回 'C'，此时退回系统 UI 语言。"""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        langid: int = kernel32.GetUserDefaultUILanguage()
    except (AttributeError, OSError):
        return ""
    return "zh" if (langid & 0x3FF) == 0x04 else "en"  # 0x04 = 中文主语言 ID


def detect_language() -> str:
    """返回 ``"zh"`` 或 ``"en"``：优先环境变量，其次系统 locale，最后 Windows UI 语言。"""
    for variable in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        value = os.environ.get(variable)
        if value:
            detected = _language_from_locale(value)
            if detected is not None:
                return detected

    try:
        raw_locale = locale.getlocale()[0] or ""
    except (ValueError, TypeError):
        raw_locale = ""

    for candidate in (raw_locale, _windows_ui_language()):
        detected = _language_from_locale(candidate)
        if detected is not None:
            return detected
    return "en"


# ---------------------------------------------------------------------------
# 读取密码前的终端检查
# ---------------------------------------------------------------------------


# 【修复 2】getpass 在没有真实终端时会静默降级成普通 input，密码会明文上屏。
# 这里提供一个可单独替换的判断函数（便于测试注入），并在 _read_secret() 里硬性拦截：
# 不是真实终端就抛异常中止，绝不降级。
class NotInteractiveTerminalError(RuntimeError):
    """标准输入不是交互式终端，无法安全地隐藏密码或口令。"""


def _is_interactive_terminal() -> bool:
    """标准输入是否为真实终端（管道、重定向、cron、部分 IDE 伪终端都会返回 False）。"""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


# ---------------------------------------------------------------------------
# 主机密钥指纹与“未知主机”确认策略
# ---------------------------------------------------------------------------


def _fingerprint(key: paramiko.PKey) -> str:
    """按 OpenSSH 现代格式计算 SHA256 指纹，便于与服务器端 ssh-keygen -lf 对照。"""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _glob_to_regex(pattern: str) -> str:
    """把 OpenSSH 的通配翻译成正则：只有 ``*`` 和 ``?`` 是元字符，其余按字面量。"""
    return "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    )


def _hostname_matches(pattern: str, hostname: str) -> bool:
    """**单个**模式是否命中主机名：精确、哈希（|1|salt|hash）、或 OpenSSH 通配。

    【评审 7】不用 fnmatch：它把 ``[abc]`` 当字符类，而 OpenSSH 的 match_pattern()
    只认 ``*`` 和 ``?``，``[`` 是普通字符。用 fnmatch 会比 OpenSSH 匹配得更宽，
    对撤销规则来说就是"多撤销了一批主机"。这里自己翻译成正则，语义与 OpenSSH 对齐。
    注意：这只是"单模式"判断，逗号列表和 ``!`` 否定要由 _pattern_list_matches() 处理。
    """
    if pattern == hostname:
        return True
    if pattern.startswith("|1|"):
        if hostname.startswith("|1|"):
            return False
        try:
            return HostKeys.hash_host(hostname, pattern) == pattern
        except (ValueError, TypeError, AssertionError):
            return False  # 模式本身畸形，交给 _pattern_is_usable() 在解析阶段拦掉
    if "*" in pattern or "?" in pattern:
        return re.fullmatch(_glob_to_regex(pattern), hostname) is not None
    return False


def _pattern_list_matches(patterns: Iterable[str], hostname: str) -> bool:
    """按 OpenSSH ``match_pattern_list()`` 的语义判断主机名是否命中一组模式。

    【评审 7】OpenSSH 的规则是：
      * 模式之间用逗号分隔（paramiko 已经把主机名字段拆成列表，这里再拆一次兜底）；
      * 以 ``!`` 开头的是否定项，一旦命中就整体判为 **不匹配**（veto）；
      * 至少要有一个非否定项命中；只有否定项的列表对任何主机都不匹配。
    不实现否定语义的后果不是"漏撤销"，而是反过来：管理员用 ``!host`` 明确排除的主机
    仍会被当成已撤销而拒绝连接（可用性问题），所以照样要修。
    """
    positive = False
    for item in patterns:
        for token in str(item).split(","):
            token = token.strip()
            if not token:
                continue
            if token.startswith("!"):
                if _hostname_matches(token[1:], hostname):
                    return False  # 否定项命中 -> 整体不匹配
                continue
            if _hostname_matches(token, hostname):
                positive = True
    return positive


def _pattern_is_usable(pattern: str) -> bool:
    """校验哈希形式主机名（``|1|<base64 salt>|<base64 hash>``）能不能可靠求值。

    【GPT 评审 5】只校验"格式合法 + 这台机器上算得出来"，**不比较哈希值**：
    换一个测试主机名重新哈希，结果必然与原记录不同，若用 `== 原记录` 来判断，
    合法的哈希撤销记录也会被误判为不可用，从而把正常连接一起拒掉。
    至于"是不是当前这台主机"，由 _hostname_matches() 用真实主机名判断。
    """
    if pattern.startswith("!"):  # 否定项：真正要校验的是它后面那个模式
        pattern = pattern[1:]
    if not pattern.startswith("|1|"):
        return bool(pattern)
    parts = pattern.split("|")
    if len(parts) != 4 or parts[1] != "1":
        return False
    try:
        # OpenSSH 的 |1| 格式固定是 HMAC-SHA1：盐与摘要各 20 字节
        salt = base64.b64decode(parts[2], validate=True)
        digest = base64.b64decode(parts[3], validate=True)
        # 再确认本机确实能算出这种哈希（SHA-1 被禁用等极端环境下要安全失败）
        HostKeys.hash_host("format-check.invalid", pattern)
    except (ValueError, TypeError, AssertionError):
        return False
    return len(salt) == 20 and len(digest) == 20


def _is_positive_finite_number(value: object) -> bool:
    """是否为有限正数（拒绝 bool、inf、nan，以及大到转不成 float 的超大整数）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        number = float(value)
    except OverflowError:
        return False
    return math.isfinite(number) and number > 0


def _same_key(left: paramiko.PKey, right: paramiko.PKey) -> bool:
    """两把公钥是否是同一把（类型 + 公钥内容）。"""
    return left.get_name() == right.get_name() and left.asbytes() == right.asbytes()


def _key_is_revoked(
    revoked: Sequence[tuple[Sequence[str], paramiko.PKey]],
    hostnames: Iterable[str],
    key: paramiko.PKey,
) -> bool:
    """判断某把主机密钥是否命中撤销列表：同一把密钥，且主机名命中某条模式列表。

    ``revoked`` 的每一项是 ``(patterns, key)``：patterns 是 **同一条撤销记录** 里的
    模式列表（保留分组，否定项才生效）。
    """
    return any(
        _same_key(revoked_key, key)
        and any(_pattern_list_matches(patterns, host) for host in hostnames)
        for patterns, revoked_key in revoked
    )


class HostKeyRejectedError(paramiko.SSHException):
    """用户主动拒绝信任未知主机密钥——是“主动中止”，而非协议故障。"""


class HostKeyRevokedError(paramiko.SSHException):
    """密钥被 known_hosts 的 @revoked 撤销，或撤销规则无法解析（安全失败）。"""


class KnownHostsReadError(paramiko.SSHException):
    """信任文件存在却读不了（权限、被占用等）。不能当成"文件不存在"放过去。"""


class _ConfirmUnknownHostKey(paramiko.MissingHostKeyPolicy):
    """未知主机密钥时显示指纹并让用户确认，而不是像 AutoAddPolicy 那样无条件信任。"""

    def __init__(
        self,
        text: Mapping[str, str],
        revoked: Sequence[tuple[Sequence[str], paramiko.PKey]] = (),
        ask: Callable[[str], str] | None = None,
    ) -> None:
        self._text = text
        self._ask = ask
        # 【GPT 评审 1】撤销列表：命中就要无条件拒绝，绝不给用户"手动接受"的机会。
        self._revoked = tuple(revoked)
        # 【修复 1】记录用户"刚刚确认过"的主机密钥，供 _connect() 在握手成功后落盘。
        # 只放在内存里的话，进程一退就丢，和文案承诺的"写入本机 known_hosts"不一致。
        # 值形如 ("[127.0.0.1]:2222", <PKey>)，None 表示这次没有新确认的密钥。
        self._accepted: tuple[str, paramiko.PKey] | None = None

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        # 【GPT 评审 1】@revoked 优先于一切：先判撤销，再谈"未知密钥要不要信任"。
        if _key_is_revoked(self._revoked, (hostname,), key):
            raise HostKeyRevokedError(self._text["host_key_revoked"])

        message = self._text["host_key_unknown"].format(
            host=hostname,
            algorithm=key.get_name(),
            fingerprint=_fingerprint(key),
        )
        ask = self._ask or input  # 运行时解析，便于测试注入或整体替换
        # 【GPT 评审 3】指纹与核对要求用 print 输出，而不是塞进 input() 的提示串：
        # 它内容更长、更该被认真读到，也不该因为输出被重定向/记日志就消失，
        # 或者被用户当成"不过是在问一句 y/n"。
        print(message)
        answer = ask(self._text["host_key_confirm"])
        if answer.strip().lower() not in YES_ANSWERS:
            raise HostKeyRejectedError(self._text["host_key_rejected"])
        client.get_host_keys().add(hostname, key.get_name(), key)
        self._accepted = (hostname, key)  # 内存里先信任，握手成功后再追加到 known_hosts


class Credentials(NamedTuple):
    """一次连接尝试所需的认证材料，二者只会有一个非空。"""

    password: str | None = None
    pkey: paramiko.PKey | None = None


# ---------------------------------------------------------------------------
# 主角：SSHLoginManager
# ---------------------------------------------------------------------------


class SSHLoginManager:
    """引导用户输入服务器信息、选择登录方式并建立 SSH 连接。

    参数
    ----
    host:
        服务器地址；传 ``None`` 时交互式询问（默认提示语为
        “请输入服务器IP地址（本机测试填127.0.0.1）”）。
    port:
        SSH 端口，默认 22；传 ``None`` 时交互式询问（回车即用默认值）。
    username:
        登录用户名，默认 ``"root"``；传 ``None`` 时交互式询问。
    timeout:
        连接/认证超时秒数，默认 10 秒；必须是 (0, 3600] 之间的有限正数
        （``inf`` / ``nan`` / 超大值会被 :class:`ValueError` 拒绝，它们在
        socket 层会抛 OverflowError）。
    lang:
        强制语言（``"zh"`` 或 ``"en"``）；默认按系统语言环境自动检测。

    参数不合法（端口越界、host/username 非字符串、timeout 非正数等）时会在构造阶段
    抛 :class:`ValueError`，而不是拖到连接时才炸：这些值最终会落到 socket 层，
    端口越界在 Windows 上会被静默回绕到别的端口，timeout<=0 则抛 ValueError，
    都不在 run() 的捕获范围内。

    用法::

        manager = SSHLoginManager()          # 询问 IP，端口 22，用户 root
        client = manager.run()               # 返回已连接的 SSHClient，失败返回 None
        ...
        manager.close()                      # 或使用 with 语句自动关闭
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = DEFAULT_PORT,
        username: str | None = DEFAULT_USERNAME,
        *,
        timeout: float = 10.0,
        lang: str | None = None,
    ) -> None:
        self.lang = lang if lang in MESSAGES else detect_language()
        self.text: Mapping[str, str] = MESSAGES[self.lang]
        # 【GPT 评审 4】显式传入的参数先在边界上校验，非法值立刻报错（快速失败），
        # 避免拖到 socket 层才抛 OverflowError / ValueError 这类 run() 兜不住的异常。
        self._validate_arguments(host, port, username, timeout)
        self.timeout = timeout
        self.host = host if host is not None else self._ask_host()
        self.port = port if port is not None else self._ask_port()
        self.username = username if username is not None else self._ask_username()
        self.client: paramiko.SSHClient | None = None
        # 【修复 1】落盘目标：用户级 known_hosts。只做"追加一行"，不重写整个文件。
        self.known_hosts_path = Path.home() / ".ssh" / "known_hosts"
        # 【GPT 评审 1】撤销列表：加载 known_hosts 时填充，握手时用于硬性拒绝。
        # 每项是 (模式列表, 密钥)：列表里可能含 "!" 否定项，所以必须整组保存
        self._revoked: tuple[tuple[tuple[str, ...], paramiko.PKey], ...] = ()

    def _validate_arguments(
        self,
        host: str | None,
        port: int | None,
        username: str | None,
        timeout: float,
    ) -> None:
        """校验构造参数；非法值抛带双语说明的 ValueError。

        【GPT 评审 4】为什么要在这里拦：
          * ``timeout=-1`` 会让 socket 抛 ``ValueError: Timeout value out of range``，
            该异常不在 run() 捕获的类型里，用户看到的是裸 traceback；
          * ``port=99999`` 在 Windows 上不会报错，而是被静默回绕成 34463 去连接，
            等于连到了一台没打算连的端口；
          * ``port="abc"`` 虽然最终也会失败，但会被误报成"无法解析主机名"。
        ``None`` 是合法值，含义是"交给交互式询问"，由 _ask_* 系列做同样的范围校验。
        """
        rules: tuple[tuple[str, object, bool], ...] = (
            ("host", host, isinstance(host, str) and bool(host.strip())),
            (
                "port",
                port,
                not isinstance(port, bool)
                and isinstance(port, int)
                and 1 <= port <= 65535,
            ),
            ("username", username, isinstance(username, str) and bool(username.strip())),
            # 【GPT 评审 5】timeout 只判 "> 0" 不够：inf 和 1e9 以上的数值都能通过，
            # 真正落到 socket.settimeout() 时才抛 OverflowError，而它不在 run() 的
            # 捕获范围内。这里要求"有限正数且不超过 MAX_TIMEOUT"。
            (
                "timeout",
                timeout,
                _is_positive_finite_number(timeout) and timeout <= MAX_TIMEOUT,
            ),
        )
        for name, value, valid in rules:
            if value is not None and not valid:
                raise ValueError(
                    self.text["invalid_argument"].format(
                        detail=f"{name}={value!r}", max_timeout=f"{MAX_TIMEOUT:g}"
                    )
                )

    # -- 交互式收集服务器信息 ------------------------------------------------

    def _ask_host(self) -> str:
        while True:
            value = input(self.text["host_prompt"]).strip()
            if value:
                return value
            print(self.text["invalid_host"])

    def _ask_port(self) -> int:
        while True:
            raw = input(self.text["port_prompt"].format(default=DEFAULT_PORT)).strip()
            if not raw:
                return DEFAULT_PORT
            # 【修复 4】不能再用 raw.isdigit()：它对 '²' 这类 Unicode 上标数字也返回 True，
            # 但 int('²') 会抛 ValueError，异常会直接逃出 run() 把整个流程打断。
            # 改成先 int() 再判范围，任何非数字输入都走同一条双语错误提示。
            try:
                port = int(raw)
            except ValueError:
                print(self.text["invalid_port"])
                continue
            if 1 <= port <= 65535:
                return port
            print(self.text["invalid_port"])

    def _ask_username(self) -> str:
        value = input(self.text["username_prompt"].format(default=DEFAULT_USERNAME)).strip()
        return value or DEFAULT_USERNAME  # 直接回车即使用默认用户名

    # -- 选择登录方式 --------------------------------------------------------

    def choose_method(self) -> str:
        """询问登录方式，返回 ``"password"`` / ``"key"`` / ``"auto"``。"""
        print(
            self.text["menu_title"].format(
                user=self.username, host=self.host, port=self.port
            )
        )
        print(self.text["menu_password"])
        print(self.text["menu_key"])
        print(self.text["menu_auto"])
        while True:
            choice = input(self.text["menu_prompt"]).strip()
            if choice in LOGIN_METHODS:
                return LOGIN_METHODS[choice]
            print(self.text["invalid_choice"])

    # -- 把“方式”变成“认证材料” ---------------------------------------------

    def _resolve_credentials(self, method: str) -> Credentials | None:
        """返回本次尝试要用的认证材料；返回 ``None`` 表示本地准备失败，需重选方式。"""
        if method == "password":
            return Credentials(password=self._read_secret(self.text["password_prompt"]))
        if method == "key":
            return self._key_credentials()
        return self._auto_credentials()

    def _read_secret(self, prompt: str) -> str:
        """安全读取密码/口令，唯一入口。

        【修复 2】管道、cron、部分 IDE 伪终端下 getpass 会静默 fallback 到普通 input，
        密码就会明文上屏并被 shell 记录。所以先确认标准输入是真实终端；
        不是就直接抛 NotInteractiveTerminalError（由 run() 统一友好提示并中止），
        绝不退化成明文输入。
        """
        if not _is_interactive_terminal():
            raise NotInteractiveTerminalError(self.text["not_interactive"])
        return getpass(prompt)

    def _key_credentials(self) -> Credentials | None:
        """让用户指定私钥路径，自动展开 ~ 并处理带口令的私钥。"""
        while True:
            raw = input(self.text["key_path_prompt"]).strip().strip("'\"")
            if not raw:
                print(self.text["key_path_required"])
                continue
            path = Path(raw).expanduser()  # ~ 展开为绝对路径
            if not path.is_file():
                print(self.text["key_not_found"].format(path=path))
                continue
            pkey = self._load_key(path)
            return Credentials(pkey=pkey) if pkey is not None else None

    def _auto_credentials(self) -> Credentials | None:
        """在 ~/.ssh 下按优先级寻找默认私钥。"""
        ssh_dir = Path.home() / ".ssh"
        for name in DEFAULT_KEY_NAMES:
            candidate = ssh_dir / name
            if not candidate.is_file():
                continue
            print(self.text["key_auto_found"].format(path=candidate))
            pkey = self._load_key(candidate)
            if pkey is not None:
                return Credentials(pkey=pkey)
            print(self.text["key_try_next"].format(path=candidate))
        print(
            self.text["key_auto_missing"].format(
                directory=ssh_dir, names=" / ".join(DEFAULT_KEY_NAMES)
            )
        )
        return None

    def _load_key(self, path: Path) -> paramiko.PKey | None:
        """尝试各种算法解析私钥；失败时打印原因并返回 ``None``。

        【GPT 评审 2】把失败原因分开报，不用一个宽泛的 except 糊在一起：
          * 打不开文件（权限不足、是目录、被占用）-> key_permission_denied / key_read_failed
          * 需要口令 -> 交给 _load_encrypted_key()，它自己区分口令错误并允许重试
          * 算法或格式不匹配 -> 换下一种算法继续试，全部失败才报"无法解析"
        自己先 open() 再交给 paramiko 解析，是为了让"权限问题"和"格式问题"
        在报错上能区分开——file_exists 不等于 file_readable。

        注意必须用**文本模式**打开：paramiko 的 from_private_key() 内部是用 str 正则
        去匹配 "-----BEGIN ... KEY-----" 的，传二进制句柄会抛
        TypeError: cannot use a string pattern on a bytes-like object。
        """
        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except PermissionError:
            print(self.text["key_permission_denied"].format(path=path))
            return None
        except OSError as error:
            print(self.text["key_read_failed"].format(path=path, detail=error))
            return None

        with handle:
            for key_type in KEY_TYPES:
                try:
                    handle.seek(0)  # 换算法重试时要回到文件开头
                    return key_type.from_private_key(handle)
                except paramiko.PasswordRequiredException:
                    return self._load_encrypted_key(key_type, path)
                except (paramiko.SSHException, ValueError):
                    # SSHException：算法不匹配或格式不符；ValueError：cryptography
                    # 对某些畸形密钥会抛它，paramiko 并不包装，所以必须一并兜住。
                    continue
        print(self.text["key_unreadable"].format(path=path))
        return None

    def _load_encrypted_key(
        self, key_type: type[paramiko.PKey], path: Path
    ) -> paramiko.PKey | None:
        """带口令的私钥：用 getpass 读取口令，最多重试两次。"""
        for _ in range(2):
            # 【修复 2】私钥口令同样走 _read_secret()，非交互终端一律拒绝，不降级。
            passphrase = self._read_secret(
                self.text["key_passphrase_prompt"].format(path=path)
            )
            try:
                return key_type.from_private_key_file(str(path), password=passphrase)
            except paramiko.SSHException:
                print(self.text["key_passphrase_wrong"])
        print(self.text["key_unreadable"].format(path=path))
        return None

    # -- 建立连接 ------------------------------------------------------------

    def _system_known_hosts_paths(self) -> tuple[Path, ...]:
        """返回常见的**系统级**主机信任文件路径（只读，不写入）。

        【评审 6】OpenSSH 除了用户自己的 ~/.ssh/known_hosts，还会读系统级信任库：
        Linux/macOS 是 /etc/ssh/ssh_known_hosts，Windows OpenSSH 是
        %ProgramData%\\ssh\\ssh_known_hosts。管理员在这里统一维护的主机密钥
        （以及撤销规则）如果被忽略，就等于把集中管理的信任策略架空。
        注意只读这些文件：用户新确认的密钥仍然只追加到自己的 ~/.ssh/known_hosts。
        """
        candidates: list[Path] = [Path("/etc/ssh/ssh_known_hosts")]
        program_data = os.environ.get("ProgramData")
        if program_data:
            candidates.append(Path(program_data) / "ssh" / "ssh_known_hosts")
        elif os.name == "nt":
            candidates.append(Path("C:/ProgramData/ssh/ssh_known_hosts"))

        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            identity = os.path.normcase(str(candidate))
            if identity not in seen:  # 同一个路径只读一次
                seen.add(identity)
                unique.append(candidate)
        return tuple(unique)

    def _scan_markers(
        self, lines: Sequence[str], path: Path
    ) -> tuple[list[tuple[tuple[str, ...], paramiko.PKey]], int]:
        """扫描 known_hosts 里的 ``@`` 标记行，返回 (撤销列表, 无法解析的行数)。

        【GPT 评审 1】OpenSSH 的语义必须照做，不能一律跳过：
          * ``@revoked`` 是"这把密钥已作废"的强覆盖，必须按拒绝处理。如果只是跳过它，
            原本该被拒绝的密钥就会退化成"未知密钥"，之后用户一个 y 就把它接受了。
          * 撤销规则自己解析不了时（行残缺、哈希部分畸形、密钥不是合法 base64），
            采用安全失败：直接抛错中止本次连接，而不是装作没看见。
          * ``@cert-authority`` 是 CA 签发信任，paramiko 没有校验主机证书的能力，
            这里明确告知用户"这类主机不会被自动信任"，而不是静默忽略。
        【评审 7】每条撤销记录的**模式列表要整体保留**（而不是拆成一条条）：
        OpenSSH 允许 ``host1,*.example.com,!safe.example.com`` 这种写法，逗号和 ``!``
        都属于"同一条规则"的语义，拆开就再也判断不出否定项该否决什么。
        """
        revoked: list[tuple[tuple[str, ...], paramiko.PKey]] = []
        unparsed = 0
        ca_noticed = False
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped.startswith("@"):
                continue
            # 【GPT 评审 4】必须按"任意空白"切分。known_hosts 的分隔符可以是空格也可以是
            # 制表符，之前用 partition(" ") 时，制表符版本的 @revoked 会被整行当成
            # "不认识的标记行"跳过 —— 撤销规则就此形同虚设（已实测确认）。
            parts = stripped.split(None, 1)
            marker = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            if marker == "@revoked":
                try:
                    entry = HostKeyEntry.from_line(rest.strip())
                except Exception:  # noqa: BLE001 - 解析失败=无法判断，必须安全失败
                    entry = None
                if entry is None or not all(
                    _pattern_is_usable(pattern) for pattern in entry.hostnames
                ):
                    raise HostKeyRevokedError(
                        self.text["known_hosts_revoked_unparsed"].format(
                            path=path, line=lineno
                        )
                    )
                # 整条记录作为一个规则保存：模式列表 + 密钥
                revoked.append((tuple(entry.hostnames), entry.key))
            elif marker == "@cert-authority":
                if not ca_noticed:
                    print(self.text["known_hosts_ca_note"])
                    ca_noticed = True
            else:
                unparsed += 1  # 不认识的标记行：明确提示，不静默吞掉
        return revoked, unparsed

    def _load_known_hosts(self, client: paramiko.SSHClient) -> None:
        """加载用户级 + 系统级 known_hosts，并落实 @revoked / @cert-authority 语义。

        【GPT 评审 1】为什么完全自己解析，而不是先试
        ``client.load_system_host_keys()`` 再降级：
          1. paramiko 只跳过 SSHException，``@cert-authority`` / ``@revoked`` 会让它抛
             ``InvalidHostKey``（不是 SSHException 子类），整个登录流程直接崩掉；
          2. 更关键的是它在崩溃前已经把前面几行塞进了 ``_system_host_keys``，而
             ``SSHClient.connect()`` 查主机密钥时**先查这个容器**、查不到才查
             ``_host_keys``。于是"从信任库里剔除被撤销的条目"会被那份残留数据架空，
             撤销规则就形同虚设——所以不能让 paramiko 提前加载半个文件。

        【评审 6】多文件的两个要点（这也正是把系统级文件拉进来之后最容易出错的地方）：
          * 必须**先把所有文件里的 @revoked 规则汇总**，再去加载普通条目。否则
            "A 文件撤销、B 文件信任"的同一个密钥就能绕过去；
          * 文件存在却读不了（权限不足、被占用）时安全失败，而不是当成文件不存在——
            否则攻击者只要让信任文件读不了，就能逼系统退化成"未知密钥"。
        写入方向不变：用户新确认的密钥只追加到自己的 ~/.ssh/known_hosts。
        """
        sources: list[tuple[Path, list[str]]] = []
        # 用户级在前、系统级在后：后加入的条目会覆盖同主机同算法的旧条目，
        # 也就是集中管理的系统记录优先（两者冲突时连接会被判为"密钥不一致"而中止）。
        for path in (self.known_hosts_path, *self._system_known_hosts_paths()):
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()
            except FileNotFoundError:
                continue  # 没有这个信任文件是正常情况
            except OSError as error:
                raise KnownHostsReadError(
                    self.text["known_hosts_read_failed"].format(path=path, detail=error)
                ) from error
            sources.append((path, lines))

        if not sources:
            self._revoked = ()
            return

        revoked: list[tuple[str, paramiko.PKey]] = []
        leftover: dict[Path, int] = {}
        for path, lines in sources:  # 第一遍：汇总所有撤销规则（跨文件生效）
            source_revoked, unparsed = self._scan_markers(lines, path)
            revoked.extend(source_revoked)
            leftover[path] = unparsed
        self._revoked = tuple(revoked)  # 供确认策略在握手时做硬性拦截

        for path, lines in sources:  # 第二遍：加载普通条目，撤销命中的一律剔除
            unparsed = leftover[path]
            loaded = 0
            dropped = 0
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "@")):
                    continue
                try:
                    entry = HostKeyEntry.from_line(stripped)
                except Exception:  # noqa: BLE001 - 个别行坏掉不该影响其它记录
                    unparsed += 1
                    continue
                # 命中任一信任文件的撤销规则，绝不能进信任库，否则会被当成"已知主机"放行
                if _key_is_revoked(revoked, entry.hostnames, entry.key):
                    dropped += 1
                    continue
                for hostname in entry.hostnames:
                    client.get_host_keys().add(hostname, entry.key.get_name(), entry.key)
                loaded += 1

            if unparsed:
                print(self.text["known_hosts_partial"].format(count=unparsed))
            if dropped:
                print(self.text["known_hosts_revoked_skipped"].format(count=dropped))
            print(self.text["known_hosts_loaded"].format(count=loaded, path=path))

    # -- 把用户确认过的密钥追加到 known_hosts ---------------------------------

    def _known_hosts_name(self, hostname: str) -> str:
        """known_hosts 里的主机名字段。

        【修复 1】非默认端口必须写成 ``[host]:port``，否则 OpenSSH 和 paramiko 都命中不了
        这条记录（连 22 端口用 ssh 连接时同样如此）。paramiko 传进来的 hostname 在
        非默认端口下已经是 ``[host]:port``，这里做个判断，避免画蛇添足地再套一层方括号。
        """
        if hostname.startswith("[") and "]:" in hostname:
            return hostname
        if self.port == DEFAULT_PORT:
            return hostname
        return f"[{hostname}]:{self.port}"

    def _remember_host_key(self, hostname: str, key: paramiko.PKey) -> None:
        """把用户刚确认过的主机密钥以"追加一行"的方式写进 ~/.ssh/known_hosts。

        【修复 1】为什么不用 client.save_host_keys()：paramiko 会用内存里的数据重写整个
        文件，把 @cert-authority / @revoked 等它不认识的行、以及用户自己的注释全部抹掉，
        属于破坏性操作。这里只做 append：原有内容一行不动。
        追加失败（权限不足、路径只读等）只打印 warning，绝不影响已经建立的连接。
        """
        line = f"{self._known_hosts_name(hostname)} {key.get_name()} {key.get_base64()}\n"
        try:
            self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
            # 若文件末尾没有换行符，先补一个；否则新条目会和最后一行粘成一条无效记录。
            needs_leading_newline = False
            if self.known_hosts_path.is_file():
                with open(self.known_hosts_path, "rb") as handle:
                    handle.seek(0, os.SEEK_END)
                    if handle.tell() > 0:
                        handle.seek(-1, os.SEEK_END)
                        needs_leading_newline = handle.read(1) != b"\n"
            # newline="\n" 明确关掉平台换行转换，保证写进去的就是 OpenSSH 期望的格式
            with open(self.known_hosts_path, "a", encoding="utf-8", newline="\n") as handle:
                if needs_leading_newline:
                    handle.write("\n")
                handle.write(line)
        except OSError as error:
            # 只告警、不抛：连接已经建好了，写不进信任库不该把用户拦在门外。
            print(
                self.text["host_key_save_failed"].format(
                    path=self.known_hosts_path, detail=error
                )
            )
            return
        print(self.text["host_key_saved"].format(path=self.known_hosts_path))

    def _connect(self, credentials: Credentials) -> paramiko.SSHClient:
        """先做一次 TCP 预检（精确定位超时/拒绝/域名错误），再交给 Paramiko 握手认证。"""
        print(
            self.text["connecting"].format(
                user=self.username, host=self.host, port=self.port
            )
        )
        client = paramiko.SSHClient()
        sock: socket.socket | None = None
        try:
            # 预检：连接超时、端口拒绝、域名解析失败的报错由这里精确定位
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

            self._load_known_hosts(client)  # 复用本机已知主机密钥
            # 【修复 1】留着 policy 的引用，握完手才能知道用户这次有没有确认新密钥
            policy = _ConfirmUnknownHostKey(self.text, self._revoked)
            client.set_missing_host_key_policy(policy)
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=credentials.password,
                pkey=credentials.pkey,
                sock=sock,
                # 明确关闭“自动找密钥 / 使用 ssh-agent”，避免隐式凭据带来意外登录方式
                look_for_keys=False,
                allow_agent=False,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
        except BaseException:
            client.close()
            if sock is not None:
                with suppress(OSError):
                    sock.close()
            raise

        self.client = client
        # 【修复 1】握手成功后才落盘：确认过但连不上时不留垃圾记录。
        # 放在 try 之外，写文件失败不会触发上面的 client.close() 回滚。
        if policy._accepted is not None:  # noqa: SLF001 - 与确认策略约定好的内部字段
            self._remember_host_key(*policy._accepted)
        print(self.text["connected"].format(host=self.host, port=self.port))
        return client

    # -- 排错诊断 ------------------------------------------------------------

    def _report(self, error: BaseException) -> bool:
        """按异常类型输出本地化的报错与排错建议；返回 ``True`` 表示可以重试。"""
        text = self.text
        print()  # 与上面的提示语空开一行，便于阅读

        if isinstance(error, paramiko.AuthenticationException):
            print(text["err_auth"])
            print(text["hint_auth"])
            return True
        if isinstance(error, socket.timeout):
            print(text["err_timeout"].format(timeout=f"{self.timeout:g}"))
            print(text["hint_timeout"])
            return True
        if isinstance(error, socket.gaierror):
            print(text["err_unknown_host"].format(detail=error))
            print(text["hint_unknown_host"])
            return True
        if isinstance(error, ConnectionRefusedError):
            print(text["err_refused"])
            print(text["hint_refused"])
            return True
        # 【修复 5】多地址全部连不上时 paramiko 抛 NoValidConnectionsError。
        # 它继承自 OSError（不是 SSHException），落进 err_protocol 分支会误导用户去
        # "确认端口上跑的是不是 SSH 服务"，而真实原因通常是不可达或被拦截。
        # 说明：本模块自带 TCP 预检，正常路径不会走到这里；保留该分支是为了兜住
        # 极端情况（例如后续有人去掉预检、改成完全交给 paramiko 直连）。
        if isinstance(error, NoValidConnectionsError):
            print(text["err_no_valid_conn"])
            print(text["hint_no_valid_conn"])
            return True
        if isinstance(error, paramiko.BadHostKeyException):
            print(text["err_host_key_mismatch"])
            print(text["hint_host_key_mismatch"])
            return False  # 安全相关，直接中止，不鼓励“重试就好”
        if isinstance(error, HostKeyRejectedError):
            print(error)
            return False
        # 【GPT 评审 1】@revoked 命中或撤销规则不可解析：安全失败，不提供"重试就好"。
        if isinstance(error, HostKeyRevokedError):
            print(error)
            return False
        # 【评审 6】信任文件读不了：安全失败，同样不提供"重试就好"。
        if isinstance(error, KnownHostsReadError):
            print(error)
            return False
        if isinstance(error, paramiko.SSHException):
            print(text["err_protocol"].format(detail=error))
            print(text["hint_protocol"])
            return False

        print(text["err_generic"].format(detail=error))
        print(text["hint_generic"])
        return False

    # -- 主流程 --------------------------------------------------------------

    def _prepare_credentials(self) -> Credentials:
        """反复"选登录方式 + 准备凭据"，直到拿到可用的认证材料。

        【修复 3】这一段故意不消耗连接重试次数：密钥路径写错、私钥解析失败、
        自动查找没命中，都属于"本地准备工作没做好"，用户重新选一次就行。
        原来的写法把它算进 MAX_ATTEMPTS，三次本地失误就 give up，一次连接都没发起过，
        与 MAX_ATTEMPTS 注释里"选方式 + 连接轮次"的语义不符。
        """
        while True:
            credentials = self._resolve_credentials(self.choose_method())
            if credentials is not None:
                return credentials

    def run(self) -> paramiko.SSHClient | None:
        """完整走一遍“选方式 → 认证 → 连接”。成功返回 SSHClient，否则返回 ``None``。"""
        try:
            # 【修复 3】只有真正发起 _connect() 并失败，才算消耗一次重试机会。
            attempts = 0
            while attempts < MAX_ATTEMPTS:
                credentials = self._prepare_credentials()
                try:
                    return self._connect(credentials)
                except (paramiko.SSHException, socket.timeout, OSError) as error:
                    attempts += 1
                    retryable = self._report(error)
                    self.close()
                    if not retryable or attempts >= MAX_ATTEMPTS:
                        break
                    if input(self.text["retry_prompt"]).strip().lower() not in YES_ANSWERS:
                        break
        except NotInteractiveTerminalError as error:
            # 【修复 2】非交互终端：只提示一次并中止，不进入任何重试流程。
            print(error)
            self.close()
            return None
        except (KeyboardInterrupt, EOFError):  # Ctrl-C 或输入被重定向到空流
            print(self.text["cancelled"])
            self.close()
            return None
        print(self.text["give_up"])
        return None

    # -- 资源管理 ------------------------------------------------------------

    def close(self) -> None:
        """关闭底层连接（幂等，可重复调用）。"""
        if self.client is not None:
            self.client.close()
            self.client = None

    def __enter__(self) -> SSHLoginManager:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _ensure_utf8_output() -> None:
    """在旧版/非 UTF-8 终端上避免 emoji 与中文导致 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        with suppress(AttributeError, OSError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]


def main() -> int:
    """可执行示例：三个参数都交互询问，连上后跑一条 whoami 验证。"""
    _ensure_utf8_output()
    with SSHLoginManager(port=None, username=None) as manager:
        client = manager.run()
        if client is None:
            return 1
        _, stdout, _ = client.exec_command("whoami")
        print(f"🐚 whoami -> {stdout.read().decode(errors='replace').strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# 本次 Code Review 的修改点（按顺序）
#   1. 修复 1：_ConfirmUnknownHostKey 记录 accepted；_connect() 握手成功后由
#      _remember_host_key() 以 append 方式追加一行到 ~/.ssh/known_hosts，
#      非默认端口写成 [host]:port；失败只 warning，不用 save_host_keys()。
#   2. 修复 2：新增 NotInteractiveTerminalError 与 _is_interactive_terminal()，
#      密码/私钥口令统一走 _read_secret()，非交互终端直接中止。
#   3. 修复 3：抽出 _prepare_credentials() 内层循环，本地准备失败不再消耗
#      MAX_ATTEMPTS，只有 _connect() 抛错才 attempts += 1。
#   4. 修复 4：_ask_port() 改用 try/except ValueError 解析端口。
#   5. 修复 5：_report() 新增 NoValidConnectionsError 分支（err_no_valid_conn /
#      hint_no_valid_conn 两对新文案）。
#   6. 修复 6：依赖声明改为 paramiko>=5（4.0.0 存在 CVE-2026-44405）。
#   新增的 i18n 键：err_no_valid_conn / hint_no_valid_conn（要求内），
#   以及 not_interactive / host_key_saved / host_key_save_failed（配合修复 1、2
#   的提示语，保持中英双语查表结构，没有硬编码文案）。
#   _load_known_hosts()、detect_language()/_language_from_locale() 未改动。
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 第二轮评审（GPT）的修改点
#   1. @revoked 语义（评审 1）：新增 _hostname_matches() / _pattern_is_usable() /
#      _same_key() / _key_is_revoked() 与 HostKeyRevokedError。
#      · 命中撤销规则的条目不会进信任库，握手时再由确认策略硬性拦截，
#        两种路径都不给用户"手动接受已撤销密钥"的机会；
#      · 撤销规则本身解析不了（行残缺、哈希段畸形、密钥不是合法 base64）-> 安全失败，
#        抛 HostKeyRevokedError 中止本次连接；
#      · _load_known_hosts() 改为完全自己逐行解析，不再先调
#        client.load_system_host_keys()：它遇到 @ 标记行会抛 InvalidHostKey，
#        而且崩溃前已把前面几行塞进 _system_host_keys，偏偏 connect() 查主机密钥时
#        优先查这个容器 —— 撤销列表会被那份残留数据架空；
#      · @cert-authority 改为明确提示"paramiko 无法校验 CA 签发的主机证书"，
#        不再静默跳过；known_hosts_partial 文案改为带 {count}。
#   2. 私钥读取（评审 2）：_load_key() 先自己以文本模式 open()，
#      把"权限不足 / 读不了"与"格式不受支持"分开提示；逐算法重试时同时兜住
#      paramiko.SSHException 与 cryptography 可能抛出的 ValueError。
#      注意：paramiko 的 from_private_key() 内部用 str 正则匹配 PEM 头，
#      必须传文本句柄，传二进制会抛 TypeError。
#   3. 信任提示（评审 3）：host_key_unknown / host_key_confirm 明确要求通过云服务商
#      控制台、管理员或服务器端 ssh-keygen -lf 核对指纹，并写明"看到指纹本身
#      不能证明连接安全"，避免把"用户点了确认"当成指纹已验证。
#   新增 i18n 键：host_key_revoked / known_hosts_revoked_unparsed /
#   known_hosts_revoked_skipped / known_hosts_ca_note /
#   key_permission_denied / key_read_failed。
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 第三轮评审（GPT）的修改点
#   1. 制表符分隔的 @revoked 行（评审 4）：_scan_markers() 里原来的
#      stripped.partition(" ") 改成 stripped.split(None, 1)，按任意空白切分。
#      之前的写法遇到 "@revoked\t[host]:port\tssh-rsa\tAAAA" 会把整行当成 marker，
#      既不等于 "@revoked" 也不算 "@cert-authority"，于是被记成"不认识的标记行"跳过 ——
#      撤销规则形同虚设，已实测确认并补了回归用例（制表符版撤销/剔除/坏规则/CA/普通条目）。
#   2. 构造参数校验（评审 4）：新增 _validate_arguments()，非法的
#      host / port / username / timeout 在构造阶段就抛带双语说明的 ValueError。
#      原因：timeout<=0 会让 socket 抛 ValueError: Timeout value out of range，
#      该异常不在 run() 捕获的类型里，用户看到裸 traceback；port=99999 在 Windows 上
#      会被静默回绕成 34463 去连接（连到了没打算连的端口）；port="abc" 会被误报成
#      "无法解析主机名"。None 仍是合法值，表示交给交互式询问（由 _ask_* 做同样的校验）。
#      新增文案 invalid_argument。
#   3. 指纹提示（评审 3）：host_key_unknown 的内容改为 print 输出，不再拼进 input()
#      的提示串——它更长、更该被认真读到，也不该因为输出重定向/记日志而消失。
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 第四轮评审（GPT）的修改点
#   1. 哈希形式主机名（评审 5）：_pattern_is_usable() 重写为显式的"格式 + 长度"校验
#      （|1|<base64 salt>|<base64 hash>，字段数、base64 合法性、盐与摘要各 20 字节），
#      再加一次"本机算得出来"的探测（SHA-1 被禁用的环境要安全失败）。
#      原实现虽然也只是"算一次看抛不抛异常"、并没有拿结果去比较，但写法容易被读成
#      "拿固定测试名重新哈希再要求相等"，所以改成不再留歧义；同时补上了此前完全
#      没有用例覆盖的哈希撤销记录测试（命中拒绝、绕过阻挡、坏规则安全失败）。
#   2. 超时上下界（评审 5）：新增 MAX_TIMEOUT = 3600.0 与 _is_positive_finite_number()。
#      原来只判 timeout > 0，inf 和 1e9 以上的值都能通过，直到 socket.settimeout()
#      才抛 OverflowError（不在 run() 捕获范围内，裸 traceback）。现在要求
#      "有限正数且 <= MAX_TIMEOUT"，bool / inf / nan / 超大整数一律拒绝；
#      invalid_argument 文案同步说明区间。
#   3. 顺带记录实测行为：paramiko 的 HostKeys.get() 会走 lookup()，所以哈希形式的
#      普通条目是能被匹配复用的（通配模式不行），这一条已加入回归用例。
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 第五轮评审（GPT 提供的 system_hosts 版本）的修改点
#   1. 系统级主机信任文件（评审 6，需求来自上一轮我提的待办）：
#      · 新增 _system_known_hosts_paths()：/etc/ssh/ssh_known_hosts（Linux/macOS）
#        与 %ProgramData%\ssh\ssh_known_hosts（Windows OpenSSH），路径去重后返回；
#      · _load_known_hosts() 改为多文件两阶段加载：先汇总**所有**文件里的 @revoked，
#        再加载普通条目并剔除命中撤销的条目 —— 否则"A 文件撤销、B 文件信任"的同一把
#        密钥就能把撤销绕过去（GPT 这版在这点上做对了，已用专项用例验证）；
#      · 文件存在却读不了（权限不足、被占用）时抛新增的 KnownHostsReadError 并中止，
#        不把"读不了"当成"不存在"，避免被逼着退化成"未知密钥";
#      · 写入方向不变：用户新确认的密钥只追加到 ~/.ssh/known_hosts，系统级文件只读，
#        专项用例里比对了系统文件的字节未被改动。
#   2. 新增文案 known_hosts_read_failed。
#   说明：实现按本文件的既有风格重写，行为与候选版本在 15 项专项用例上一致。
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 第六轮评审（GPT）的修改点
#   1. 撤销规则的主机名模式语义（评审 7）：
#      · 新增 _pattern_list_matches()：按 OpenSSH match_pattern_list() 处理
#        逗号分隔的多个模式、以及以 ! 开头的否定项（命中即整体判为不匹配，
#        且要求至少有一个正项命中；纯否定列表对任何主机都不匹配）；
#      · 新增 _glob_to_regex()，_hostname_matches() 不再用 fnmatch：OpenSSH 只把
#        * 和 ? 当元字符，[abc] 是字面量，而 fnmatch 会把方括号当字符类，
#        匹配得比 OpenSSH 更宽 —— 对撤销规则来说就是"多撤销了一批主机"；
#      · _scan_markers() 里每条撤销记录改为整组保存 (模式列表, 密钥)，
#        拆成单条就已丢失否定项要否决谁的信息；
#      · _pattern_is_usable() 先剥掉 ! 前缀再校验格式。
#      实测结论（比评审的说法更精确）：paramiko 会按逗号拆分主机名字段，所以
#      "逗号列表被漏掉"并不成立；真正出问题的是否定项被当成普通模式 → 后果是
#      过度撤销（把管理员用 ! 明确排除的主机也拒掉），属可用性问题而非安全洞。
#      共补 7 条回归用例（含 5 条真实连接）。
#   2. 顺带固定一个容易写错的 OpenSSH 事实：非默认端口下主机名是 [host]:port，
#      形如 127.0.0.* 的模式匹配不了它，要写 [127.0.0.*]:* 才命中。
# ---------------------------------------------------------------------------

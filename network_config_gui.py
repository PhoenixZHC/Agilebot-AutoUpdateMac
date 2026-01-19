#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
网络配置工具 - GUI版本
用于更新控制柜MAC地址的可视化工具
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import sys
import ctypes
import re
import random
import base64
import ipaddress
import threading
import time
from datetime import datetime

# 检查管理员权限
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# 如果没有管理员权限，请求提升
if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

class NetworkConfigGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Auto update Mac address")
        self.root.geometry("1400x800")
        self.root.resizable(True, True)  # 允许窗口调整大小
        self.root.minsize(1000, 600)  # 设置最小窗口大小

        # 设置现代化背景色
        self.root.configure(bg="#F5F7FA")

        # 设置窗口图标（如果有的话）
        try:
            self.root.iconbitmap(default='')
        except:
            pass

        # 变量
        self.control_ip = tk.StringVar()
        self.control_password = tk.StringVar(value="root")  # 默认密码
        self.status_text = None

        # 创建界面
        self.create_widgets()

    def create_widgets(self):
        # 配置现代化样式
        style = ttk.Style()
        style.theme_use('clam')

        # 配置现代化颜色方案
        style.configure('TFrame', background='#F5F7FA')
        style.configure('TLabelframe', background='#FFFFFF', borderwidth=1, relief=tk.FLAT)
        style.configure('TLabelframe.Label', background='#FFFFFF', foreground='#2C3E50',
                       font=('Microsoft YaHei UI', 11, 'bold'))
        style.configure('TLabel', background='#FFFFFF', foreground='#34495E',
                       font=('Microsoft YaHei UI', 10))
        style.configure('TEntry', fieldbackground='#FFFFFF', borderwidth=1,
                       relief=tk.SOLID, padding=8, font=('Microsoft YaHei UI', 10))
        style.map('TEntry',
                 focuscolor=[('focus', '#4A90E2')],
                 bordercolor=[('focus', '#4A90E2')])

        # 主框架 - 使用左右布局
        main_frame = tk.Frame(self.root, bg="#F5F7FA", padx=20, pady=20)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 左侧内容框架
        left_frame = tk.Frame(main_frame, bg="#F5F7FA")
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 15))

        # 右侧状态框架
        right_frame = tk.Frame(main_frame, bg="#F5F7FA")
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 顶部Header区域
        header_frame = tk.Frame(left_frame, bg="#F5F7FA")
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))

        # 标题 - 更现代化的大标题
        title_label = tk.Label(
            header_frame,
            text="Auto update Mac address",
            font=("Microsoft YaHei UI", 24, "bold"),
            bg="#F5F7FA",
            fg="#2C3E50"
        )
        title_label.pack(anchor=tk.W, pady=(0, 5))

        # 副标题
        subtitle_label = tk.Label(
            header_frame,
            text="自动更新Mac地址",
            font=("Microsoft YaHei UI", 11),
            bg="#F5F7FA",
            fg="#7F8C8D"
        )
        subtitle_label.pack(anchor=tk.W, pady=(0, 20))

        # 现代化提示信息区域（放在最前面）- 参照图片样式
        tip_container = tk.Frame(left_frame, bg="#FFF4E6", relief=tk.FLAT, bd=0)
        tip_container.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20), padx=0)

        # 左侧图标区域 - 深橙色条带
        icon_frame = tk.Frame(tip_container, bg="#FF9800", width=50)
        icon_frame.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        icon_label = tk.Label(
            icon_frame,
            text="⚠",
            font=("Microsoft YaHei UI", 24),
            bg="#FF9800",
            fg="white"
        )
        icon_label.pack(expand=True, pady=15)

        # 提示文本区域
        tip_text_frame = tk.Frame(tip_container, bg="#FFF4E6")
        tip_text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 20), pady=(18, 18))

        tip_title = tk.Label(
            tip_text_frame,
            text="重要提示",
            font=("Microsoft YaHei UI", 12, "bold"),
            bg="#FFF4E6",
            fg="#2C3E50",
            anchor=tk.W
        )
        tip_title.pack(anchor=tk.W, pady=(0, 8))

        tip_content = tk.Label(
            tip_text_frame,
            text="请确保本地IP和控制柜IP在同一网段!",
            font=("Microsoft YaHei UI", 11),
            bg="#FFF4E6",
            fg="#2C3E50",
            anchor=tk.W
        )
        tip_content.pack(anchor=tk.W)

        # 步骤1：输入控制柜IP和密码 - 现代化卡片设计
        step1_frame = ttk.LabelFrame(left_frame, text="步骤1: 输入控制柜信息", padding="20")
        step1_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))

        # 标签样式
        label_style = {'font': ('Microsoft YaHei UI', 10, 'bold'), 'bg': '#FFFFFF', 'fg': '#34495E'}

        ip_label = tk.Label(step1_frame, text="控制柜IP地址:", **label_style)
        ip_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 8), padx=(0, 10))
        ip_entry = ttk.Entry(step1_frame, textvariable=self.control_ip, font=("Microsoft YaHei UI", 11), width=30)
        ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 0), pady=(0, 15))

        password_label = tk.Label(step1_frame, text="控制柜密码:", **label_style)
        password_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 8), padx=(0, 10))
        password_entry = ttk.Entry(step1_frame, textvariable=self.control_password, show="*",
                                  font=("Microsoft YaHei UI", 11), width=30)
        password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 0), pady=(0, 0))

        # 步骤2：显示计算出的配置 - 现代化卡片设计
        step2_frame = ttk.LabelFrame(left_frame, text="步骤 2: MAC地址信息", padding="20")
        step2_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))

        # 配置信息显示区域使用更好的视觉样式
        info_container = tk.Frame(step2_frame, bg="#FFFFFF")
        info_container.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)

        # MAC地址显示 - 参照图片样式
        mac_label_title = tk.Label(info_container, text="MAC地址:",
                                    font=("Microsoft YaHei UI", 10, "bold"),
                                    bg="#FFFFFF", fg="#34495E", anchor=tk.W)
        mac_label_title.grid(row=0, column=0, sticky=tk.W, pady=(0, 8))

        self.mac_address_label = tk.Label(info_container, text="未生成",
                                         font=("Microsoft YaHei UI", 11),
                                         bg="#FFFFFF", fg="#95A5A6",
                                         anchor=tk.W, padx=0, pady=0,
                                         relief=tk.FLAT, bd=0)
        self.mac_address_label.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 0))

        info_container.columnconfigure(0, weight=1)

        # 绑定IP输入事件，自动计算MAC地址
        self.control_ip.trace('w', self.on_ip_changed)

        # 执行按钮区域
        action_frame = ttk.Frame(left_frame)
        action_frame.grid(row=4, column=0, columnspan=2, pady=15, sticky=(tk.W, tk.E))

        # 按钮容器，居中显示
        button_container = ttk.Frame(action_frame)
        button_container.pack(expand=True)

        # 配置现代化按钮样式 - 绿色主题
        style = ttk.Style()
        style.configure("Primary.TButton",
                       font=("Microsoft YaHei UI", 11, "bold"),
                       padding=(25, 12))
        style.map("Primary.TButton",
                 background=[('active', '#27AE60'), ('!active', '#2ECC71')],
                 foreground=[('active', 'white'), ('!active', 'white')])

        self.execute_btn = ttk.Button(
            button_container,
            text="开始配置",
            command=self.execute_configuration,
            style="Primary.TButton",
            width=20
        )
        self.execute_btn.pack(side=tk.LEFT, padx=10)

        # 状态显示区域（右侧）- 现代化设计
        status_frame = ttk.LabelFrame(right_frame, text="执行状态", padding="15")
        status_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#2C3E50",  # 现代化深蓝灰色背景
            fg="#ECF0F1",  # 浅色文字
            insertbackground="#5BA3F5",  # 蓝色光标
            selectbackground="#4A90E2",  # 选中背景
            selectforeground="#FFFFFF",  # 选中文字颜色
            relief=tk.FLAT,
            borderwidth=0,
            padx=10,
            pady=10
        )
        self.status_text.pack(fill=tk.BOTH, expand=True)

        # 绑定鼠标滚轮事件到状态文本区域
        def on_mousewheel_status(event):
            # 检查是否在状态文本区域内
            if self.status_text.winfo_containing(event.x_root, event.y_root) == self.status_text:
                self.status_text.yview_scroll(int(-1 * (event.delta / 120)), "units")

        # 绑定鼠标滚轮（Windows）
        self.status_text.bind("<MouseWheel>", on_mousewheel_status)
        # 绑定鼠标滚轮（Linux，如果需要）
        self.status_text.bind("<Button-4>", lambda e: self.status_text.yview_scroll(-1, "units"))
        self.status_text.bind("<Button-5>", lambda e: self.status_text.yview_scroll(1, "units"))

        # 配置网格权重 - 让所有组件充分利用窗口空间
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=2)  # 左侧占更多空间
        main_frame.columnconfigure(1, weight=3)  # 右侧状态区域占更多空间
        main_frame.rowconfigure(0, weight=1)
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(2, weight=1)  # 步骤1可扩展
        left_frame.rowconfigure(3, weight=1)  # 步骤2可扩展
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)
        step1_frame.columnconfigure(1, weight=1)  # 输入框列可扩展
        step2_frame.columnconfigure(0, weight=1)  # 信息显示列可扩展
        info_container.columnconfigure(0, weight=1)

        # 执行标志
        self.is_running = False
        self.stop_flag = False

    def log(self, message, color="black", level="INFO"):
        """在状态区域添加日志（带时间戳）"""
        if self.status_text:
            from datetime import datetime
            timestamp = datetime.now().strftime("[%H:%M:%S]")

            # 根据级别添加前缀
            if level == "ERROR":
                prefix = f"{timestamp} [错误]"
            elif level == "WARNING":
                prefix = f"{timestamp} [警告]"
            elif level == "SUCCESS":
                prefix = f"{timestamp} [成功]"
            else:
                prefix = f"{timestamp} [信息]"

            log_message = f"{prefix} {message}\n"
            self.status_text.insert(tk.END, log_message)

            # 根据颜色和级别设置文本颜色
            if color == "red" or level == "ERROR":
                self.status_text.tag_add("error", f"end-{len(log_message)}c", "end-1c")
                self.status_text.tag_config("error", foreground="#FF4444")
            elif color == "green" or level == "SUCCESS":
                self.status_text.tag_add("success", f"end-{len(log_message)}c", "end-1c")
                self.status_text.tag_config("success", foreground="#44FF44")
            elif level == "WARNING":
                self.status_text.tag_add("warning", f"end-{len(log_message)}c", "end-1c")
                self.status_text.tag_config("warning", foreground="#FFAA00")

            self.status_text.see(tk.END)
            self.root.update()


    def _format_connection_error(self, error_message, control_ip, local_ip):
        """格式化连接错误信息，添加故障排除建议"""
        # 检查是否是连接超时或连接失败的错误
        is_timeout = False
        is_connection_error = False

        error_lower = str(error_message).lower()
        if "timeout" in error_lower or "timed out" in error_lower or "10060" in str(error_message) or "连接超时" in error_message:
            is_timeout = True
        if "连接" in error_message or "connection" in error_lower or "连接失败" in error_message:
            is_connection_error = True

        # 构建错误信息
        error_text = f"错误信息：\n{error_message}\n\n"

        if is_timeout or is_connection_error:
            error_text += "控制柜连接不上，请检查：\n\n"
            error_text += "1. 控制柜已开机\n"
            error_text += "2. 网线已连接\n"
            error_text += "3. IP地址正确\n"
            error_text += f"   控制柜IP: {control_ip}\n"
            error_text += "4. 确保本地IP与控制柜IP在同一网段\n"
            error_text += "\n提示：请确保控制柜已启动，网线连接正常，\n"
            error_text += "并且本地IP地址与控制柜IP在同一网段内。"
        else:
            error_text += "请检查：\n"
            error_text += "1. 控制柜SSH服务是否正常运行\n"
            error_text += "2. SSH密码是否正确\n"
            error_text += "3. 网络连接是否正常"

        return error_text

    def _log_error_with_troubleshooting(self, error_message, control_ip, local_ip):
        """在日志中记录错误信息及故障排除建议"""
        # 检查是否是连接超时或连接失败的错误
        is_timeout = False
        is_connection_error = False

        error_lower = str(error_message).lower()
        if "timeout" in error_lower or "timed out" in error_lower or "10060" in str(error_message) or "连接超时" in error_message:
            is_timeout = True
        if "连接" in error_message or "connection" in error_lower or "连接失败" in error_message:
            is_connection_error = True

        # 记录错误信息
        self.log(f"错误详情: {error_message}", level="ERROR")

        if is_timeout or is_connection_error:
            self.log("控制柜连接不上，请检查：", level="ERROR")
            self.log("1. 控制柜已开机", level="WARNING")
            self.log("2. 网线已连接", level="WARNING")
            self.log("3. IP地址正确", level="WARNING")
            self.log(f"   控制柜IP: {control_ip}", level="INFO")
            self.log("4. 确保本地IP与控制柜IP在同一网段", level="WARNING")
            self.log("提示：请确保控制柜已启动，网线连接正常，并且本地IP地址与控制柜IP在同一网段内。", level="ERROR")
        else:
            self.log("请检查：", level="ERROR")
            self.log("1. 控制柜SSH服务是否正常运行", level="WARNING")
            self.log("2. SSH密码是否正确", level="WARNING")
            self.log("3. 网络连接是否正常", level="WARNING")

    def _get_password_from_user(self):
        """从用户获取密码（如果密码为空时调用）"""
        # 创建密码输入对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("输入控制柜密码")
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # 居中显示
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        password_var = tk.StringVar(value="root")
        result = [None]  # 使用列表以便在闭包中修改

        ttk.Label(dialog, text="请输入控制柜SSH密码:", font=("Microsoft YaHei UI", 9)).pack(pady=10)
        password_entry = ttk.Entry(dialog, textvariable=password_var, width=30, show="*")
        password_entry.pack(pady=5)
        password_entry.focus()

        def on_ok():
            result[0] = password_var.get().strip()
            dialog.destroy()

        def on_cancel():
            result[0] = None
            dialog.destroy()

        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="确定", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=on_cancel).pack(side=tk.LEFT, padx=5)

        # 绑定Enter键
        password_entry.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: on_cancel())

        dialog.wait_window()
        return result[0]



    def on_ip_changed(self, *args):
        """IP地址改变时自动计算MAC地址"""
        ip = self.control_ip.get().strip()
        if not ip:
            self.mac_address_label.config(text="未生成", fg="#95A5A6", bg="#FFFFFF")
            return

        try:
            # 验证IP格式
            ipaddress.ip_address(ip)

            # 生成MAC地址
            mac_address = self.generate_mac_address()

            # 更新步骤2的MAC地址信息 - 参照图片样式
            self.mac_address_label.config(text=mac_address, fg="#34495E", bg="#FFFFFF")
        except ValueError:
            self.mac_address_label.config(text="IP格式无效", fg="#E74C3C", bg="#FFFFFF")
        except Exception as e:
            self.mac_address_label.config(text="计算错误", fg="#E74C3C", bg="#FFFFFF")


    def generate_mac_address(self):
        """生成随机MAC地址"""
        try:
            now = datetime.now()
            random_bytes = [random.randint(0, 255) for _ in range(3)]

            mac_bytes = [
                ((now.month - 1) << 4) | (0x02 if random.randint(0, 1) == 0 else 0x06),  # 确保本地管理
                min(now.day, 255),
                now.hour,
                now.minute,
                now.second,
                random_bytes[1]
            ]

            # XOR混合
            for i in range(6):
                mac_bytes[i] ^= random_bytes[2]

            # 确保第一个字节的第二位是偶数（本地管理地址）
            mac_bytes[0] = (mac_bytes[0] & 0xFE) | 0x02

            mac_str = ':'.join([f"{b:02X}" for b in mac_bytes])
            return mac_str
        except:
            # 备用方案
            mac_bytes = [random.randint(0, 255) for _ in range(6)]
            mac_bytes[0] = (mac_bytes[0] & 0xFE) | 0x02
            return ':'.join([f"{b:02X}" for b in mac_bytes])

    def execute_configuration(self):
        """执行配置"""
        # 验证输入
        if not self.control_ip.get().strip():
            messagebox.showerror("错误", "请输入控制柜IP地址！")
            return

        try:
            ipaddress.ip_address(self.control_ip.get().strip())
        except ValueError:
            messagebox.showerror("错误", "IP地址格式无效！")
            return

        # 禁用按钮
        self.execute_btn.config(state=tk.DISABLED)
        self.is_running = True
        self.stop_flag = False

        # 在新线程中执行
        thread = threading.Thread(target=self._execute_configuration_thread)
        thread.daemon = True
        thread.start()

    def _execute_configuration_thread(self):
        """执行配置的线程函数"""
        try:
            control_ip = self.control_ip.get().strip()

            self.log("=" * 50)
            self.log("开始更新控制柜MAC地址...")
            self.log(f"控制柜IP: {control_ip}")
            self.log("=" * 50)

            # 步骤1：更新控制柜MAC地址
            self.log("\n步骤 1: 更新控制柜MAC地址", level="INFO")
            # 获取密码
            password = self.control_password.get().strip() or "root"
            mac_success, mac_message = self.update_control_cabinet_mac(control_ip, password=password)

            # 更新步骤2的MAC地址显示
            self._update_step2_display(mac_address=mac_message)

            if mac_success:
                self.log(f"MAC地址更新成功", level="SUCCESS")
                if mac_message:
                    self.log(mac_message, level="SUCCESS")
                self.root.after(0, lambda: messagebox.showinfo("成功", "MAC地址更新成功！"))
            else:
                self.log(f"MAC地址更新失败: {mac_message}", level="ERROR")
                # 在日志中显示详细错误信息（包含故障排除建议）
                self._log_error_with_troubleshooting(mac_message, control_ip, "")

                # 生成友好的错误信息，包含故障排除建议
                error_msg = self._format_connection_error(mac_message, control_ip, "")
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("MAC地址更新失败", msg))

        except Exception as e:
            self.log(f"执行过程中出错: {str(e)}", "red")
            self.root.after(0, lambda: messagebox.showerror("错误", f"执行过程中出错:\n{str(e)}"))
        finally:
            self._reset_buttons()

    def _reset_buttons(self):
        """重置按钮状态"""
        self.root.after(0, lambda: self.execute_btn.config(state=tk.NORMAL))
        self.is_running = False

    def _update_step2_display(self, mac_address=None):
        """更新步骤2的显示信息"""
        # 更新MAC地址显示（优先使用保存的生成MAC地址）
        if hasattr(self, '_last_generated_mac') and self._last_generated_mac:
            # 优先使用保存的生成MAC地址（这是实际计算出的MAC地址，与执行状态中显示的一致）
            mac = self._last_generated_mac
            self.root.after(0, lambda m=mac: self.mac_address_label.config(
                text=m, fg="#34495E", bg="#FFFFFF"))
        elif mac_address:
            # 如果消息中包含MAC地址，尝试从消息中提取（作为备用）
            mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', str(mac_address))
            if mac_match:
                mac = mac_match.group(1)
                self.root.after(0, lambda m=mac: self.mac_address_label.config(
                    text=m, fg="#34495E", bg="#FFFFFF"))


    def update_control_cabinet_mac(self, control_ip, username="root", password=None):
        """通过SSH更新控制柜MAC地址"""
        try:
            # 如果密码为空，提示用户输入
            if not password or password.strip() == "":
                password = self._get_password_from_user()
                if not password:
                    return False, "未输入密码，操作已取消"

            # 生成MAC地址（在方法开始时生成，以便后续使用）
            random_mac = self.generate_mac_address()
            # 保存生成的MAC地址，以便在更新步骤3时使用
            self._last_generated_mac = random_mac

            # 首先尝试使用paramiko（如果可用）
            try:
                import paramiko
                return self._update_mac_with_paramiko(control_ip, username, password, random_mac)
            except ImportError:
                # paramiko不可用，使用系统SSH客户端
                pass

            # 检查SSH是否可用
            ssh_check = subprocess.run(
                ["where", "ssh"],
                capture_output=True,
                text=True
            )

            if ssh_check.returncode != 0:
                return False, "未找到SSH客户端，请安装OpenSSH客户端。"

            self.log(f"正在连接到控制柜 ({control_ip})...")
            self.log(f"计算出的MAC地址: {random_mac}")

            # 创建bash脚本
            bash_script = f"""#!/bin/bash

# Check if interfaces file exists
if [ ! -f /etc/network/interfaces ]; then
    echo "FILE_NOT_FOUND"
    exit 1
fi

BACKUP_FILE="/etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/network/interfaces "$BACKUP_FILE" 2>/dev/null

if grep -q "hwaddress ether" /etc/network/interfaces; then
    sed -i "s/.*hwaddress ether [0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}/hwaddress ether {random_mac}/g" /etc/network/interfaces
    sed -i "s/.*#.*hwaddress ether [0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}/hwaddress ether {random_mac}/g" /etc/network/interfaces
    hwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
    echo "UPDATED"
    echo "$hwaddressLine"
else
    awk 'BEGIN{{found=0}} /address[[:space:]]/ && found==0 {{print $0; print "hwaddress ether {random_mac}"; found=1; next}} {{print}}' /etc/network/interfaces > /tmp/interfaces_new 2>&1
    if [ -f /tmp/interfaces_new ]; then
        if grep -q "hwaddress ether" /tmp/interfaces_new; then
            mv /tmp/interfaces_new /etc/network/interfaces
            if grep -q "hwaddress ether" /etc/network/interfaces; then
                hwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
                echo "ADDED"
                echo "$hwaddressLine"
            else
                echo "ERROR: hwaddress ether line was not added to final file"
                exit 1
            fi
        else
            cp /etc/network/interfaces.backup.* /etc/network/interfaces 2>/dev/null || cp "$BACKUP_FILE" /etc/network/interfaces
            sed -i '/address[[:space:]]/a\\hwaddress ether {random_mac}' /etc/network/interfaces
            if grep -q "hwaddress ether" /etc/network/interfaces; then
                hwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
                echo "ADDED"
                echo "$hwaddressLine"
            else
                echo "ERROR: hwaddress ether line was not added by awk or sed"
                exit 1
            fi
        fi
    else
        echo "ERROR: Failed to create new interfaces file"
        exit 1
    fi
fi

# 从保存后的interfaces文件中读取hwaddress ether行
if [ -f /etc/network/interfaces ]; then
    finalHwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
    if [ -n "$finalHwaddressLine" ]; then
        echo "FINAL_HWADDRESS_LINE"
        echo "$finalHwaddressLine"
    fi
fi
"""

            # 编码为base64
            script_bytes = bash_script.encode('utf-8')
            script_base64 = base64.b64encode(script_bytes).decode('utf-8')

            # 构建SSH命令
            bash_command = f'echo "{script_base64}" | base64 -d | bash'

            self.log("正在通过SSH连接...")
            self.log("密码提示：root")

            # 尝试使用sshpass（如果可用）
            sshpass_available = False
            try:
                sshpass_result = subprocess.run(
                    ["where", "sshpass"],
                    capture_output=True,
                    timeout=2
                )
                if sshpass_result.returncode == 0:
                    sshpass_available = True
            except:
                pass

            if sshpass_available:
                # 使用sshpass自动输入密码
                ssh_cmd = [
                    "sshpass", "-p", password,
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=NUL",
                    "-o", "LogLevel=ERROR",
                    f"{username}@{control_ip}",
                    bash_command
                ]
            else:
                # 没有sshpass，提示用户手动输入
                self.log("注意：未找到sshpass，需要手动输入SSH密码")
                self.log("请在新打开的命令行窗口中执行以下命令：")
                self.log(f'ssh -o StrictHostKeyChecking=no {username}@{control_ip} "{bash_command}"')
                self.log("密码：root")
                return False, "需要手动输入SSH密码。请按照提示在命令行中执行。"

            # 执行SSH命令（增加超时时间）
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=60  # 增加超时时间到60秒
            )

            # 解析结果
            output = result.stdout
            error = result.stderr

            # 过滤SSH警告信息
            filtered_output = []
            for line in output.split('\n'):
                if not any(x in line for x in [
                    "Warning: Permanently added",
                    "cannot stat",
                    "No such file or directory",
                    "^cp:"
                ]):
                    filtered_output.append(line)

            output = '\n'.join(filtered_output)

            if result.returncode == 0 or "UPDATED" in output or "ADDED" in output:
                # 提取hwaddress ether行
                hwaddress_line = None
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    line = line.strip()
                    if line == "FINAL_HWADDRESS_LINE" and i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if "hwaddress ether" in next_line:
                            hwaddress_line = next_line
                            break
                    elif "hwaddress ether" in line and re.search(r'[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', line):
                        hwaddress_line = line

                if hwaddress_line:
                    return True, hwaddress_line
                elif "UPDATED" in output:
                    return True, "hwaddress ether更新成功"
                elif "ADDED" in output:
                    return True, "hwaddress ether添加成功"
                else:
                    return True, "MAC地址更新成功"
            elif "FILE_NOT_FOUND" in output:
                return False, "未找到interfaces文件"
            elif "Permission denied" in error or "Authentication failed" in error:
                return False, "SSH密码验证失败"
            elif "Connection" in error or "timed out" in error or "10060" in error:
                return False, "控制柜连接失败: 连接超时"
            else:
                return False, f"更新失败: {error or output}"

        except subprocess.TimeoutExpired:
            return False, "SSH连接超时"
        except Exception as e:
            return False, f"更新过程中出错: {str(e)}"

    def _update_mac_with_paramiko(self, control_ip, username, password, random_mac=None):
        """使用paramiko库更新MAC地址（更可靠的方法）"""
        import paramiko

        try:
            self.log(f"正在连接到控制柜 ({control_ip})...")

            # 如果没有提供MAC地址，则生成一个
            if random_mac is None:
                random_mac = self.generate_mac_address()
            self.log(f"计算出的MAC地址: {random_mac}")

            # 创建SSH客户端
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # 连接（增加超时时间，支持ping通但SSH响应慢的情况）
            try:
                ssh.connect(
                    control_ip,
                    username=username,
                    password=password,
                    timeout=30,  # 增加超时时间到30秒
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=30  # 增加banner超时时间
                )
            except paramiko.AuthenticationException:
                return False, "SSH密码验证失败"
            except paramiko.SSHException as e:
                return False, f"SSH连接失败: {str(e)}"
            except Exception as e:
                return False, f"连接控制柜失败: {str(e)}"

            self.log("SSH连接成功")

            # 创建bash脚本
            bash_script = f"""#!/bin/bash

# Check if interfaces file exists
if [ ! -f /etc/network/interfaces ]; then
    echo "FILE_NOT_FOUND"
    exit 1
fi

BACKUP_FILE="/etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/network/interfaces "$BACKUP_FILE" 2>/dev/null

if grep -q "hwaddress ether" /etc/network/interfaces; then
    sed -i "s/.*hwaddress ether [0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}/hwaddress ether {random_mac}/g" /etc/network/interfaces
    sed -i "s/.*#.*hwaddress ether [0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}:[0-9A-Fa-f]\\{{2\\}}/hwaddress ether {random_mac}/g" /etc/network/interfaces
    hwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
    echo "UPDATED"
    echo "$hwaddressLine"
else
    awk 'BEGIN{{found=0}} /address[[:space:]]/ && found==0 {{print $0; print "hwaddress ether {random_mac}"; found=1; next}} {{print}}' /etc/network/interfaces > /tmp/interfaces_new 2>&1
    if [ -f /tmp/interfaces_new ]; then
        if grep -q "hwaddress ether" /tmp/interfaces_new; then
            mv /tmp/interfaces_new /etc/network/interfaces
            if grep -q "hwaddress ether" /etc/network/interfaces; then
                hwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
                echo "ADDED"
                echo "$hwaddressLine"
            else
                echo "ERROR: hwaddress ether line was not added to final file"
                exit 1
            fi
        else
            cp /etc/network/interfaces.backup.* /etc/network/interfaces 2>/dev/null || cp "$BACKUP_FILE" /etc/network/interfaces
            sed -i '/address[[:space:]]/a\\hwaddress ether {random_mac}' /etc/network/interfaces
            if grep -q "hwaddress ether" /etc/network/interfaces; then
                hwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
                echo "ADDED"
                echo "$hwaddressLine"
            else
                echo "ERROR: hwaddress ether line was not added by awk or sed"
                exit 1
            fi
        fi
    else
        echo "ERROR: Failed to create new interfaces file"
        exit 1
    fi
fi

# 从保存后的interfaces文件中读取hwaddress ether行
if [ -f /etc/network/interfaces ]; then
    finalHwaddressLine=$(grep "hwaddress ether" /etc/network/interfaces | head -1 | sed 's/^[[:space:]]*//')
    if [ -n "$finalHwaddressLine" ]; then
        echo "FINAL_HWADDRESS_LINE"
        echo "$finalHwaddressLine"
    fi
fi
"""

            # 执行命令
            self.log("正在控制柜上执行命令...")
            stdin, stdout, stderr = ssh.exec_command(bash_script)

            # 读取输出
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            exit_status = stdout.channel.recv_exit_status()

            # 关闭连接
            ssh.close()

            # 过滤警告信息
            filtered_output = []
            for line in output.split('\n'):
                if not any(x in line for x in [
                    "Warning: Permanently added",
                    "cannot stat",
                    "No such file or directory",
                    "^cp:"
                ]):
                    filtered_output.append(line)

            output = '\n'.join(filtered_output)

            if exit_status == 0 or "UPDATED" in output or "ADDED" in output:
                # 提取hwaddress ether行
                hwaddress_line = None
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    line = line.strip()
                    if line == "FINAL_HWADDRESS_LINE" and i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if "hwaddress ether" in next_line:
                            hwaddress_line = next_line
                            break
                    elif "hwaddress ether" in line and re.search(r'[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', line):
                        hwaddress_line = line

                if hwaddress_line:
                    return True, hwaddress_line
                elif "UPDATED" in output:
                    return True, "hwaddress ether更新成功"
                elif "ADDED" in output:
                    return True, "hwaddress ether添加成功"
                else:
                    return True, "MAC地址更新成功"
            elif "FILE_NOT_FOUND" in output:
                return False, "未找到interfaces文件"
            else:
                return False, f"更新失败: {error or output}"

        except Exception as e:
            return False, f"更新过程中出错: {str(e)}"


def main():
    root = tk.Tk()
    app = NetworkConfigGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

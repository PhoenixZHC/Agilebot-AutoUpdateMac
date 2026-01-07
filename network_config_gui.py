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

        # 设置窗口图标（如果有的话）
        try:
            self.root.iconbitmap(default='')
        except:
            pass

        # 变量
        self.adapters = []
        self.selected_adapter_index = -1
        self.selected_adapter_name = ""
        self.control_ip = tk.StringVar()
        self.control_password = tk.StringVar(value="root")  # 默认密码
        self.status_text = None
        self.adapter_frames = []  # 存储适配器Frame的引用

        # 创建界面
        self.create_widgets()

        # 加载网络适配器
        self.load_adapters()

    def create_widgets(self):
        # 主框架 - 使用左右布局
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 左侧内容框架
        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        # 右侧状态框架
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 顶部Header区域
        header_frame = ttk.Frame(left_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        # 标题
        title_label = ttk.Label(
            header_frame,
            text="Auto update Mac address",
            font=("Microsoft YaHei UI", 16, "bold")
        )
        title_label.pack(anchor=tk.W)

        # 步骤1：选择网络适配器（点选形式，参考Windows网络连接界面）
        step1_frame = ttk.LabelFrame(left_frame, text="步骤 1: 选择网络适配器", padding="10")
        step1_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # 配置步骤框架样式
        style = ttk.Style()
        try:
            style.configure("Step.TLabelframe", borderwidth=2, relief=tk.SOLID)
            style.configure("Step.TLabelframe.Label", font=("Microsoft YaHei UI", 10, "bold"))
        except:
            pass

        # 标题栏
        header_frame = ttk.Frame(step1_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(header_frame, text="网络适配器:", font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT)
        refresh_btn = ttk.Button(header_frame, text="刷新列表", command=self.load_adapters)
        refresh_btn.pack(side=tk.RIGHT, padx=(10, 0))

        # 创建可滚动的适配器列表容器
        adapter_container = ttk.Frame(step1_frame)
        adapter_container.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # 创建Canvas和Scrollbar用于滚动（移除固定高度，让其自适应）
        canvas = tk.Canvas(adapter_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(adapter_container, orient="vertical", command=canvas.yview)
        self.adapter_list_frame = ttk.Frame(canvas)

        # 配置滚动
        self.adapter_list_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.adapter_list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 绑定鼠标滚轮
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        self.adapter_canvas = canvas
        self.adapter_list_frame_ref = self.adapter_list_frame

        # 配置权重
        step1_frame.columnconfigure(0, weight=1)
        step1_frame.rowconfigure(1, weight=1)
        adapter_container.columnconfigure(0, weight=1)
        adapter_container.rowconfigure(0, weight=1)

        # 步骤2：输入控制柜IP和密码
        step2_frame = ttk.LabelFrame(left_frame, text="步骤 2: 输入控制柜信息", padding="10")
        step2_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        ttk.Label(step2_frame, text="控制柜IP地址:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ip_entry = ttk.Entry(step2_frame, textvariable=self.control_ip)
        ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)

        ttk.Label(step2_frame, text="控制柜密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(step2_frame, textvariable=self.control_password, show="*")
        password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)

        # 步骤3：显示计算出的配置
        step3_frame = ttk.LabelFrame(left_frame, text="步骤 3: 网络配置信息", padding="10")
        step3_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # 配置信息显示区域使用更好的视觉样式
        info_container = ttk.Frame(step3_frame)
        info_container.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)

        self.local_ip_label = ttk.Label(info_container, text="本地IP地址: 未计算", foreground="gray", font=("Microsoft YaHei UI", 9))
        self.local_ip_label.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=3)

        self.subnet_mask_label = ttk.Label(info_container, text="子网掩码: 未计算", foreground="gray", font=("Microsoft YaHei UI", 9))
        self.subnet_mask_label.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=3)

        self.mac_address_label = ttk.Label(info_container, text="MAC地址: 未计算", foreground="gray", font=("Microsoft YaHei UI", 9))
        self.mac_address_label.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=3)

        info_container.columnconfigure(0, weight=1)

        # 绑定IP输入事件，自动计算配置
        self.control_ip.trace('w', self.on_ip_changed)

        # 执行按钮区域
        action_frame = ttk.Frame(left_frame)
        action_frame.grid(row=4, column=0, columnspan=2, pady=15, sticky=(tk.W, tk.E))

        # 按钮容器，居中显示
        button_container = ttk.Frame(action_frame)
        button_container.pack(expand=True)

        self.execute_btn = ttk.Button(
            button_container,
            text="开始配置",
            command=self.execute_configuration,
            width=15
        )
        self.execute_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            button_container,
            text="停止",
            command=self.stop_execution,
            state=tk.DISABLED,
            width=15
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 状态显示区域（右侧）
        status_frame = ttk.LabelFrame(right_frame, text="执行状态", padding="10")
        status_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#1E1E1E",  # 深色背景
            fg="#D4D4D4",  # 浅色文字
            insertbackground="#FFFFFF",  # 光标颜色
            selectbackground="#264F78",  # 选中背景
            selectforeground="#FFFFFF"  # 选中文字颜色
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
        left_frame.rowconfigure(1, weight=3)  # 适配器列表区域可扩展
        left_frame.rowconfigure(2, weight=1)  # 步骤2可扩展
        left_frame.rowconfigure(3, weight=1)  # 步骤3可扩展
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)
        step1_frame.columnconfigure(0, weight=1)
        step1_frame.rowconfigure(1, weight=1)
        step2_frame.columnconfigure(1, weight=1)  # 输入框列可扩展
        step3_frame.columnconfigure(0, weight=1)  # 信息显示列可扩展

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

    def load_adapters(self):
        """加载网络适配器列表"""
        try:
            self.log("正在获取网络适配器列表...", level="INFO")

            # 使用PowerShell获取适配器信息（包括连接名称）
            # 确保使用UTF-8编码以支持Unicode字符（中文、日文、韩文等）
            ps_cmd = """
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            $OutputEncoding = [System.Text.Encoding]::UTF8
            $adapters = Get-NetAdapter | Select-Object Name, Status, InterfaceDescription
            $result = @()
            foreach ($adapter in $adapters) {
                $connection = Get-NetConnectionProfile -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue
                $connectionName = if ($connection) { $connection.Name } else { "" }
                $result += @{
                    Name = $adapter.Name
                    Status = $adapter.Status
                    InterfaceDescription = $adapter.InterfaceDescription
                    ConnectionName = $connectionName
                }
            }
            $result | ConvertTo-Json -Depth 10
            """

            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                 "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8; " + ps_cmd],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'  # 使用replace而不是ignore，确保Unicode字符正确处理
            )

            if result.returncode == 0:
                import json
                try:
                    # 确保JSON解析时正确处理Unicode
                    adapters_data = json.loads(result.stdout, strict=False)
                    if not isinstance(adapters_data, list):
                        adapters_data = [adapters_data]

                    self.adapters = []

                    for adapter in adapters_data:
                        # 确保所有字符串字段都正确处理Unicode
                        name = str(adapter.get('Name', '')).strip()
                        status = str(adapter.get('Status', '')).strip()
                        desc = str(adapter.get('InterfaceDescription', '')).strip()
                        conn_name = str(adapter.get('ConnectionName', '')).strip()

                        if name:
                            self.adapters.append({
                                'name': name,
                                'status': status,
                                'description': desc,
                                'connection_name': conn_name
                            })

                    # 创建适配器列表显示
                    self._create_adapter_list()

                    self.log(f"找到 {len(self.adapters)} 个网络适配器")
                except json.JSONDecodeError:
                    # 如果JSON解析失败，尝试使用netsh
                    self.load_adapters_netsh()
            else:
                # 使用netsh作为备用方案
                self.load_adapters_netsh()

        except Exception as e:
            self.log(f"获取适配器列表时出错: {str(e)}", level="ERROR")
            messagebox.showerror("错误", f"无法获取网络适配器列表: {str(e)}")

    def _create_adapter_list(self):
        """创建适配器列表显示（点选形式，参考Windows网络连接界面）"""
        # 清除现有的适配器Frame
        for frame in self.adapter_frames:
            frame.destroy()
        self.adapter_frames = []

        # 创建样式
        style = ttk.Style()
        try:
            style.configure("Selected.TFrame", background="#E3F2FD")
            style.configure("Selected.TLabel", background="#E3F2FD", foreground="#1976D2")
        except:
            pass

        # 为每个适配器创建可点击的Frame
        for i, adapter in enumerate(self.adapters):
            name = adapter['name']
            status = adapter['status']
            desc = adapter['description']
            status_text = self._get_status_text(status)

            # 创建适配器Frame（可点击）
            adapter_frame = ttk.Frame(self.adapter_list_frame_ref, relief=tk.RAISED, borderwidth=1)
            adapter_frame.grid(row=i, column=0, sticky=(tk.W, tk.E), padx=2, pady=2)
            adapter_frame.bind("<Button-1>", lambda e, idx=i: self.on_adapter_clicked(idx))

            # 适配器名称（左侧，加粗）
            # 使用支持Unicode的字体
            name_label = ttk.Label(
                adapter_frame,
                text=name,
                font=("Microsoft YaHei UI", 9, "bold"),
                anchor="w"
            )
            name_label.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
            name_label.bind("<Button-1>", lambda e, idx=i: self.on_adapter_clicked(idx))

            # 状态（右侧，绿色或灰色）
            status_color = "#4CAF50" if status_text == "已连接" else "#757575"
            status_label = ttk.Label(
                adapter_frame,
                text=status_text,
                foreground=status_color,
                font=("Microsoft YaHei UI", 9),  # 使用支持Unicode的字体
                anchor="e"
            )
            status_label.grid(row=0, column=1, sticky=tk.E, padx=10, pady=5)
            status_label.bind("<Button-1>", lambda e, idx=i: self.on_adapter_clicked(idx))

            # 描述信息（第二行，完整显示）
            if desc:
                desc_label = ttk.Label(
                    adapter_frame,
                    text=f"({desc})",
                    font=("Microsoft YaHei UI", 8),  # 使用支持Unicode的字体
                    foreground="#666666",
                    anchor="w"
                )
                desc_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 5))
                desc_label.bind("<Button-1>", lambda e, idx=i: self.on_adapter_clicked(idx))

            # 配置列权重
            adapter_frame.columnconfigure(0, weight=1)
            adapter_frame.columnconfigure(1, weight=0)

            self.adapter_frames.append(adapter_frame)

        # 默认选择第一个适配器
        if len(self.adapters) > 0:
            self.on_adapter_clicked(0)

        # 更新Canvas滚动区域
        self.adapter_list_frame_ref.update_idletasks()
        self.adapter_canvas.configure(scrollregion=self.adapter_canvas.bbox("all"))

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
            error_text += f"   本地IP: {local_ip}\n"
            error_text += "4. 本地IP在同一子网\n"
            error_text += "\n提示：请确保控制柜已启动，网线连接正常，\n"
            error_text += "并且本地IP地址与控制柜IP在同一子网内。"
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
            self.log(f"   本地IP: {local_ip}", level="INFO")
            self.log("4. 本地IP在同一子网", level="WARNING")
            self.log("提示：请确保控制柜已启动，网线连接正常，并且本地IP地址与控制柜IP在同一子网内。", level="ERROR")
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


    def _get_status_text(self, status):
        """将状态转换为中文显示"""
        status_lower = str(status).lower()
        if status_lower in ['up', 'connected', '已连接']:
            return "已连接"
        elif status_lower in ['down', 'disconnected', '已断开连接']:
            return "未连接"
        elif 'cable' in status_lower or '电缆' in status_lower:
            return "网络电缆被拔出"
        elif 'enabled' in status_lower or '已启用' in status_lower:
            return "已启用"
        else:
            return str(status)

    def load_adapters_netsh(self):
        """使用netsh获取适配器列表（备用方案）"""
        try:
            # 使用UTF-8编码以支持Unicode字符
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                encoding='utf-8',  # 改为UTF-8以支持Unicode
                errors='replace'  # 使用replace确保Unicode字符正确处理
            )

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                self.adapters = []
                adapter_names = []

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # 跳过标题行
                    if 'State' in line or '状态' in line or line.startswith('---'):
                        continue

                    # 使用正则表达式匹配，支持中英文
                    # 格式：状态 类型 管理状态 名称
                    # 例如：Connected Dedicated Enabled "以太网"
                    # 或者：已连接 专用 已启用 "WLAN"
                    match = re.match(r'^(\S+)\s+(\S+)\s+(\S+)\s+(.+)$', line)
                    if match:
                        status = match.group(1)
                        name = match.group(4).strip().strip('"').strip("'")

                        if name:
                            self.adapters.append({
                                'name': name,
                                'status': status,
                                'description': '',
                                'connection_name': ''
                            })

                # 创建适配器列表显示
                self._create_adapter_list()

                self.log(f"找到 {len(self.adapters)} 个网络适配器")
        except Exception as e:
            self.log(f"使用netsh获取适配器时出错: {str(e)}", "red")

    def on_adapter_clicked(self, index):
        """适配器点击事件"""
        if 0 <= index < len(self.adapters):
            # 更新选中状态
            self.selected_adapter_index = index
            adapter = self.adapters[index]
            self.selected_adapter_name = adapter['name']

            # 更新所有适配器Frame的显示状态
            self._update_adapter_selection()

            # 记录日志
            self.log(f"已选择适配器: {adapter['name']}")

    def _update_adapter_selection(self):
        """更新适配器选择状态的显示"""
        for i, frame in enumerate(self.adapter_frames):
            if i == self.selected_adapter_index:
                # 选中状态：蓝色背景
                frame.configure(style="Selected.TFrame")
                for widget in frame.winfo_children():
                    if isinstance(widget, ttk.Label):
                        widget.configure(style="Selected.TLabel")
            else:
                # 未选中状态：默认样式
                frame.configure(style="TFrame")
                for widget in frame.winfo_children():
                    if isinstance(widget, ttk.Label):
                        widget.configure(style="TLabel")

    def on_ip_changed(self, *args):
        """IP地址改变时自动计算配置"""
        ip = self.control_ip.get().strip()
        if not ip:
            self.local_ip_label.config(text="本地IP地址: 未计算", foreground="gray")
            self.subnet_mask_label.config(text="子网掩码: 未计算", foreground="gray")
            self.mac_address_label.config(text="MAC地址: 未计算", foreground="gray")
            return

        try:
            # 验证IP格式
            ipaddress.ip_address(ip)

            # 计算子网掩码
            subnet_mask = self.calculate_subnet_mask(ip)

            # 计算本地IP（同子网，最后一位随机2-255）
            local_ip = self.calculate_local_ip(ip)

            # 生成MAC地址
            mac_address = self.generate_mac_address()

            # 更新步骤3的配置信息
            self.local_ip_label.config(text=f"本地IP地址: {local_ip}", foreground="green")
            self.subnet_mask_label.config(text=f"子网掩码: {subnet_mask}", foreground="green")
            self.mac_address_label.config(text=f"MAC地址: {mac_address}", foreground="green")
        except ValueError:
            self.local_ip_label.config(text="本地IP地址: IP格式无效", foreground="red")
            self.subnet_mask_label.config(text="子网掩码: IP格式无效", foreground="red")
            self.mac_address_label.config(text="MAC地址: IP格式无效", foreground="red")
        except Exception as e:
            self.local_ip_label.config(text=f"本地IP地址: 计算错误", foreground="red")
            self.subnet_mask_label.config(text=f"子网掩码: 计算错误", foreground="red")
            self.mac_address_label.config(text=f"MAC地址: 计算错误", foreground="red")

    def calculate_subnet_mask(self, ip):
        """计算子网掩码"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            first_byte = int(ip_obj.packed[0])

            if first_byte == 10:
                return "255.0.0.0"
            elif first_byte == 172 and 16 <= int(ip_obj.packed[1]) <= 31:
                return "255.255.0.0"
            elif first_byte == 192 and int(ip_obj.packed[1]) == 168:
                return "255.255.255.0"
            else:
                return "255.255.255.0"
        except:
            return "255.255.255.0"

    def calculate_local_ip(self, control_ip):
        """计算本地IP地址"""
        try:
            ip_obj = ipaddress.ip_address(control_ip)
            ip_bytes = bytearray(ip_obj.packed)
            control_last_byte = ip_bytes[3]

            # 生成一个不同于控制柜IP最后一位的数字（2-255）
            # 如果控制柜IP最后一位是2-255，则排除它
            available_values = [i for i in range(2, 256) if i != control_last_byte]
            if not available_values:
                # 如果所有值都被排除（理论上不会发生），使用2
                available_values = [2]

            ip_bytes[3] = random.choice(available_values)
            return str(ipaddress.ip_address(bytes(ip_bytes)))
        except:
            return None

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
        if self.selected_adapter_index < 0 or not self.selected_adapter_name:
            messagebox.showerror("错误", "请选择网络适配器！")
            return

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
        self.stop_btn.config(state=tk.NORMAL)
        self.is_running = True
        self.stop_flag = False

        # 在新线程中执行
        thread = threading.Thread(target=self._execute_configuration_thread)
        thread.daemon = True
        thread.start()

    def stop_execution(self):
        """停止执行"""
        self.stop_flag = True
        self.log("正在停止...")

    def _execute_configuration_thread(self):
        """执行配置的线程函数"""
        try:
            # 获取选中的适配器名称
            adapter_name = self.selected_adapter_name

            control_ip = self.control_ip.get().strip()
            subnet_mask = self.calculate_subnet_mask(control_ip)
            local_ip = self.calculate_local_ip(control_ip)

            self.log("=" * 50)
            self.log("开始配置网络...")
            self.log(f"控制柜IP: {control_ip}")
            self.log(f"本地IP: {local_ip}")
            self.log(f"子网掩码: {subnet_mask}")
            self.log(f"网络适配器: {adapter_name}")
            self.log("=" * 50)

            # 步骤1：配置本地网络
            self.log("\n步骤 1: 配置本地网络", level="INFO")
            success, message = self.set_static_ip(adapter_name, local_ip, subnet_mask)

            if not success:
                self.log(f"配置失败: {message}", level="ERROR")
                self.root.after(0, lambda: messagebox.showerror("错误", f"网络配置失败:\n{message}"))
                self._reset_buttons()
                return

            self.log(f"配置成功: {message}", level="SUCCESS")
            # 保存配置的值，以便后续更新时使用
            self._last_configured_local_ip = local_ip
            self._last_configured_subnet_mask = subnet_mask
            # 更新步骤3的本地IP和子网掩码显示
            self._update_step3_display(local_ip=local_ip, subnet_mask=subnet_mask)
            self.log("等待网络稳定...", level="INFO")
            time.sleep(3)

            if self.stop_flag:
                self.log("已停止")
                self._reset_buttons()
                return

            # 步骤2：更新控制柜MAC地址
            self.log("\n步骤 2: 更新控制柜MAC地址", level="INFO")
            # 获取密码
            password = self.control_password.get().strip() or "root"
            # 保存local_ip用于错误信息显示
            self._last_local_ip = local_ip
            mac_success, mac_message = self.update_control_cabinet_mac(control_ip, password=password)

            # 无论成功或失败，都更新步骤3的MAC地址显示（使用计算出的MAC地址）
            # 更新步骤3的MAC地址显示，同时保留local_ip和subnet_mask
            self._update_step3_display(local_ip=local_ip, subnet_mask=subnet_mask, mac_address=mac_message)

            if mac_success:
                self.log(f"MAC地址更新成功", level="SUCCESS")
                if mac_message:
                    self.log(mac_message, level="SUCCESS")
                self.root.after(0, lambda: messagebox.showinfo("成功", "MAC地址更新成功！"))
            else:
                self.log(f"MAC地址更新失败: {mac_message}", level="ERROR")
                # 在日志中显示详细错误信息（包含故障排除建议）
                self._log_error_with_troubleshooting(mac_message, control_ip, self._last_local_ip or local_ip)

                # 生成友好的错误信息，包含故障排除建议
                error_msg = self._format_connection_error(mac_message, control_ip, self._last_local_ip or local_ip)
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("MAC地址更新失败", msg))

        except Exception as e:
            self.log(f"执行过程中出错: {str(e)}", "red")
            self.root.after(0, lambda: messagebox.showerror("错误", f"执行过程中出错:\n{str(e)}"))
        finally:
            self._reset_buttons()

    def _reset_buttons(self):
        """重置按钮状态"""
        self.root.after(0, lambda: self.execute_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
        self.is_running = False

    def _update_step3_display(self, local_ip=None, subnet_mask=None, mac_address=None):
        """更新步骤3的显示信息"""
        # 如果没有传递local_ip，尝试使用保存的值
        if not local_ip and hasattr(self, '_last_configured_local_ip'):
            local_ip = self._last_configured_local_ip
        # 如果没有传递subnet_mask，尝试使用保存的值
        if not subnet_mask and hasattr(self, '_last_configured_subnet_mask'):
            subnet_mask = self._last_configured_subnet_mask

        if local_ip:
            self.root.after(0, lambda ip=local_ip: self.local_ip_label.config(
                text=f"本地IP地址: {ip}", foreground="green"))
        if subnet_mask:
            self.root.after(0, lambda sm=subnet_mask: self.subnet_mask_label.config(
                text=f"子网掩码: {sm}", foreground="green"))
        # 更新MAC地址显示（优先使用保存的生成MAC地址）
        if hasattr(self, '_last_generated_mac') and self._last_generated_mac:
            # 优先使用保存的生成MAC地址（这是实际计算出的MAC地址，与执行状态中显示的一致）
            mac = self._last_generated_mac
            self.root.after(0, lambda m=mac: self.mac_address_label.config(
                text=f"MAC地址: {m}", foreground="green"))
        elif mac_address:
            # 如果消息中包含MAC地址，尝试从消息中提取（作为备用）
            mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', str(mac_address))
            if mac_match:
                mac = mac_match.group(1)
                self.root.after(0, lambda m=mac: self.mac_address_label.config(
                    text=f"MAC地址: {m}", foreground="green"))

    def set_static_ip(self, adapter_name, ip_address, subnet_mask, gateway=None):
        """设置静态IP地址"""
        try:
            self.log(f"正在检查并更新IP配置...")

            # 先尝试移除现有配置（如果存在），忽略错误
            remove_result = subprocess.run(
                ["netsh", "interface", "ipv4", "delete", "address",
                 f"name={adapter_name}", f"address={ip_address}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(0.5)

            # 设置新配置（即使IP已存在，也会更新配置）
            self.log(f"正在设置IP配置...")
            if gateway:
                cmd = ["netsh", "interface", "ipv4", "set", "address",
                       f"name={adapter_name}", "source=static",
                       f"address={ip_address}", f"mask={subnet_mask}",
                       f"gateway={gateway}"]
            else:
                cmd = ["netsh", "interface", "ipv4", "set", "address",
                       f"name={adapter_name}", "source=static",
                       f"address={ip_address}", f"mask={subnet_mask}"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',  # 改为UTF-8以支持Unicode
                errors='replace'  # 使用replace确保Unicode字符正确处理
            )

            if result.returncode == 0:
                return True, f"IP配置成功 (IP: {ip_address}, 掩码: {subnet_mask})"
            else:
                # 如果设置失败，尝试先删除所有IP配置，然后重新设置
                error_msg = result.stderr or result.stdout or "未知错误"
                # 尝试删除所有IP地址配置
                subprocess.run(
                    ["netsh", "interface", "ipv4", "delete", "address",
                     f"name={adapter_name}", "all"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(0.5)
                # 重新尝试设置
                retry_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                if retry_result.returncode == 0:
                    return True, f"IP配置成功 (IP: {ip_address}, 掩码: {subnet_mask})"
                else:
                    return False, error_msg

        except Exception as e:
            return False, str(e)

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

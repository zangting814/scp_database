import hashlib
import tkinter as tk
from tkinter import ttk, messagebox
import json
from datetime import datetime
import socket
import os
import numpy as np
# import matplotlib.pyplot as plt
import pandas as pd
# import mglearn 
#coding:utf-8
# import pygame,
import sys,random,time,easygui
# from pygame.locals import *
#初始化pygame环境
# pygame.init()


class SCPDatabaseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SCP基金会机密数据库")
        self.root.geometry("1200x800")
        
        # 初始化数据库文件
        self.db_file = "scp_database.json"
        self.user_db = "users.json"
        self.log_file = "access_log.txt"
        self.initialize_files()
        
        # 记录访问IP
        self.log_access()
        
        # 显示登录界面
        self.show_login()

        # 显示登出界面
        self.logout()
    
#    def logout(self):
#        """登出"""
#        outname = easygui.enterbox('登出 Sing Out')
#        out = outname

#    def register(self):
#       easygui.enterbox('再见，' + self.out) 
#        pygame.quit()
#        sys.exit()  
  

    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    
    def logout(self):
        """完善登出功能"""
        if hasattr(self, 'current_user'):
            messagebox.showinfo("登出", f"再见，{self.current_user['username']}")
            del self.current_user
        self.show_login()

    def initialize_files(self):
        """统一初始化所有文件"""
        files = {
            self.db_file: {"scps": []},
            self.user_db: {"users": []},
            self.log_file: "SCP数据库访问日志\n"
        }
        
        for file, default_content in files.items():
            if not os.path.exists(file):
                with open(file, 'w') as f:
                    if isinstance(default_content, dict):
                        json.dump(default_content, f)
                    else:
                        f.write(default_content)

    def show_main_interface(self):
        """优化主界面显示"""
        self.clear_window()
        
        # 创建主界面元素
        self.canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.draw_scp_interface()
        
    # 其余界面代码...

    def log_access(self):
        """记录访问者IPv4地址和时间"""
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(self.log_file, 'a') as f:
                f.write(f"[{timestamp}]访问IP: {ip}\n")
        except Exception as e:
            print(f"日志记录失败: {e}")
        
        # 日志文件
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("SCP数据库访问日志\n")

    def initialize_files(self):
        """初始化所有必要文件"""
        # SCP数据库
        if not os.path.exists(self.db_file):
            with open(self.db_file, 'w') as f:
                json.dump({"scps": []}, f)
        
        # 用户数据库
        if not os.path.exists(self.user_db):
            with open(self.user_db, 'w') as f:
                json.dump({"users": []}, f)
        
        # 日志文件
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("SCP数据库访问日志\n")

    def show_login(self):
        """显示登录/注册界面"""
        self.clear_window()
        
        # SCP风格装饰
        self.canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.draw_scp_interface()
        
        # 登录框
        login_frame = tk.Frame(self.canvas, bg="#222", padx=20, pady=20)
        self.canvas.create_window(600, 400, window=login_frame)
        
        tk.Label(login_frame, text="☣ SCP数据库访问认证 ☣", 
                fg="red", bg="#222", font=("Arial", 16)).pack(pady=10)
        
        # 用户名
        tk.Label(login_frame, text="用户名:", fg="white", bg="#222").pack()
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.pack(pady=5)
        
        # 密码
        tk.Label(login_frame, text="密码:", fg="white", bg="#222").pack()
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.pack(pady=5)
        
        # 按钮
        btn_frame = tk.Frame(login_frame, bg="#222")
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="登录", command=self.attempt_login).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="注册", command=self.show_register).pack(side=tk.LEFT, padx=5)

    def draw_scp_interface(self):
        """绘制SCP风格界面元素"""
        # 清除现有内容
        self.canvas.delete("all")
        
        # 黑色背景
        self.canvas.create_rectangle(0, 0, 1200, 800, fill="black", outline="")
        
        # 红色边框
        self.canvas.create_rectangle(10, 10, 1190, 790, outline="#ff0000", width=5)
        
        # 标题
        self.canvas.create_text(600, 50, text="☣ SCP 机密数据库 ☣", 
                            fill="#ff0000", font=("Arial", 24, "bold"))
        
        # 装饰线
        self.canvas.create_line(100, 100, 1100, 100, fill="#ff0000", width=2)
        self.canvas.create_line(100, 700, 1100, 700, fill="#ff0000", width=2)
        
        # 警告标语
        self.canvas.create_text(600, 750, text="未经授权的访问将受到纪律处分",
                            fill="#ff0000", font=("Arial", 12))

    def show_register(self):
        """显示注册窗口"""
        register_window = tk.Toplevel(self.root)
        register_window.title("新用户注册")
        register_window.geometry("400x300")
        
        tk.Label(register_window, text="新用户注册", font=("Arial", 14)).pack(pady=10)
        
        # 表单
        tk.Label(register_window, text="用户名:").pack()
        new_user_entry = ttk.Entry(register_window)
        new_user_entry.pack(pady=5)
        
        tk.Label(register_window, text="密码:").pack()
        new_pass_entry = ttk.Entry(register_window, show="*")
        new_pass_entry.pack(pady=5)
        
        tk.Label(register_window, text="确认密码:").pack()
        confirm_pass_entry = ttk.Entry(register_window, show="*")
        confirm_pass_entry.pack(pady=5)
        
        def submit_registration():
            username = new_user_entry.get()
            password = new_pass_entry.get()
            confirm = confirm_pass_entry.get()
            
            if not username or not password:
                messagebox.showerror("错误", "用户名和密码不能为空")
                return
                
            if password != confirm:
                messagebox.showerror("错误", "密码不匹配")
                return
                
            # 检查用户是否存在
            with open(self.user_db, 'r') as f:
                data = json.load(f)
                if any(u['username'] == username for u in data['users']):
                    messagebox.showerror("错误", "用户名已存在")
                    return
            
            new_user = {
                "username": username,
                "password": hash_password(password),  # 存储哈希值
                "access_level": "user"
            }

            data['users'].append(new_user)
            with open(self.user_db, 'w') as f:
                json.dump(data, f, indent=4)
            
            messagebox.showinfo("成功", "注册成功！请登录")
            register_window.destroy()
        
        ttk.Button(register_window, text="注册", command=submit_registration).pack(pady=10)

    def attempt_login(self):
        """尝试登录"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        with open(self.user_db, 'r') as f:
            data = json.load(f)
            user = next((u for u in data['users'] if u['username'] == username and u['password'] == password), None)
            
            if user:
                self.current_user = user
                self.show_main_interface()
            else:
                messagebox.showerror("错误", "无效的用户名或密码")

    def show_main_interface(self):
        """显示主界面"""
        self.clear_window()
        
        # 创建Canvas主界面
        self.canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        # 绘制SCP风格界面
        self.draw_scp_interface()
        
        # 创建数据库操作控件
        self.create_widgets()
        
        # 添加用户信息显示
        user_info = tk.Label(self.root, text=f"登录用户: {self.current_user['username']}", 
                           fg="white", bg="black", anchor="e")
        user_info.pack(fill=tk.X, side=tk.BOTTOM)
        
        # 加载数据
        self.load_data()

    def logout(self):
        easygui.enterbox("")    
    
    def create_widgets(self):
        """创建数据库操作控件"""
        # 主框架
        main_frame = tk.Frame(self.canvas, bg="black")
        self.canvas.create_window(600, 400, window=main_frame, width=1000, height=600)
        
        # SCP列表树状图
        self.tree = ttk.Treeview(main_frame, columns=('id', 'class', 'name'), show='headings')
        self.tree.heading('id', text='条目编号')
        self.tree.heading('class', text='等级')
        self.tree.heading('name', text='名称')
        self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 控制面板
        control_frame = tk.Frame(main_frame, bg="black")
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # 按钮
        ttk.Button(control_frame, text="添加条目", command=self.add_scp).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="查看详情", command=self.view_scp).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="删除条目", command=self.delete_scp).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="刷新列表", command=self.load_data).pack(side=tk.LEFT, padx=5)
        
        # 搜索框
        search_frame = tk.Frame(control_frame, bg="black")
        search_frame.pack(side=tk.RIGHT, padx=5)
        ttk.Label(search_frame, text="搜索:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(search_frame, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="搜索", command=self.search_scp).pack(side=tk.LEFT)
        
        # 加载数据
        self.load_data()

    def load_data(self):
        """加载SCP数据"""
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        try:
            with open(self.db_file, 'r') as f:
                data = json.load(f)
                for scp in data['scps']:
                    self.tree.insert('', tk.END, values=(scp['scp_id'], scp['object_class'], scp['name']))
        except Exception as e:
            messagebox.showerror("错误", f"加载数据库失败: {e}")

    def add_scp(self):
        """添加新SCP"""
        add_window = tk.Toplevel(self.root)
        add_window.title("添加条目")
        add_window.geometry("500x600")
        
        # 表单字段
        tk.Label(add_window, text="条目编号 (如SCP-XXX):").pack(pady=5)
        scp_id_entry = ttk.Entry(add_window)
        scp_id_entry.pack(pady=5)
        
        tk.Label(add_window, text="等级:").pack(pady=5)
        class_entry = ttk.Combobox(add_window, values=["Safe", "Euclid", "Keter", "Thaumiel", "Neutralized"])
        class_entry.pack(pady=5)
        
        tk.Label(add_window, text="名称:").pack(pady=5)
        name_entry = ttk.Entry(add_window)
        name_entry.pack(pady=5)
        
        tk.Label(add_window, text="描述:").pack(pady=5)
        desc_text = tk.Text(add_window, height=10)
        desc_text.pack(pady=5)
        
        tk.Label(add_window, text="收容措施:").pack(pady=5)
        contain_text = tk.Text(add_window, height=10)
        contain_text.pack(pady=5)
        
        def submit():
            new_scp = {
                "scp_id": scp_id_entry.get(),
                "object_class": class_entry.get(),
                "name": name_entry.get(),
                "description": desc_text.get("1.0", tk.END).strip(),
                "containment_procedure": contain_text.get("1.0", tk.END).strip(),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            try:
                with open(self.db_file, 'r+') as f:
                    data = json.load(f)
                    data['scps'].append(new_scp)
                    f.seek(0)
                    json.dump(data, f, indent=4)
                    f.truncate()
                
                messagebox.showinfo("成功", "条目已添加")
                self.load_data()
                add_window.destroy()
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {e}")
        
        ttk.Button(add_window, text="提交", command=submit).pack(pady=10)

    def view_scp(self):
        """查看SCP详情"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("警告", "请先选择一个条目")
            return
            
        scp_id = self.tree.item(selected)['values'][0]
        
        try:
            with open(self.db_file, 'r') as f:
                data = json.load(f)
                scp = next((s for s in data['scps'] if s['scp_id'] == scp_id), None)
                
                if scp:
                    detail_window = tk.Toplevel(self.root)
                    detail_window.title(f"SCP-{scp_id} 详情")
                    detail_window.geometry("800x600")
                    
                    notebook = ttk.Notebook(detail_window)
                    
                    # 基本信息标签页
                    info_frame = ttk.Frame(notebook)
                    notebook.add(info_frame, text="基本信息")
                    
                    ttk.Label(info_frame, text=f"条目编号: {scp['scp_id']}", font=('Arial', 14, 'bold')).pack(pady=10)
                    ttk.Label(info_frame, text=f"等级: {scp['object_class']}").pack(pady=5)
                    ttk.Label(info_frame, text=f"名称: {scp['name']}").pack(pady=5)
                    ttk.Label(info_frame, text=f"创建时间: {scp['created_at']}").pack(pady=5)
                    
                    # 描述标签页
                    desc_frame = ttk.Frame(notebook)
                    notebook.add(desc_frame, text="描述")
                    
                    desc_text = tk.Text(desc_frame, wrap=tk.WORD)
                    desc_text.insert(tk.END, scp['description'])
                    desc_text.config(state=tk.DISABLED)
                    desc_scroll = ttk.Scrollbar(desc_frame, command=desc_text.yview)
                    desc_text['yscrollcommand'] = desc_scroll.set
                    desc_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    desc_scroll.pack(side=tk.RIGHT, fill=tk.Y)
                    
                    # 收容措施标签页
                    contain_frame = ttk.Frame(notebook)
                    notebook.add(contain_frame, text="收容措施")
                    
                    contain_text = tk.Text(contain_frame, wrap=tk.WORD)
                    contain_text.insert(tk.END, scp['containment_procedure'])
                    contain_text.config(state=tk.DISABLED)
                    contain_scroll = ttk.Scrollbar(contain_frame, command=contain_text.yview)
                    contain_text['yscrollcommand'] = contain_scroll.set
                    contain_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    contain_scroll.pack(side=tk.RIGHT, fill=tk.Y)
                    
                    notebook.pack(fill=tk.BOTH, expand=True)
                else:
                    messagebox.showerror("错误", "找不到指定的条目")
        except Exception as e:
            messagebox.showerror("错误", f"读取数据失败: {e}")

    def delete_scp(self):
        """删除SCP条目"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("警告", "请先选择一个条目")
            return
            
        scp_id = self.tree.item(selected)['values'][0]
        
        if messagebox.askyesno("确认", f"确定要删除条目-{scp_id}吗？此操作不可恢复！"):
            try:
                with open(self.db_file, 'r+') as f:
                    data = json.load(f)
                    data['scps'] = [s for s in data['scps'] if s['scp_id'] != scp_id]
                    f.seek(0)
                    json.dump(data, f, indent=4)
                    f.truncate()
                
                messagebox.showinfo("成功", "条目已删除")
                self.load_data()
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {e}")

    def search_scp(self):
        """搜索SCP条目"""
        query = self.search_entry.get().lower()
        if not query:
            self.load_data()
            return
            
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            if any(query in str(v).lower() for v in values):
                self.tree.selection_set(item)
                self.tree.focus(item)
                self.tree.see(item)
            else:
                self.tree.detach(item)

    
    def clear_window(self):
        """清除当前窗口所有内容"""
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SCPDatabaseApp(root)
    root.mainloop()
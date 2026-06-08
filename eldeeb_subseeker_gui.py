#!/usr/bin/env python3
# eldeeb_subseeker_gui_final.py - حل كامل لمشكلة النسخ/لصق + دعم IP بأكثر من دومين

import sys
import asyncio
import threading
import json
import re
import ipaddress
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from typing import Set, List, Dict
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

import customtkinter as ctk
import aiohttp
import dns.resolver
import dns.zone
import dns.query
import dns.reversename

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ========== دوال نسخ/لصق متقدمة ==========
def copy_text(widget):
    """نسخ النص المحدد من أي عنصر"""
    try:
        if isinstance(widget, ctk.CTkEntry):
            inner = widget._entry
            if inner.selection_present():
                text = inner.selection_get()
                widget.clipboard_clear()
                widget.clipboard_append(text)
        elif isinstance(widget, ctk.CTkTextbox):
            inner = widget._textbox
            try:
                text = inner.selection_get()
                widget.clipboard_clear()
                widget.clipboard_append(text)
            except:
                pass
        elif isinstance(widget, (tk.Entry, tk.Text, scrolledtext.ScrolledText)):
            try:
                text = widget.selection_get()
                widget.clipboard_clear()
                widget.clipboard_append(text)
            except:
                pass
    except:
        pass

def paste_text(widget):
    """لصق النص من الحافظة إلى العنصر النشط"""
    try:
        text = widget.clipboard_get()
        if isinstance(widget, ctk.CTkEntry):
            widget._entry.insert("insert", text)
        elif isinstance(widget, ctk.CTkTextbox):
            widget._textbox.insert("insert", text)
        elif isinstance(widget, (tk.Entry, tk.Text, scrolledtext.ScrolledText)):
            widget.insert("insert", text)
    except:
        pass

def cut_text(widget):
    """قص النص المحدد"""
    try:
        if isinstance(widget, ctk.CTkEntry):
            inner = widget._entry
            if inner.selection_present():
                text = inner.selection_get()
                widget.clipboard_clear()
                widget.clipboard_append(text)
                inner.delete("sel.first", "sel.last")
        elif isinstance(widget, ctk.CTkTextbox):
            inner = widget._textbox
            try:
                text = inner.selection_get()
                widget.clipboard_clear()
                widget.clipboard_append(text)
                inner.delete("sel.first", "sel.last")
            except:
                pass
        elif isinstance(widget, (tk.Entry, tk.Text, scrolledtext.ScrolledText)):
            try:
                text = widget.selection_get()
                widget.clipboard_clear()
                widget.clipboard_append(text)
                widget.delete("sel.first", "sel.last")
            except:
                pass
    except:
        pass

def select_all(widget):
    """تحديد كل النص في العنصر"""
    try:
        if isinstance(widget, ctk.CTkEntry):
            widget._entry.selection_range(0, "end")
            widget._entry.icursor("end")
        elif isinstance(widget, ctk.CTkTextbox):
            widget._textbox.tag_add("sel", "1.0", "end")
            widget._textbox.mark_set("insert", "end")
        elif isinstance(widget, (tk.Entry, tk.Text, scrolledtext.ScrolledText)):
            widget.tag_add("sel", "1.0", "end")
            widget.mark_set("insert", "end")
    except:
        pass

def show_context_menu(widget, event):
    """قائمة السياق بزر الفأرة الأيمن"""
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="نسخ", command=lambda: copy_text(widget))
    menu.add_command(label="لصق", command=lambda: paste_text(widget))
    menu.add_command(label="قص", command=lambda: cut_text(widget))
    menu.add_separator()
    menu.add_command(label="تحديد الكل", command=lambda: select_all(widget))
    menu.post(event.x_root, event.y_root)

def enable_global_copy_paste(root):
    """تمكين الاختصارات والقوائم لكل العناصر الموجودة والمستقبلية"""
    # ربط الاختصارات على مستوى النافذة
    root.bind_all("<Control-c>", lambda e: copy_text(root.focus_get()))
    root.bind_all("<Control-v>", lambda e: paste_text(root.focus_get()))
    root.bind_all("<Control-x>", lambda e: cut_text(root.focus_get()))
    root.bind_all("<Control-a>", lambda e: select_all(root.focus_get()))
    # ربط زر الفأرة الأيمن لأي عنصر سيتم إنشاؤه (سنقوم بذلك يدويًا عند إنشاء العناصر)

# ========== النواة الهندسية المتطورة مع دعم IP متعدد الدومينات ==========
class EldeebSubSeekerCore:
    def __init__(self, target: str, recursive: bool = False, threads: int = 150,
                 hidden_mode: bool = False, wordlist_path: str = None, progress_callback=None):
        self.original_target = target.strip()
        self.all_root_domains: Set[str] = set()   # النطاقات الرئيسية المستخرجة من IP
        self.recursive = recursive
        self.threads = threads
        self.hidden_mode = hidden_mode
        self.wordlist_path = wordlist_path
        self.found_domains: Set[str] = set()
        self.semaphore = None
        self.session = None
        self.progress_callback = progress_callback
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    async def update_progress(self, value: int, msg: str):
        if self.progress_callback:
            await self.progress_callback(value, msg)

    async def fetch(self, url: str, headers: Dict = None) -> str:
        if self._stop_flag:
            return ""
        async with self.semaphore:
            try:
                async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    return ""
            except:
                return ""

    async def get_all_domains_by_ip(self, ip: str) -> Set[str]:
        """الحصول على جميع النطاقات التي تم حلها لهذا الـ IP باستخدام AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
        data = await self.fetch(url)
        if not data:
            return set()
        try:
            js = json.loads(data)
            domains = set()
            for record in js.get('passive_dns', []):
                hostname = record.get('hostname', '')
                if hostname:
                    domains.add(hostname)
            # استخراج النطاقات الرئيسية (أعلى مستوى، مثل newegg.com من sub.newegg.com)
            root_domains = set()
            for domain in domains:
                parts = domain.split('.')
                if len(parts) >= 2:
                    root_domains.add('.'.join(parts[-2:]))
                else:
                    root_domains.add(domain)
            return root_domains
        except:
            return set()

    async def get_domain_from_ptr(self, ip: str) -> str:
        """محاولة الحصول على نطاق واحد من PTR"""
        try:
            rev = dns.reversename.from_address(ip)
            ptr = str(dns.resolver.resolve(rev, "PTR")[0]).rstrip('.')
            parts = ptr.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return ptr
        except:
            return ""

    async def scan_domain(self, domain: str) -> Set[str]:
        """مسح نطاق واحد باستخدام المصادر الأساسية والتقنيات المخفية"""
        subdomains = set()
        # المصادر السلبية
        tasks = []
        # AlienVault
        url_av = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        tasks.append(self.fetch(url_av))
        # CertSpotter
        url_cs = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        tasks.append(self.fetch(url_cs))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        # معالجة AlienVault
        if results[0] and isinstance(results[0], str):
            try:
                data = json.loads(results[0])
                for rec in data.get('passive_dns', []):
                    host = rec.get('hostname', '')
                    if host and host.endswith(f".{domain}"):
                        subdomains.add(host)
            except:
                pass
        # معالجة CertSpotter
        if results[1] and isinstance(results[1], str):
            try:
                data = json.loads(results[1])
                for entry in data:
                    for dns_name in entry.get('dns_names', []):
                        if dns_name.endswith(f".{domain}") or dns_name == domain:
                            subdomains.add(dns_name)
            except:
                pass

        # التقنيات المخفية إذا كان الوضع مفعلاً
        if self.hidden_mode and not self._stop_flag:
            await self.update_progress(50, f"تقنيات مخفية على {domain}")
            # هجوم القاموس
            if self.wordlist_path:
                try:
                    with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    async def check(w):
                        full = f"{w}.{domain}"
                        try:
                            await asyncio.to_thread(resolver.resolve, full, 'A')
                            return full
                        except:
                            return None
                    tasks = [check(w) for w in wordlist[:3000]]
                    brute_results = await asyncio.gather(*tasks)
                    subdomains.update({r for r in brute_results if r})
                except:
                    pass
            # AXFR (zone transfer)
            try:
                ns_answers = dns.resolver.resolve(domain, 'NS')
                for ns in ns_answers:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=5))
                        for name in zone.nodes.keys():
                            if name.to_text() != '@':
                                subdomains.add(f"{name.to_text()}.{domain}")
                    except:
                        pass
            except:
                pass
        return subdomains

    async def start_scan(self):
        async with aiohttp.ClientSession() as session:
            self.session = session
            self.semaphore = asyncio.Semaphore(self.threads)

            await self.update_progress(5, "تحليل الهدف...")
            # تحديد ما إذا كان الهدف IP
            try:
                ipaddress.ip_address(self.original_target)
                is_ip = True
            except:
                is_ip = False

            if is_ip:
                await self.update_progress(10, f"جلب جميع النطاقات المرتبطة بالـ IP {self.original_target} ...")
                # الحصول على قائمة النطاقات الرئيسية من passive DNS
                self.all_root_domains = await self.get_all_domains_by_ip(self.original_target)
                # إضافة نطاق PTR إن وجد
                ptr_domain = await self.get_domain_from_ptr(self.original_target)
                if ptr_domain:
                    self.all_root_domains.add(ptr_domain)

                if not self.all_root_domains:
                    await self.update_progress(20, "لم يتم العثور على نطاقات مرتبطة بهذا الـ IP")
                    return set()

                await self.update_progress(20, f"تم العثور على {len(self.all_root_domains)} نطاق رئيسي: {', '.join(list(self.all_root_domains)[:5])}")
                # مسح كل نطاق رئيسي
                all_subdomains = set()
                for i, root_domain in enumerate(self.all_root_domains):
                    if self._stop_flag:
                        break
                    progress = 20 + int((i / len(self.all_root_domains)) * 70)
                    await self.update_progress(progress, f"مسح النطاق: {root_domain}")
                    subs = await self.scan_domain(root_domain)
                    all_subdomains.update(subs)
                    # إضافة النطاق الرئيسي نفسه إن لم يكن موجوداً
                    all_subdomains.add(root_domain)
                self.found_domains = all_subdomains
            else:
                # الهدف هو نطاق مباشر
                self.all_root_domains.add(self.original_target)
                self.found_domains = await self.scan_domain(self.original_target)
                self.found_domains.add(self.original_target)

            await self.update_progress(100, "اكتمل المسح")
            return self.found_domains

# ========== الواجهة الرسومية ==========
class EldeebSubSeekerGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Eldeeb SubSeeker v5.0 - IP متعدد الدومينات + نسخ/لصق")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)

        self.scan_thread = None
        self.core = None

        self.build_ui()
        enable_global_copy_paste(self.root)  # تفعيل الاختصارات العالمية
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log(self, msg):
        self.log_text.insert("end", f"[*] {msg}\n")
        self.log_text.see("end")
        self.root.update_idletasks()

    def update_progress(self, value, msg):
        def _up():
            self.progress_bar.set(value / 100.0)
            self.status_label.configure(text=msg)
            self.log(msg)
        self.root.after(0, _up)

    async def async_progress_callback(self, value, msg):
        self.update_progress(value, msg)

    def display_results(self, domains: Set[str]):
        self.results_text.delete(1.0, "end")
        # عرض النطاقات الرئيسية أولاً (إذا كان IP)
        if self.core and self.core.all_root_domains:
            self.results_text.insert("end", "=== النطاقات الرئيسية المرتبطة بالـ IP ===\n")
            for rd in sorted(self.core.all_root_domains):
                self.results_text.insert("end", f"🔹 {rd}\n")
            self.results_text.insert("end", "\n=== النطاقات الفرعية المكتشفة ===\n")
        for d in sorted(domains):
            self.results_text.insert("end", f"{d}\n")
        stats = f"إجمالي النطاقات المكتشفة: {len(domains)}\n"
        if self.core and self.core.all_root_domains:
            stats += f"النطاقات الرئيسية: {len(self.core.all_root_domains)}\n"
        self.stats_label.configure(text=stats)

    def copy_all_results(self):
        content = self.results_text.get(1.0, "end").strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.log("تم نسخ جميع النتائج")

    def save_results_to_file(self):
        path = self.output_path.get()
        if not path:
            path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.results_text.get(1.0, "end").strip())
            self.log(f"حفظ النتائج في {path}")

    def clear_results(self):
        self.results_text.delete(1.0, "end")
        self.log("مسح النتائج")

    def select_wordlist(self):
        path = filedialog.askopenfilename(title="اختر ملف قاموس", filetypes=[("Text files", "*.txt")])
        if path:
            self.wordlist_path.set(path)
            self.log(f"تم اختيار القاموس: {path}")

    def select_output_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            self.output_path.set(path)

    def build_ui(self):
        main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)

        sidebar = ctk.CTkFrame(main_frame, width=320, corner_radius=10)
        sidebar.pack(side="left", fill="y", padx=(0, 15))
        sidebar.pack_propagate(False)

        results_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        results_frame.pack(side="right", fill="both", expand=True)

        # العنوان
        ctk.CTkLabel(sidebar, text="⚙️ إعدادات المسح", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(15, 20))

        # حقل الهدف
        ctk.CTkLabel(sidebar, text="الهدف (نطاق أو IP):", anchor="w").pack(fill="x", padx=15, pady=(5,0))
        self.target_entry = ctk.CTkEntry(sidebar, placeholder_text="مثال: newegg.com  أو  50.6.204.111", font=ctk.CTkFont(size=14))
        self.target_entry.pack(fill="x", padx=15, pady=(0,15))

        # الخيارات
        self.recursive_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(sidebar, text="مسح متكرر (Recursive)", variable=self.recursive_var).pack(anchor="w", padx=15, pady=5)

        self.hidden_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(sidebar, text="🔍 وضع النطاقات المخفية (قاموس + AXFR)", variable=self.hidden_var).pack(anchor="w", padx=15, pady=5)

        # شريط الخيوط
        ctk.CTkLabel(sidebar, text="عدد الخيوط:", anchor="w").pack(fill="x", padx=15, pady=(10,0))
        self.threads_slider = ctk.CTkSlider(sidebar, from_=10, to=500, number_of_steps=49)
        self.threads_slider.set(150)
        self.threads_slider.pack(fill="x", padx=15, pady=5)
        self.threads_value_label = ctk.CTkLabel(sidebar, text="150", anchor="w")
        self.threads_value_label.pack(fill="x", padx=15)
        self.threads_slider.configure(command=lambda v: self.threads_value_label.configure(text=str(int(v))))

        # ملف القاموس
        self.wordlist_frame = ctk.CTkFrame(sidebar)
        self.wordlist_frame.pack(fill="x", padx=15, pady=5)
        self.wordlist_path = ctk.StringVar()
        self.wordlist_entry = ctk.CTkEntry(self.wordlist_frame, placeholder_text="مسار ملف القاموس (للوضع المخفي)", state="normal")
        self.wordlist_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.wordlist_button = ctk.CTkButton(self.wordlist_frame, text="📂", width=40, command=self.select_wordlist)
        self.wordlist_button.pack(side="right")

        # ملف الإخراج
        ctk.CTkLabel(sidebar, text="ملف الإخراج (اختياري):", anchor="w").pack(fill="x", padx=15, pady=(15,0))
        output_frame = ctk.CTkFrame(sidebar)
        output_frame.pack(fill="x", padx=15, pady=5)
        self.output_path = ctk.StringVar()
        self.output_entry = ctk.CTkEntry(output_frame, placeholder_text="result.txt", textvariable=self.output_path)
        self.output_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        ctk.CTkButton(output_frame, text="💾", width=40, command=self.select_output_file).pack(side="right")

        # الأزرار
        control_frame = ctk.CTkFrame(sidebar)
        control_frame.pack(fill="x", padx=15, pady=20)
        self.scan_button = ctk.CTkButton(control_frame, text="▶ بدء المسح", command=self.start_scan, fg_color="#2e7d32", font=ctk.CTkFont(size=14, weight="bold"))
        self.scan_button.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.stop_button = ctk.CTkButton(control_frame, text="⏹ إيقاف", command=self.stop_scan, state="disabled", fg_color="#c62828")
        self.stop_button.pack(side="right", fill="x", expand=True, padx=(5,0))

        self.progress_bar = ctk.CTkProgressBar(sidebar)
        self.progress_bar.pack(fill="x", padx=15, pady=(10,5))
        self.progress_bar.set(0)
        self.status_label = ctk.CTkLabel(sidebar, text="جاهز", anchor="center")
        self.status_label.pack(fill="x", padx=15, pady=(0,15))

        # منطقة النتائج مع تبويبات
        tabview = ctk.CTkTabview(results_frame)
        tabview.pack(fill="both", expand=True, padx=10, pady=10)
        tabview.add("📋 النتائج")
        tabview.add("📊 إحصائيات")
        tabview.add("📄 سجل التشغيل")

        results_tab = tabview.tab("📋 النتائج")
        self.results_text = scrolledtext.ScrolledText(results_tab, wrap="none", font=("Consolas", 11), bg="#1e1e1e", fg="#d4d4d4")
        self.results_text.pack(fill="both", expand=True, padx=5, pady=5)

        btn_frame = ctk.CTkFrame(results_tab, fg_color="transparent")
        btn_frame.pack(fill="x", padx=5, pady=(0,5))
        ctk.CTkButton(btn_frame, text="📋 نسخ الكل", command=self.copy_all_results, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="💾 حفظ النتائج", command=self.save_results_to_file, width=120).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🗑 مسح الشاشة", command=self.clear_results, width=100).pack(side="left", padx=5)

        stats_tab = tabview.tab("📊 إحصائيات")
        self.stats_label = ctk.CTkLabel(stats_tab, text="", justify="left", font=ctk.CTkFont(size=14))
        self.stats_label.pack(anchor="nw", padx=15, pady=15)

        log_tab = tabview.tab("📄 سجل التشغيل")
        self.log_text = scrolledtext.ScrolledText(log_tab, wrap="word", font=("Consolas", 10), bg="#1e1e1e", fg="#cccccc")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        # تفعيل قائمة السياق لبعض العناصر التي قد لا تلتقطها bind_all
        for widget in [self.target_entry, self.wordlist_entry, self.output_entry, self.results_text, self.log_text]:
            widget.bind("<Button-3>", lambda e, w=widget: show_context_menu(w, e))

    def run_scan_async(self):
        async def wrapper():
            target = self.target_entry.get().strip()
            if not target:
                self.root.after(0, lambda: messagebox.showerror("خطأ", "الرجاء إدخال نطاق أو IP"))
                return
            wordlist = self.wordlist_path.get() if self.hidden_var.get() else None
            self.core = EldeebSubSeekerCore(
                target=target,
                recursive=self.recursive_var.get(),
                threads=int(self.threads_slider.get()),
                hidden_mode=self.hidden_var.get(),
                wordlist_path=wordlist,
                progress_callback=self.async_progress_callback
            )
            results = await self.core.start_scan()
            self.root.after(0, lambda: self.display_results(results))
            self.root.after(0, lambda: self.log(f"✅ اكتمل. تم العثور على {len(results)} نطاقاً"))
            if self.output_path.get():
                with open(self.output_path.get(), 'w', encoding='utf-8') as f:
                    for d in sorted(results):
                        f.write(d + "\n")
                self.log(f"حفظ النتائج في {self.output_path.get()}")
            self.root.after(0, self.scan_finished)
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(wrapper())
        except Exception as e:
            self.root.after(0, lambda: self.log(f"خطأ: {str(e)}"))
            self.root.after(0, self.scan_finished)

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("خطأ", "الرجاء إدخال نطاق أو IP")
            return
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.clear_results()
        self.log(f"بدء المسح على {target} (الوضع المخفي: {self.hidden_var.get()})")
        self.progress_bar.set(0)
        self.status_label.configure(text="جارِ المسح...")
        self.scan_thread = threading.Thread(target=self.run_scan_async, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.core:
            self.core.stop()
            self.log("تم إيقاف المسح")
        self.scan_finished()

    def scan_finished(self):
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="جاهز")
        self.core = None

    def on_closing(self):
        if self.scan_thread and self.scan_thread.is_alive():
            if messagebox.askokcancel("إنهاء", "المسح قيد التشغيل. هل تريد الخروج؟"):
                if self.core:
                    self.core.stop()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    missing = []
    for lib in ["customtkinter", "aiohttp", "dns"]:
        try:
            __import__(lib)
        except:
            missing.append(lib)
    if missing:
        print(f"تثبيت المتطلبات: pip install {' '.join(missing)}")
        sys.exit(1)
    app = EldeebSubSeekerGUI()
    app.run()
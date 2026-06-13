import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

from core.engine import run_scan


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Vulnerability Scanner")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TLabel", background="#1e1e1e", foreground="white", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"))

        # ===== TITLE =====
        ttk.Label(root, text="Vulnerability Assessment Tool", font=("Segoe UI", 16, "bold")).pack(pady=10)

        # ===== INPUT =====
        frame = tk.Frame(root, bg="#1e1e1e")
        frame.pack()

        self.entry = ttk.Entry(frame, width=40)
        self.entry.grid(row=0, column=0, padx=10)

        self.button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.button.grid(row=0, column=1)

        # ===== PROGRESS =====
        self.progress = ttk.Progressbar(root, length=400, mode="indeterminate")
        self.progress.pack(pady=10)

        # ===== OUTPUT =====
        self.output = tk.Text(root, bg="#2b2b2b", fg="white", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True, padx=10, pady=10)

        # 🎨 Color tags
        self.output.tag_config("high", foreground="red")
        self.output.tag_config("medium", foreground="orange")
        self.output.tag_config("low", foreground="lightgreen")
        self.output.tag_config("cve", foreground="yellow")

    def start_scan(self):
        ip = self.entry.get().strip()

        if not ip:
            messagebox.showwarning("Input Error", "Enter target IP")
            return

        self.start_time = time.time()

        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "🚀 Starting scan...\n\n")

        self.button.config(state=tk.DISABLED)
        self.progress.start()

        thread = threading.Thread(target=self.run_scan_thread, args=(ip,))
        thread.daemon = True
        thread.start()

    def run_scan_thread(self, ip):
        try:
            results, score, report = run_scan(ip)
            self.root.after(0, self.display_results, results, score, report)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, self.reset_ui)

    def display_results(self, results, score, report):
        self.output.delete(1.0, tk.END)

        duration = round(time.time() - self.start_time, 2)
        total_ports = len(results)

        self.output.insert(tk.END, "==============================\n")
        self.output.insert(tk.END, " 🔐 SCAN RESULTS\n")
        self.output.insert(tk.END, "==============================\n\n")

        self.output.insert(tk.END, f"🔥 Risk Score: {score}/100\n")
        self.output.insert(tk.END, f"📊 Open Ports Found: {total_ports}\n")
        self.output.insert(tk.END, f"⏱ Scan Duration: {duration} seconds\n")
        self.output.insert(tk.END, f"📄 Report: {report}\n\n")

        for r in results:
            self.output.insert(tk.END, f"🔹 Port {r['port']} ({r['service']})\n")

            if r["risk"] == "HIGH":
                self.output.insert(tk.END, f"   Risk: {r['risk']}\n", "high")
            elif r["risk"] == "MEDIUM":
                self.output.insert(tk.END, f"   Risk: {r['risk']}\n", "medium")
            else:
                self.output.insert(tk.END, f"   Risk: {r['risk']}\n", "low")

            self.output.insert(tk.END, f"   Issue: {r['issue']}\n")
            self.output.insert(tk.END, f"   Fix: {r['fix']}\n")

            if "CVE" in r["issue"]:
                self.output.insert(tk.END, f"   ⚠ CVE: {r['issue']}\n", "cve")

            self.output.insert(tk.END, "\n")

        self.output.insert(tk.END, "✅ Scan completed.\n")

        self.reset_ui()

    def reset_ui(self):
        self.progress.stop()
        self.button.config(state=tk.NORMAL)




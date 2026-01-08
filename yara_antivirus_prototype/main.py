import os
import yara
import shutil
import json
import math
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Listbox, Scrollbar, Text, END, RIGHT, Y, LEFT, BOTH, Frame
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Constants
QUARANTINE_DIR = "quarantine"
LOG_FILE = "scan_log.txt"
RULES_FILE = "rules.yar"
SIGNATURES_FILE = "signatures.json"
QUARANTINE_META = "quarantine_meta.json"
HEURISTIC_ENABLED = True

# Real-time monitoring configuration
MONITOR_FOLDER = "C:\\Users\\anshu"  
MONITOR_INTERVAL = 5  # seconds between checks
MONITOR_ENABLED = False  # Default state

def log_event(message):
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} - {message}\n")

class FolderMonitorHandler(FileSystemEventHandler):
    def __init__(self, rules, signatures):
        super().__init__()
        self.rules = rules
        self.signatures = signatures
        
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            log_event(f"Real-time monitor detected new file: {file_path}")
            if scan_file(file_path, self.rules, self.signatures, show_popup=False):
                messagebox.showwarning("Malware Detected", 
                                     f"Real-time monitor quarantined: {os.path.basename(file_path)}")

def start_monitoring(rules, signatures):
    global MONITOR_ENABLED, monitor_thread, observer
    
    if MONITOR_ENABLED:
        return
    
    if not os.path.exists(MONITOR_FOLDER):
        log_event(f"Monitoring folder not found: {MONITOR_FOLDER}")
        messagebox.showerror("Error", f"Monitoring folder not found: {MONITOR_FOLDER}")
        return
    
    try:
        event_handler = FolderMonitorHandler(rules, signatures)
        observer = Observer()
        observer.schedule(event_handler, MONITOR_FOLDER, recursive=True)
        observer.start()
        MONITOR_ENABLED = True
        log_event(f"Started real-time monitoring of: {MONITOR_FOLDER}")
    except Exception as e:
        log_event(f"Failed to start monitoring: {e}")
        messagebox.showerror("Monitoring Error", f"Failed to start monitoring: {e}")

def stop_monitoring():
    global MONITOR_ENABLED, observer
    
    if not MONITOR_ENABLED:
        return
    
    try:
        observer.stop()
        observer.join()
        MONITOR_ENABLED = False
        log_event(f"Stopped real-time monitoring of: {MONITOR_FOLDER}")
    except Exception as e:
        log_event(f"Failed to stop monitoring: {e}")
        messagebox.showerror("Monitoring Error", f"Failed to stop monitoring: {e}")

def load_rules():
    try:
        return yara.compile(filepath=RULES_FILE)
    except yara.SyntaxError as e:
        log_event(f"Failed to compile YARA rules: {e}")
        return None

def load_signatures():
    try:
        with open(SIGNATURES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        log_event(f"Failed to load signatures: {e}")
        return {}

def save_quarantine_meta(file_name, original_path):
    try:
        meta = {}
        if os.path.exists(QUARANTINE_META):
            with open(QUARANTINE_META, "r") as f:
                meta = json.load(f)
        meta[file_name] = original_path
        with open(QUARANTINE_META, "w") as f:
            json.dump(meta, f)
    except Exception as e:
        log_event(f"Error saving quarantine metadata: {e}")

def signature_scan(file_path, signatures):
    try:
        with open(file_path, "rb") as f:
            content = f.read().decode(errors="ignore")
            for name, sig in signatures.items():
                if sig in content:
                    log_event(f"Signature match: {file_path} -> {name}")
                    quarantine_file(file_path)
                    return True
    except Exception as e:
        log_event(f"Error in signature scan: {file_path} -> {e}")
    return False

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    for byte_count in freq.values():
        p_x = byte_count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def heuristic_scan(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            size = len(content)
            entropy = calculate_entropy(content)
            content_str = content.decode(errors="ignore").lower()

            if size < 1024 or size > 10 * 1024 * 1024:
                log_event(f"Heuristic match (size anomaly): {file_path}")
                return True

            if entropy > 7.5:
                log_event(f"Heuristic match (high entropy): {file_path} [Entropy: {entropy:.2f}]")
                return True

            suspicious_keywords = ['createremotethread', 'virtualalloc', 'getprocaddress']
            if any(keyword in content_str for keyword in suspicious_keywords):
                log_event(f"Heuristic match (suspicious strings): {file_path}")
                return True
    except Exception as e:
        log_event(f"Error in heuristic scan: {file_path} -> {e}")
    return False

def quarantine_file(file_path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    file_name = os.path.basename(file_path)
    quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
    save_quarantine_meta(file_name, os.path.abspath(file_path))
    shutil.move(file_path, quarantine_path)
    log_event(f"File quarantined: {file_path} -> {quarantine_path}")

def scan_file(file_path, rules, signatures, show_popup=True):
    log_event(f"Scanning file: {file_path}")
    

    if rules:
        try:
            matches = rules.match(filepath=file_path)
            if matches:
                log_event(f"YARA match: {file_path} - Matches: {matches}")
                quarantine_file(file_path)
                if show_popup:
                    messagebox.showwarning("Malware Detected", f"{file_path} quarantined by YARA!")
                return True
        except Exception as e:
            log_event(f"Error during YARA scan: {file_path} -> {e}")
            if show_popup:
                messagebox.showerror("YARA Scan Error", str(e))

    if signature_scan(file_path, signatures):
        if show_popup:
            messagebox.showwarning("Malware Detected", f"{file_path} quarantined by signature!")
        return True

    #if HEURISTIC_ENABLED and heuristic_scan(file_path):
        quarantine_file(file_path)
        if show_popup:
            messagebox.showwarning("Suspicious File", f"{file_path} quarantined by heuristic rules!")
        return True

    log_event(f"No threat found: {file_path}")
    if show_popup:
        messagebox.showinfo("Scan Complete", "No threats detected in file.")
    return False

def scan_directory(directory, rules, signatures):
    log_event(f"Started scanning folder: {directory}")
    found = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if scan_file(file_path, rules, signatures, show_popup=False):
                found.append(file_path)

    if found:
        messagebox.showwarning("Threats Detected", f"{len(found)} file(s) quarantined in folder scan.\nSee logs for details.")
    else:
        messagebox.showinfo("Scan Complete", "No threats detected in folder.")

    log_event(f"Completed scanning folder: {directory}, Threats found: {len(found)}")

def restore_file(file_name):
    quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
    if not os.path.exists(quarantine_path):
        log_event(f"Restore failed: {file_name} not found in quarantine")
        messagebox.showerror("Error", "File not found in quarantine.")
        return

    try:
        with open(QUARANTINE_META, "r") as f:
            meta = json.load(f)
        original_path = meta.get(file_name, os.path.join(".", file_name))
    except Exception as e:
        log_event(f"Restore metadata error: {e}")
        original_path = os.path.join(".", file_name)

    shutil.move(quarantine_path, original_path)
    log_event(f"File restored: {quarantine_path} -> {original_path}")
    messagebox.showinfo("Restored", f"{file_name} restored successfully.")

def delete_file(file_name):
    quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
    if os.path.exists(quarantine_path):
        os.remove(quarantine_path)
        log_event(f"File deleted from quarantine: {quarantine_path}")
        messagebox.showinfo("Deleted", f"{file_name} deleted from quarantine.")
    else:
        log_event(f"Delete failed: {file_name} not found in quarantine")
        messagebox.showerror("Error", "File not found in quarantine.")

def restore_all_files():
    if not os.path.exists(QUARANTINE_META):
        messagebox.showinfo("Restore All", "No metadata found for quarantine.")
        return
    try:
        with open(QUARANTINE_META, "r") as f:
            meta = json.load(f)
        for file_name, original_path in meta.items():
            quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
            if os.path.exists(quarantine_path):
                shutil.move(quarantine_path, original_path)
                log_event(f"File restored: {quarantine_path} -> {original_path}")
        
        # Delete metadata file
        os.remove(QUARANTINE_META)

        # Clean up any remaining files in quarantine folder
        if os.path.exists(QUARANTINE_DIR):
            for file in os.listdir(QUARANTINE_DIR):
                file_path = os.path.join(QUARANTINE_DIR, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            # Remove the folder if empty
            if not os.listdir(QUARANTINE_DIR):
                os.rmdir(QUARANTINE_DIR)

        messagebox.showinfo("Restore All", "All files restored and quarantine cleared.")
    except Exception as e:
        log_event(f"Restore all error: {e}")
        messagebox.showerror("Error", "Failed to restore all files.")

def delete_all_files():
    if not os.path.exists(QUARANTINE_DIR):
        messagebox.showinfo("Delete All", "No quarantine folder found.")
        return
    try:
        for file_name in os.listdir(QUARANTINE_DIR):
            file_path = os.path.join(QUARANTINE_DIR, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
                log_event(f"File deleted from quarantine: {file_path}")
        messagebox.showinfo("Delete All", "All files deleted from quarantine.")
    except Exception as e:
        log_event(f"Delete all error: {e}")
        messagebox.showerror("Error", "Failed to delete all files.")

def view_quarantine(content_frame):
    for widget in content_frame.winfo_children():
        widget.destroy()

    files = os.listdir(QUARANTINE_DIR) if os.path.exists(QUARANTINE_DIR) else []
    if not files:
        tk.Label(content_frame, text="No files in quarantine.", fg="white", bg="#1e1e1e").pack()
        return

    listbox = Listbox(content_frame, width=80, bg="#2e2e2e", fg="white", selectbackground="#00aaff")
    scrollbar = Scrollbar(content_frame, command=listbox.yview)
    listbox.config(yscrollcommand=scrollbar.set)

    for file in files:
        listbox.insert(END, file)

    def on_select(event):
        try:
            selected = listbox.get(listbox.curselection())
            action = messagebox.askquestion(
                "Quarantine Action",
                f"What do you want to do with '{selected}'?",
                icon='question', type='yesnocancel',
                default='yes',
                detail="Yes = Restore, No = Delete, Cancel = Nothing"
            )
            if action == 'yes':
                restore_file(selected)
                listbox.delete(listbox.curselection())
            elif action == 'no':
                delete_file(selected)
                listbox.delete(listbox.curselection())
        except:
            pass

    listbox.bind("<<ListboxSelect>>", on_select)
    listbox.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.pack(side=RIGHT, fill=Y)

def clear_logs(content_frame):
    try:
        with open(LOG_FILE, "w") as f:
            f.write("=== Antivirus Log Cleared ===\n")
        log_event("Logs were cleared.")
        update_logs_view(content_frame)
        messagebox.showinfo("Logs Cleared", "Log file has been cleared.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to clear logs: {e}")

def update_logs_view(content_frame):
    for widget in content_frame.winfo_children():
        widget.destroy()

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("=== Antivirus Log Started ===\n")

    text_area = Text(content_frame, wrap='word', bg="#2e2e2e", fg="white")
    text_area.pack(side=LEFT, fill=BOTH, expand=True)

    scrollbar = Scrollbar(content_frame, command=text_area.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    text_area.config(yscrollcommand=scrollbar.set)

    try:
        with open(LOG_FILE, "r") as log:
            content = log.read()
            text_area.insert(1.0, content)
    except Exception as e:
        text_area.insert(1.0, f"Failed to read log file: {e}")

    text_area.config(state='disabled')

def main():
    global HEURISTIC_ENABLED, MONITOR_ENABLED, observer
    
    rules = load_rules()
    signatures = load_signatures()

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("=== Antivirus Log Started ===\n")

    app = tk.Tk()
    app.title("Simple Antivirus - Signature + YARA + Heuristic")
    app.geometry("1000x600")
    app.configure(bg="#1e1e1e")

    left_frame = Frame(app, width=200, bg="#2e2e2e")
    left_frame.pack(side=LEFT, fill=Y)

    right_frame = Frame(app, bg="#1e1e1e")
    right_frame.pack(side=RIGHT, fill=BOTH, expand=True)

    def handle_scan_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            scan_file(file_path, rules, signatures)
            update_logs_view(right_frame)

    def handle_scan_folder():
        folder_path = filedialog.askdirectory()
        if folder_path:
            scan_directory(folder_path, rules, signatures)
            update_logs_view(right_frame)

    def handle_restore():
        file_name = simpledialog.askstring("Restore File", "Enter the file name to restore:")
        if file_name:
            restore_file(file_name)

    def handle_delete():
        file_name = simpledialog.askstring("Delete File", "Enter the file name to delete:")
        if file_name:
            delete_file(file_name)

    def handle_restore_all():
        restore_all_files()

    def handle_delete_all():
        delete_all_files()

    def handle_view_quarantine():
        view_quarantine(right_frame)

    def handle_view_logs():
        update_logs_view(right_frame)

    def toggle_monitoring():
        if MONITOR_ENABLED:
            stop_monitoring()
            monitor_status_var.set("Real-time Monitor: OFF")
            messagebox.showinfo("Monitoring", "Real-time monitoring disabled.")
        else:
            start_monitoring(rules, signatures)
            if MONITOR_ENABLED:  # Only update if start was successful
                monitor_status_var.set(f"Real-time Monitor: ON\n{MONITOR_FOLDER}")
            else:
                monitor_status_var.set("Real-time Monitor: OFF")

    # Status variables
    heuristic_status_var = tk.StringVar()
    heuristic_status_var.set(f"Heuristics: {'ON' if HEURISTIC_ENABLED else 'OFF'}")

    monitor_status_var = tk.StringVar()
    monitor_status_var.set(f"Real-time Monitor: {'ON' if MONITOR_ENABLED else 'OFF'}")

    # Status labels
    status_frame = Frame(left_frame, bg="#2e2e2e")
    status_frame.pack(pady=(10, 0), fill='x')

    tk.Label(status_frame, textvariable=heuristic_status_var, 
             bg="#2e2e2e", fg="#00ff88", font=("Arial", 10)).pack(pady=5)
    
    monitor_label = tk.Label(status_frame, textvariable=monitor_status_var, 
                            bg="#2e2e2e", fg="#ff8800", font=("Arial", 10))
    monitor_label.pack(pady=5)

    if MONITOR_ENABLED:
        monitor_status_var.set(f"Real-time Monitor: ON\n{MONITOR_FOLDER}")

    def toggle_heuristics():
        global HEURISTIC_ENABLED
        HEURISTIC_ENABLED = not HEURISTIC_ENABLED
        status = "ON" if HEURISTIC_ENABLED else "OFF"
        heuristic_status_var.set(f"Heuristics: {status}")
        messagebox.showinfo("Heuristic Toggle", f"Heuristic scanning is now {status}.")

    button_style = {
        "bg": "#333333",
        "fg": "#00aaff",
        "activebackground": "#555555",
        "activeforeground": "#00ccff",
        "relief": "flat",
        "width": 20,
        "font": ("Arial", 10)
    }

    tk.Label(left_frame, text="Antivirus Menu", font=("Arial", 14), bg="#2e2e2e", fg="white").pack(pady=10)
    tk.Button(left_frame, text="Toggle Heuristics", command=toggle_heuristics, **button_style).pack(pady=5)
    tk.Button(left_frame, text="Toggle Monitoring", command=toggle_monitoring, **button_style).pack(pady=5)

    menu_buttons = [
        ("Scan File", handle_scan_file),
        ("Scan Folder", handle_scan_folder),
        ("Restore File", handle_restore),
        ("Delete File", handle_delete),
        ("Restore All", handle_restore_all),
        ("Delete All", handle_delete_all),
        ("View Quarantine", handle_view_quarantine),
        ("View Logs", handle_view_logs),
        ("Clear Logs", lambda: clear_logs(right_frame)),
        ("Exit", app.quit)
    ]

    for text, command in menu_buttons:
        tk.Button(left_frame, text=text, command=command, **button_style).pack(pady=5)

    update_logs_view(right_frame)
    
    # Start monitoring if enabled by default
    if MONITOR_ENABLED:
        start_monitoring(rules, signatures)
    
    app.protocol("WM_DELETE_WINDOW", lambda: [stop_monitoring(), app.quit()])
    app.mainloop()

if __name__ == "__main__":
    main()
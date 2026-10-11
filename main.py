import os
import shutil
import hashlib
import sqlite3
import subprocess
import threading
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "Owner Security Manager"

APP_DIR = Path.home() / "OwnerSecurityManager"
QUARANTINE_DIR = APP_DIR / "quarantine"
DATABASE_FILE = APP_DIR / "security.db"

APP_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Default credentials for first run.
# Change these before publishing a real deployment.
OWNER_USERNAME = os.getenv("OWNER_USERNAME", "nuth112")
OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "112211")

SCANNER_ENABLED = True


# ============================================================
# DATABASE
# ============================================================

def get_database():
    connection = sqlite3.connect(DATABASE_FILE)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT,
            scan_time TEXT NOT NULL
        )
    """)

    connection.commit()

    return connection


def save_scan_history(file_path, result, details=""):

    connection = get_database()

    connection.execute(
        """
        INSERT INTO scan_history
        (file_path, result, details, scan_time)
        VALUES (?, ?, ?, ?)
        """,
        (
            str(file_path),
            result,
            details[:3000],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    connection.commit()
    connection.close()


# ============================================================
# AUTHENTICATION
# ============================================================

def hash_password(password):

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


OWNER_PASSWORD_HASH = hash_password(
    OWNER_PASSWORD
)


def verify_login(username, password):

    return (
        username == OWNER_USERNAME
        and
        hash_password(password)
        == OWNER_PASSWORD_HASH
    )


# ============================================================
# CLAMAV
# ============================================================

def scan_file(file_path):

    try:

        process = subprocess.run(
            [
                "clamscan",
                "--no-summary",
                str(file_path)
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        output = (
            process.stdout or ""
        ) + (
            process.stderr or ""
        )

        if "FOUND" in output:

            return "INFECTED", output

        if "OK" in output:

            return "CLEAN", output

        return "ERROR", output

    except FileNotFoundError:

        return (
            "ERROR",
            "ClamAV was not found. "
            "Install ClamAV and add clamscan to PATH."
        )

    except subprocess.TimeoutExpired:

        return (
            "ERROR",
            "Scan timed out."
        )

    except Exception as error:

        return (
            "ERROR",
            str(error)
        )


def scan_folder(folder_path):

    try:

        process = subprocess.run(
            [
                "clamscan",
                "-r",
                "--no-summary",
                str(folder_path)
            ],
            capture_output=True,
            text=True,
            timeout=900
        )

        output = (
            process.stdout or ""
        ) + (
            process.stderr or ""
        )

        infected = []

        for line in output.splitlines():

            if " FOUND" in line:

                infected.append(line)

        if infected:

            return (
                "INFECTED",
                "\n".join(infected)
            )

        return "CLEAN", output

    except FileNotFoundError:

        return (
            "ERROR",
            "ClamAV was not found."
        )

    except subprocess.TimeoutExpired:

        return (
            "ERROR",
            "Folder scan timed out."
        )

    except Exception as error:

        return (
            "ERROR",
            str(error)
        )


# ============================================================
# LOGIN WINDOW
# ============================================================

class LoginWindow(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            f"{APP_NAME} - Login"
        )

        self.geometry(
            "430x320"
        )

        self.resizable(
            False,
            False
        )

        self.configure(
            bg="#101820"
        )

        frame = tk.Frame(
            self,
            bg="#101820"
        )

        frame.pack(
            expand=True,
            fill="both",
            padx=35,
            pady=30
        )

        tk.Label(
            frame,
            text="🛡️ Owner Security Manager",
            font=("Segoe UI", 18, "bold"),
            fg="white",
            bg="#101820"
        ).pack(
            pady=(0, 25)
        )

        tk.Label(
            frame,
            text="Username",
            fg="white",
            bg="#101820"
        ).pack(
            anchor="w"
        )

        self.username = ttk.Entry(
            frame,
            width=42
        )

        self.username.pack(
            pady=(5, 12)
        )

        self.username.insert(
            0,
            OWNER_USERNAME
        )

        tk.Label(
            frame,
            text="Password",
            fg="white",
            bg="#101820"
        ).pack(
            anchor="w"
        )

        self.password = ttk.Entry(
            frame,
            width=42,
            show="*"
        )

        self.password.pack(
            pady=(5, 20)
        )

        ttk.Button(
            frame,
            text="🔐 LOGIN",
            command=self.login
        ).pack(
            ipadx=25,
            ipady=6
        )

        self.password.focus()

        self.bind(
            "<Return>",
            lambda event: self.login()
        )

    def login(self):

        username = self.username.get().strip()
        password = self.password.get()

        if verify_login(
            username,
            password
        ):

            self.destroy()

            SecurityApplication().mainloop()

        else:

            messagebox.showerror(
                "Login Failed",
                "Invalid Owner username or password."
            )


# ============================================================
# MAIN APPLICATION
# ============================================================

class SecurityApplication(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            APP_NAME
        )

        self.geometry(
            "1000x680"
        )

        self.minsize(
            900,
            600
        )

        self.scan_enabled = True

        self.protocol(
            "WM_DELETE_WINDOW",
            self.logout
        )

        self.create_interface()

    # --------------------------------------------------------
    # INTERFACE
    # --------------------------------------------------------

    def create_interface(self):

        header = tk.Frame(
            self,
            bg="#101820",
            height=65
        )

        header.pack(
            fill="x"
        )

        tk.Label(
            header,
            text="🛡️ OWNER SECURITY MANAGER",
            font=("Segoe UI", 18, "bold"),
            fg="white",
            bg="#101820"
        ).pack(
            side="left",
            padx=20,
            pady=16
        )

        tk.Label(
            header,
            text=f"Owner: {OWNER_USERNAME}",
            fg="#b8c7d9",
            bg="#101820"
        ).pack(
            side="left"
        )

        ttk.Button(
            header,
            text="🔒 Logout",
            command=self.logout
        ).pack(
            side="right",
            padx=20
        )

        # Navigation

        navigation = tk.Frame(
            self,
            bg="#e9eef3"
        )

        navigation.pack(
            fill="x"
        )

        buttons = [
            ("🦠 Scan File", self.select_file),
            ("📂 Scan Folder", self.select_folder),
            ("☣️ Quarantine", self.open_quarantine),
            ("📁 File Manager", self.open_file_manager),
            ("📊 History", self.open_history),
            ("⚙️ Settings", self.open_settings)
        ]

        for text, command in buttons:

            ttk.Button(
                navigation,
                text=text,
                command=command
            ).pack(
                side="left",
                padx=5,
                pady=10
            )

        # Console

        self.console = tk.Text(
            self,
            bg="#0b1220",
            fg="#d7e3f4",
            font=("Consolas", 10)
        )

        self.console.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        self.status = tk.StringVar(
            value="Ready"
        )

        tk.Label(
            self,
            textvariable=self.status,
            anchor="w",
            bg="#101820",
            fg="white"
        ).pack(
            fill="x"
        )

        self.log(
            "Owner authentication successful."
        )

        self.log(
            "Security Manager ready."
        )

    # --------------------------------------------------------
    # LOG
    # --------------------------------------------------------

    def log(self, message):

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        self.console.insert(
            "end",
            f"[{timestamp}] {message}\n"
        )

        self.console.see(
            "end"
        )

    # --------------------------------------------------------
    # FILE SCAN
    # --------------------------------------------------------

    def select_file(self):

        if not self.scan_enabled:

            messagebox.showwarning(
                "Scanner Disabled",
                "Enable the scanner first."
            )

            return

        file_path = filedialog.askopenfilename(
            title="Select File"
        )

        if not file_path:

            return

        self.status.set(
            "Scanning file..."
        )

        self.log(
            f"Scanning: {file_path}"
        )

        def worker():

            result, details = scan_file(
                file_path
            )

            save_scan_history(
                file_path,
                result,
                details
            )

            self.after(
                0,
                lambda:
                self.display_scan_result(
                    file_path,
                    result,
                    details
                )
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    # --------------------------------------------------------
    # DISPLAY SCAN RESULT
    # --------------------------------------------------------

    def display_scan_result(
        self,
        file_path,
        result,
        details
    ):

        self.status.set(
            "Ready"
        )

        if result == "CLEAN":

            self.log(
                "✅ CLEAN - No malware detected."
            )

            messagebox.showinfo(
                "Scan Result",
                "✅ File is clean."
            )

        elif result == "INFECTED":

            self.log(
                "☣️ MALWARE DETECTED!"
            )

            answer = messagebox.askyesno(
                "Malware Detected",
                "Malware was detected.\n\n"
                "Move this file to quarantine?"
            )

            if answer:

                self.move_to_quarantine(
                    Path(file_path)
                )

        else:

            self.log(
                "⚠️ Scanner error."
            )

            messagebox.showerror(
                "Scanner Error",
                details[:1500]
            )

    # --------------------------------------------------------
    # FOLDER SCAN
    # --------------------------------------------------------

    def select_folder(self):

        if not self.scan_enabled:

            messagebox.showwarning(
                "Scanner Disabled",
                "Enable the scanner first."
            )

            return

        folder = filedialog.askdirectory(
            title="Select Folder"
        )

        if not folder:

            return

        self.status.set(
            "Scanning folder..."
        )

        self.log(
            f"Scanning folder: {folder}"
        )

        def worker():

            result, details = scan_folder(
                folder
            )

            save_scan_history(
                folder,
                result,
                details
            )

            self.after(
                0,
                lambda:
                self.display_folder_result(
                    result,
                    details
                )
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def display_folder_result(
        self,
        result,
        details
    ):

        self.status.set(
            "Ready"
        )

        if result == "CLEAN":

            self.log(
                "✅ Folder clean."
            )

            messagebox.showinfo(
                "Scan Result",
                "No malware detected."
            )

        elif result == "INFECTED":

            self.log(
                "☣️ Malware detected in folder."
            )

            messagebox.showwarning(
                "Malware Detected",
                details[:3000]
            )

        else:

            messagebox.showerror(
                "Scanner Error",
                details[:1500]
            )

    # --------------------------------------------------------
    # QUARANTINE
    # --------------------------------------------------------

    def move_to_quarantine(
        self,
        source
    ):

        try:

            if not source.exists():

                return

            destination = (
                QUARANTINE_DIR
                / source.name
            )

            if destination.exists():

                destination = (
                    QUARANTINE_DIR
                    /
                    (
                        source.stem
                        + "_"
                        + datetime.now().strftime(
                            "%Y%m%d_%H%M%S"
                        )
                        + source.suffix
                    )
                )

            shutil.move(
                str(source),
                str(destination)
            )

            self.log(
                f"🔒 Quarantined: {destination.name}"
            )

            messagebox.showinfo(
                "Quarantine",
                "File moved to quarantine."
            )

        except Exception as error:

            messagebox.showerror(
                "Quarantine Error",
                str(error)
            )

    def open_quarantine(self):

        window = tk.Toplevel(
            self
        )

        window.title(
            "☣️ Quarantine"
        )

        window.geometry(
            "750x450"
        )

        tree = ttk.Treeview(
            window,
            columns=("size",),
            show="tree headings"
        )

        tree.heading(
            "#0",
            text="File"
        )

        tree.heading(
            "size",
            text="Size"
        )

        tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        def refresh():

            tree.delete(
                *tree.get_children()
            )

            for file in QUARANTINE_DIR.iterdir():

                if file.is_file():

                    tree.insert(
                        "",
                        "end",
                        iid=str(file),
                        text=file.name,
                        values=(
                            f"{file.stat().st_size:,} bytes",
                        )
                    )

        def delete_file():

            selected = tree.selection()

            if not selected:

                messagebox.showwarning(
                    "Select File",
                    "Select a file first."
                )

                return

            file_path = Path(
                selected[0]
            )

            if messagebox.askyesno(
                "Delete",
                f"Permanently delete {file_path.name}?"
            ):

                try:

                    file_path.unlink()

                    refresh()

                    self.log(
                        f"🗑️ Deleted: {file_path.name}"
                    )

                except Exception as error:

                    messagebox.showerror(
                        "Error",
                        str(error)
                    )

        toolbar = tk.Frame(
            window
        )

        toolbar.pack(
            fill="x",
            padx=10
        )

        ttk.Button(
            toolbar,
            text="🔄 Refresh",
            command=refresh
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            toolbar,
            text="🗑️ Delete Permanently",
            command=delete_file
        ).pack(
            side="left",
            padx=5
        )

        refresh()

    # --------------------------------------------------------
    # FILE MANAGER
    # --------------------------------------------------------

    def open_file_manager(self):

        window = tk.Toplevel(
            self
        )

        window.title(
            "📁 File Manager"
        )

        window.geometry(
            "850x520"
        )

        current = {
            "folder": Path.home()
        }

        path_var = tk.StringVar(
            value=str(
                current["folder"]
            )
        )

        ttk.Entry(
            window,
            textvariable=path_var
        ).pack(
            fill="x",
            padx=10,
            pady=10
        )

        tree = ttk.Treeview(
            window,
            columns=("type", "size"),
            show="tree headings"
        )

        tree.heading(
            "#0",
            text="Name"
        )

        tree.heading(
            "type",
            text="Type"
        )

        tree.heading(
            "size",
            text="Size"
        )

        tree.pack(
            fill="both",
            expand=True,
            padx=10
        )

        def refresh():

            tree.delete(
                *tree.get_children()
            )

            folder = Path(
                path_var.get()
            )

            if not folder.is_dir():

                return

            current["folder"] = folder

            try:

                for item in sorted(
                    folder.iterdir(),
                    key=lambda x: (
                        not x.is_dir(),
                        x.name.lower()
                    )
                ):

                    if item.is_dir():

                        tree.insert(
                            "",
                            "end",
                            iid=str(item),
                            text="📁 " + item.name,
                            values=(
                                "Folder",
                                ""
                            )
                        )

                    else:

                        tree.insert(
                            "",
                            "end",
                            iid=str(item),
                            text=item.name,
                            values=(
                                "File",
                                f"{item.stat().st_size:,}"
                            )
                        )

            except PermissionError:

                messagebox.showerror(
                    "Permission Error",
                    "Access denied."
                )

        def open_item(event=None):

            selected = tree.selection()

            if not selected:

                return

            path = Path(
                selected[0]
            )

            if path.is_dir():

                path_var.set(
                    str(path)
                )

                refresh()

            else:

                try:

                    os.startfile(
                        str(path)
                    )

                except Exception as error:

                    messagebox.showerror(
                        "Open Error",
                        str(error)
                    )

        def delete():

            selected = tree.selection()

            if not selected:

                return

            path = Path(
                selected[0]
            )

            if not messagebox.askyesno(
                "Delete",
                f"Delete {path.name}?"
            ):

                return

            try:

                if path.is_dir():

                    shutil.rmtree(
                        path
                    )

                else:

                    path.unlink()

                refresh()

                self.log(
                    f"🗑️ Deleted: {path}"
                )

            except Exception as error:

                messagebox.showerror(
                    "Delete Error",
                    str(error)
                )

        tree.bind(
            "<Double-1>",
            open_item
        )

        toolbar = tk.Frame(
            window
        )

        toolbar.pack(
            fill="x",
            padx=10,
            pady=10
        )

        ttk.Button(
            toolbar,
            text="🔄 Refresh",
            command=refresh
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            toolbar,
            text="🗑️ Delete",
            command=delete
        ).pack(
            side="left",
            padx=5
        )

        refresh()

    # --------------------------------------------------------
    # HISTORY
    # --------------------------------------------------------

    def open_history(self):

        window = tk.Toplevel(
            self
        )

        window.title(
            "📊 Scan History"
        )

        window.geometry(
            "950x500"
        )

        tree = ttk.Treeview(
            window,
            columns=(
                "path",
                "result",
                "time"
            ),
            show="headings"
        )

        tree.heading(
            "path",
            text="Path"
        )

        tree.heading(
            "result",
            text="Result"
        )

        tree.heading(
            "time",
            text="Time"
        )

        tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        connection = get_database()

        rows = connection.execute(
            """
            SELECT
                file_path,
                result,
                scan_time
            FROM scan_history
            ORDER BY id DESC
            LIMIT 500
            """
        ).fetchall()

        connection.close()

        for row in rows:

            tree.insert(
                "",
                "end",
                values=row
            )

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    def open_settings(self):

        window = tk.Toplevel(
            self
        )

        window.title(
            "⚙️ Settings"
        )

        window.geometry(
            "500x300"
        )

        enabled = tk.BooleanVar(
            value=self.scan_enabled
        )

        ttk.Label(
            window,
            text="Scanner Settings",
            font=("Segoe UI", 15, "bold")
        ).pack(
            pady=20
        )

        ttk.Checkbutton(
            window,
            text="Enable Malware Scanner",
            variable=enabled
        ).pack(
            pady=10
        )

        ttk.Label(
            window,
            text=(
                "Engine: ClamAV\n\n"
                "Quarantine:\n"
                + str(QUARANTINE_DIR)
            ),
            wraplength=450
        ).pack(
            pady=10
        )

        def save():

            self.scan_enabled = enabled.get()

            self.log(
                "Scanner "
                +
                (
                    "enabled."
                    if self.scan_enabled
                    else "disabled."
                )
            )

            window.destroy()

        ttk.Button(
            window,
            text="💾 Save",
            command=save
        ).pack(
            pady=15
        )

    # --------------------------------------------------------
    # LOGOUT
    # --------------------------------------------------------

    def logout(self):

        if messagebox.askyesno(
            "Logout",
            "Logout from Owner account?"
        ):

            self.destroy()

            LoginWindow().mainloop()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    LoginWindow().mainloop()

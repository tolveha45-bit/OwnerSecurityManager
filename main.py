import os
import shutil
import hashlib
import sqlite3
import subprocess
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog


# ============================================================
# 1. CONFIGURATION
# ============================================================

APP_DIR = Path.home() / "OwnerSecurityManager"

QUARANTINE_DIR = APP_DIR / "quarantine"

DB_PATH = APP_DIR / "security.db"

APP_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# 2. OWNER ACCOUNT
# ============================================================

OWNER_USERNAME = "nuth112"

OWNER_PASSWORD = "112211"

OWNER_PASSWORD_HASH = hashlib.sha256(
    OWNER_PASSWORD.encode()
).hexdigest()


# ============================================================
# 3. DATABASE
# ============================================================

def database():

    con = sqlite3.connect(DB_PATH)

    con.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT,
            scan_time TEXT NOT NULL
        )
    """)

    con.commit()

    return con


def save_history(path, result, details=""):

    con = database()

    con.execute(
        """
        INSERT INTO scan_history
        (path, result, details, scan_time)
        VALUES (?, ?, ?, ?)
        """,
        (
            str(path),
            result,
            details[:2000],
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    con.commit()
    con.close()


# ============================================================
# 4. PASSWORD CHECK
# ============================================================

def hash_password(password):

    return hashlib.sha256(
        password.encode()
    ).hexdigest()


def check_login(username, password):

    return (
        username == OWNER_USERNAME
        and
        hash_password(password)
        == OWNER_PASSWORD_HASH
    )


# ============================================================
# 5. CLAMAV FILE SCANNER
# ============================================================

def scan_file(path):

    try:

        result = subprocess.run(
            [
                "clamscan",
                "--no-summary",
                str(path)
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        output = (
            result.stdout or ""
        ) + (
            result.stderr or ""
        )

        if "FOUND" in output:

            return (
                "INFECTED",
                output
            )

        if "OK" in output:

            return (
                "CLEAN",
                output
            )

        return (
            "ERROR",
            output
        )

    except FileNotFoundError:

        return (
            "ERROR",
            "ClamAV was not found."
        )

    except subprocess.TimeoutExpired:

        return (
            "ERROR",
            "Scan timeout."
        )

    except Exception as e:

        return (
            "ERROR",
            str(e)
        )


# ============================================================
# 6. FOLDER SCANNER
# ============================================================

def scan_folder(folder):

    try:

        result = subprocess.run(
            [
                "clamscan",
                "-r",
                "--no-summary",
                str(folder)
            ],
            capture_output=True,
            text=True,
            timeout=900
        )

        output = (
            result.stdout or ""
        ) + (
            result.stderr or ""
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

        if "ERROR" in output.upper():

            return (
                "ERROR",
                output
            )

        return (
            "CLEAN",
            output
        )

    except FileNotFoundError:

        return (
            "ERROR",
            "ClamAV was not found."
        )

    except Exception as e:

        return (
            "ERROR",
            str(e)
        )


# ============================================================
# 7. LOGIN WINDOW
# ============================================================

class LoginWindow(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            "Owner Security Manager - Login"
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
            font=(
                "Segoe UI",
                18,
                "bold"
            ),
            fg="white",
            bg="#101820"
        ).pack(
            pady=(0, 25)
        )

        tk.Label(
            frame,
            text="Username",
            fg="#d9e2ec",
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
            fg="#d9e2ec",
            bg="#101820"
        ).pack(
            anchor="w"
        )

        self.password = ttk.Entry(
            frame,
            width=42,
            show="•"
        )

        self.password.pack(
            pady=(5, 18)
        )

        ttk.Button(
            frame,
            text="🔐 LOGIN",
            command=self.login
        ).pack(
            ipadx=20,
            ipady=6
        )

        self.bind(
            "<Return>",
            lambda event: self.login()
        )

        self.password.focus()

    def login(self):

        username = self.username.get().strip()

        password = self.password.get()

        if check_login(
            username,
            password
        ):

            self.destroy()

            SecurityApp().mainloop()

        else:

            messagebox.showerror(
                "Login Failed",
                "Invalid Owner username or password."
            )


# ============================================================
# 8. MAIN SECURITY APPLICATION
# ============================================================

class SecurityApp(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            "🛡️ Owner Security Manager"
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

        self.build_interface()

    # --------------------------------------------------------
    # GUI
    # --------------------------------------------------------

    def build_interface(self):

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
            font=(
                "Segoe UI",
                18,
                "bold"
            ),
            fg="white",
            bg="#101820"
        ).pack(
            side="left",
            padx=20,
            pady=16
        )

        tk.Label(
            header,
            text="Owner: nuth112",
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

        # ----------------------------------------------------
        # MENU
        # ----------------------------------------------------

        menu = tk.Frame(
            self,
            bg="#e9eef3"
        )

        menu.pack(
            fill="x"
        )

        buttons = [

            (
                "🦠 Scan File",
                self.scan_file_dialog
            ),

            (
                "📂 Scan Folder",
                self.scan_folder_dialog
            ),

            (
                "☣️ Quarantine",
                self.show_quarantine
            ),

            (
                "📁 File Manager",
                self.file_manager
            ),

            (
                "📊 History",
                self.show_history
            ),

            (
                "⚙️ Settings",
                self.settings
            )

        ]

        for text, command in buttons:

            ttk.Button(
                menu,
                text=text,
                command=command
            ).pack(
                side="left",
                padx=5,
                pady=10
            )

        # ----------------------------------------------------
        # OUTPUT
        # ----------------------------------------------------

        self.output = tk.Text(
            self,
            bg="#0b1220",
            fg="#d7e3f4",
            font=(
                "Consolas",
                10
            )
        )

        self.output.pack(
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
            fill="x",
            padx=10,
            pady=6
        )

        self.log(
            "Welcome, Owner."
        )

        self.log(
            "Security Manager is ready."
        )

    # --------------------------------------------------------
    # LOG
    # --------------------------------------------------------

    def log(self, message):

        self.output.insert(
            "end",
            "["
            + datetime.now().strftime("%H:%M:%S")
            + "] "
            + message
            + "\n"
        )

        self.output.see(
            "end"
        )

    # --------------------------------------------------------
    # SCAN FILE
    # --------------------------------------------------------

    def scan_file_dialog(self):

        if not self.scan_enabled:

            messagebox.showwarning(
                "Scanner Disabled",
                "Scanner is disabled."
            )

            return

        path = filedialog.askopenfilename(
            title="Select file"
        )

        if not path:

            return

        self.status.set(
            "Scanning..."
        )

        self.log(
            "Scanning: "
            + path
        )

        def worker():

            result, details = scan_file(
                path
            )

            save_history(
                path,
                result,
                details
            )

            self.after(
                0,
                lambda:
                self.scan_result(
                    path,
                    result,
                    details
                )
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    # --------------------------------------------------------
    # SCAN RESULT
    # --------------------------------------------------------

    def scan_result(
        self,
        path,
        result,
        details
    ):

        self.status.set(
            "Ready"
        )

        if result == "CLEAN":

            self.log(
                "✅ CLEAN"
            )

            messagebox.showinfo(
                "Scan Result",
                "✅ No malware detected."
            )

        elif result == "INFECTED":

            self.log(
                "☣️ MALWARE DETECTED"
            )

            answer = messagebox.askyesno(
                "Malware Detected",
                "Malware was detected.\n\n"
                "Move file to quarantine?"
            )

            if answer:

                self.quarantine_file(
                    Path(path)
                )

        else:

            self.log(
                "⚠️ Scanner Error"
            )

            messagebox.showerror(
                "Scanner Error",
                details[:1500]
            )

    # --------------------------------------------------------
    # SCAN FOLDER
    # --------------------------------------------------------

    def scan_folder_dialog(self):

        if not self.scan_enabled:

            messagebox.showwarning(
                "Scanner Disabled",
                "Scanner is disabled."
            )

            return

        folder = filedialog.askdirectory(
            title="Select folder"
        )

        if not folder:

            return

        self.status.set(
            "Scanning folder..."
        )

        self.log(
            "Scanning folder: "
            + folder
        )

        def worker():

            result, details = scan_folder(
                folder
            )

            save_history(
                folder,
                result,
                details
            )

            self.after(
                0,
                lambda:
                self.folder_result(
                    result,
                    details
                )
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    # --------------------------------------------------------
    # FOLDER RESULT
    # --------------------------------------------------------

    def folder_result(
        self,
        result,
        details
    ):

        self.status.set(
            "Ready"
        )

        if result == "CLEAN":

            self.log(
                "✅ Folder CLEAN"
            )

            messagebox.showinfo(
                "Scan Result",
                "No malware detected."
            )

        elif result == "INFECTED":

            self.log(
                "☣️ Malware detected."
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

    def quarantine_file(
        self,
        source
    ):

        try:

            if not source.exists():

                return

            target = (
                QUARANTINE_DIR
                / source.name
            )

            if target.exists():

                target = (
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
                str(target)
            )

            self.log(
                "🔒 Quarantined: "
                + str(target)
            )

            messagebox.showinfo(
                "Quarantine",
                "File moved to quarantine."
            )

        except Exception as e:

            messagebox.showerror(
                "Quarantine Error",
                str(e)
            )

    # --------------------------------------------------------
    # QUARANTINE WINDOW
    # --------------------------------------------------------

    def show_quarantine(self):

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
            columns=(
                "name",
                "size"
            ),
            show="headings"
        )

        tree.heading(
            "name",
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
                        values=(
                            file.name,
                            f"{file.stat().st_size:,} bytes"
                        )
                    )

        def delete():

            selected = tree.selection()

            if not selected:

                return

            path = Path(
                selected[0]
            )

            answer = messagebox.askyesno(
                "Delete",
                "Permanently delete this file?"
            )

            if answer:

                try:

                    path.unlink()

                    refresh()

                    self.log(
                        "🗑️ Deleted: "
                        + path.name
                    )

                except Exception as e:

                    messagebox.showerror(
                        "Error",
                        str(e)
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
            text="🗑️ Delete",
            command=delete
        ).pack(
            side="left",
            padx=5
        )

        refresh()

    # --------------------------------------------------------
    # FILE MANAGER
    # --------------------------------------------------------

    def file_manager(self):

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
            "path": Path.home()
        }

        path_var = tk.StringVar(
            value=str(
                current["path"]
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
            columns=(
                "type",
                "size"
            ),
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

            current["path"] = folder

            try:

                items = sorted(
                    folder.iterdir(),
                    key=lambda x: (
                        not x.is_dir(),
                        x.name.lower()
                    )
                )

                for item in items:

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
                                f"{item.stat().st_size:,} bytes"
                            )
                        )

            except PermissionError:

                messagebox.showerror(
                    "Access denied",
                    "You do not have permission to access this folder."
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

                except Exception as e:

                    messagebox.showerror(
                        "Open Error",
                        str(e)
                    )

        def delete():

            selected = tree.selection()

            if not selected:

                return

            path = Path(
                selected[0]
            )

            answer = messagebox.askyesno(
                "Delete",
                f"Delete {path.name}?"
            )

            if not answer:

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
                    "🗑️ Deleted: "
                    + str(path)
                )

            except Exception as e:

                messagebox.showerror(
                    "Delete Error",
                    str(e)
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

    def show_history(self):

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

        tree.column(
            "path",
            width=580
        )

        tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        con = database()

        rows = con.execute(
            """
            SELECT path,result,scan_time
            FROM scan_history
            ORDER BY id DESC
            LIMIT 500
            """
        ).fetchall()

        con.close()

        for row in rows:

            tree.insert(
                "",
                "end",
                values=row
            )

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    def settings(self):

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
            text="⚙️ Scanner Settings",
            font=(
                "Segoe UI",
                15,
                "bold"
            )
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
            text=
            "Scanner: ClamAV\n\n"
            "Quarantine:\n"
            + str(QUARANTINE_DIR),
            wraplength=450
        ).pack(
            pady=10
        )

        def save():

            self.scan_enabled = enabled.get()

            self.log(
                "🟢 Scanner enabled."
                if self.scan_enabled
                else
                "🔴 Scanner disabled."
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
# 9. START PROGRAM
# ============================================================

if __name__ == "__main__":

    LoginWindow().mainloop()

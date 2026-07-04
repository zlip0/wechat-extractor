"""
WeChat Message Extractor - GUI Application.

Provides a tkinter-based GUI for detecting WeChat, listing chats,
and exporting selected conversations to TXT files.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import sys
import os
import ctypes

from extractor import WeChatExtractor, is_admin
from app_config import APP_NAME, APP_VERSION
from updater import (
    cleanup_old_update_files,
    fetch_manifest,
    is_update_available,
    download_update,
    apply_update,
)


class WeChatExtractorApp:
    """Main GUI application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WeChat Message Extractor")
        self.root.geometry("780x650")
        self.root.minsize(650, 550)

        self.extractor = WeChatExtractor()
        self.chat_items = {}  # tree item id -> ChatInfo
        self.selected_chats = set()  # set of tree item ids

        self._build_ui()

        # Auto-detect WeChat on launch
        self.root.after(500, self.detect_wechat)

    def _build_ui(self):
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Segoe UI", 11, "bold"))

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # ── Account Section ──
        acct_frame = ttk.LabelFrame(main, text="WeChat Account", padding=10)
        acct_frame.pack(fill=tk.X, pady=(0, 8))

        self.status_label = ttk.Label(
            acct_frame, text="Detecting WeChat...", wraplength=600
        )
        self.status_label.pack(anchor=tk.W)

        btn_row = ttk.Frame(acct_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))

        self.detect_btn = ttk.Button(
            btn_row, text="Detect WeChat", command=self.detect_wechat
        )
        self.detect_btn.pack(side=tk.LEFT, padx=(0, 5))

        # ── Chat List Section ──
        chat_frame = ttk.LabelFrame(main, text="Chat History", padding=10)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        # Search bar
        search_frame = ttk.Frame(chat_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_changed)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )

        # Treeview for chat list
        tree_frame = ttk.Frame(chat_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("selected", "name", "count", "type")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="none"
        )
        self.tree.heading("selected", text="✓")
        self.tree.heading("name", text="Chat Name")
        self.tree.heading("count", text="Messages")
        self.tree.heading("type", text="Type")

        self.tree.column("selected", width=30, anchor=tk.CENTER, stretch=False)
        self.tree.column("name", width=400)
        self.tree.column("count", width=80, anchor=tk.E)
        self.tree.column("type", width=70, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Toggle selection on click
        self.tree.bind("<ButtonRelease-1>", self._on_tree_click)

        # Tags for visual feedback
        self.tree.tag_configure("checked", background="#e6f3ff")
        self.tree.tag_configure("unchecked", background="white")

        # Buttons
        btn_frame = ttk.Frame(chat_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(btn_frame, text="Select All", command=self._select_all).pack(
            side=tk.LEFT, padx=(0, 5)
        )
        ttk.Button(btn_frame, text="Deselect All", command=self._deselect_all).pack(
            side=tk.LEFT
        )

        self.selected_label = ttk.Label(btn_frame, text="0 selected")
        self.selected_label.pack(side=tk.RIGHT)

        # ── Export Section ──
        export_frame = ttk.LabelFrame(main, text="Export", padding=10)
        export_frame.pack(fill=tk.X)

        # Output directory
        dir_frame = ttk.Frame(export_frame)
        dir_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(dir_frame, text="Output:").pack(side=tk.LEFT)
        default_output = os.path.join(
            os.path.expanduser("~"), "Desktop", "WeChat_Export"
        )
        self.output_var = tk.StringVar(value=default_output)
        ttk.Entry(dir_frame, textvariable=self.output_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5
        )
        ttk.Button(dir_frame, text="Browse", command=self._browse_output).pack(
            side=tk.RIGHT
        )

        # Export button
        self.export_btn = ttk.Button(
            export_frame,
            text="Export Selected Chats",
            command=self.export_chats,
            state=tk.DISABLED,
        )
        self.export_btn.pack(fill=tk.X, pady=(5, 5))

        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            export_frame, variable=self.progress_var, maximum=100
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))

        self.progress_label = ttk.Label(export_frame, text="", wraplength=600)
        self.progress_label.pack(anchor=tk.W)

    # ── Tree interactions ──

    def _on_tree_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if item in self.selected_chats:
            self.selected_chats.discard(item)
            self.tree.set(item, "selected", "☐")
            self.tree.item(item, tags=("unchecked",))
        else:
            self.selected_chats.add(item)
            self.tree.set(item, "selected", "☑")
            self.tree.item(item, tags=("checked",))
        self._update_selected_count()

    def _select_all(self):
        for item in self.tree.get_children():
            self.selected_chats.add(item)
            self.tree.set(item, "selected", "☑")
            self.tree.item(item, tags=("checked",))
        self._update_selected_count()

    def _deselect_all(self):
        for item in self.tree.get_children():
            self.selected_chats.discard(item)
            self.tree.set(item, "selected", "☐")
            self.tree.item(item, tags=("unchecked",))
        self._update_selected_count()

    def _update_selected_count(self):
        # Count only visible selected items
        visible = set(self.tree.get_children())
        count = len(self.selected_chats & visible)
        self.selected_label.config(text=f"{count} selected")

    def _on_search_changed(self, *_args):
        query = self.search_var.get().lower()
        self._populate_tree(query)

    def _populate_tree(self, search_filter=""):
        """Repopulate the treeview, optionally filtered."""
        self.tree.delete(*self.tree.get_children())

        for chat in self.extractor.chats:
            if search_filter and search_filter not in chat.display_name.lower():
                continue

            chat_type = "Group" if chat.is_group else "Private"
            item_id = self.tree.insert(
                "",
                tk.END,
                values=("☐", chat.display_name, chat.msg_count, chat_type),
                tags=("unchecked",),
            )
            self.chat_items[item_id] = chat

            # Restore selection state
            if item_id in self.selected_chats:
                self.tree.set(item_id, "selected", "☑")
                self.tree.item(item_id, tags=("checked",))

        # When repopulating after search, we need to re-map by username
        # since tree item IDs change on repopulation
        self._remap_selections()

    def _remap_selections(self):
        """After tree repopulation, re-apply selections based on usernames."""
        # This is needed because tree item IDs change when items are re-inserted
        # We track by username instead
        selected_usernames = set()
        for item_id in list(self.selected_chats):
            chat = self.chat_items.get(item_id)
            if chat:
                selected_usernames.add(chat.username)

        self.selected_chats.clear()
        self.chat_items.clear()

        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            # Find matching chat by display name
            for chat in self.extractor.chats:
                if (
                    chat.display_name == values[1]
                    and str(chat.msg_count) == str(values[2])
                ):
                    self.chat_items[item_id] = chat
                    if chat.username in selected_usernames:
                        self.selected_chats.add(item_id)
                        self.tree.set(item_id, "selected", "☑")
                        self.tree.item(item_id, tags=("checked",))
                    break

        self._update_selected_count()

    # ── Output directory ──

    def _browse_output(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_var.set(directory)

    # ── Progress updates (thread-safe) ──

    def _set_status(self, text):
        self.root.after(0, lambda: self.status_label.config(text=text))

    def _set_progress_text(self, text):
        self.root.after(0, lambda: self.progress_label.config(text=text))

    def _set_progress_bar(self, value):
        self.root.after(0, lambda: self.progress_var.set(value))

    # ── Detection ──

    def detect_wechat(self):
        self.detect_btn.config(state=tk.DISABLED)
        self._set_status("Detecting WeChat...")
        self._set_progress_text("")
        self._set_progress_bar(0)

        def _worker():
            # Step 1: Detect (passes progress callback for native scan feedback)
            info, error = self.extractor.detect_wechat(
                progress_callback=self._set_progress_text
            )
            if error:
                self._set_status(f"❌ {error}")
                self.root.after(0, lambda: self.detect_btn.config(state=tk.NORMAL))
                return

            self._set_status(
                f"✅ Account: {info.name} ({info.wxid})  |  Version: {info.version}"
            )

            # Step 2: Decrypt
            self._set_progress_text("Decrypting databases (this may take a moment)...")
            success, error = self.extractor.decrypt_databases(self._set_progress_text)
            if not success:
                self._set_progress_text(f"❌ {error}")
                self.root.after(0, lambda: self.detect_btn.config(state=tk.NORMAL))
                return

            # Step 3: Load contacts
            self.extractor.load_contacts(self._set_progress_text)

            # Step 4: Get chat list
            chats, error = self.extractor.get_chat_list(self._set_progress_text)
            if error:
                self._set_progress_text(f"❌ {error}")
                self.root.after(0, lambda: self.detect_btn.config(state=tk.NORMAL))
                return

            # Update UI on main thread
            def _update_ui():
                self.selected_chats.clear()
                self.chat_items.clear()
                self._populate_tree()
                self.export_btn.config(state=tk.NORMAL)
                self.detect_btn.config(state=tk.NORMAL)

            self.root.after(0, _update_ui)
            self._set_progress_text(f"Ready — {len(chats)} chats found.")
            self._set_progress_bar(100)

        threading.Thread(target=_worker, daemon=True).start()

    # ── Export ──

    def export_chats(self):
        # Gather selected chats
        selected = []
        for item_id in self.selected_chats:
            chat = self.chat_items.get(item_id)
            if chat:
                selected.append(chat)

        if not selected:
            messagebox.showwarning("No Selection", "Please select at least one chat to export.")
            return

        output_dir = self.output_var.get().strip()
        if not output_dir:
            messagebox.showwarning("No Output", "Please select an output directory.")
            return

        self.export_btn.config(state=tk.DISABLED)
        self._set_progress_bar(0)

        my_name = self.extractor.wx_info.name if self.extractor.wx_info else "Me"

        def _worker():
            def on_progress(text, pct):
                self._set_progress_text(text)
                self._set_progress_bar(pct)

            success_count, errors = self.extractor.export_multiple_chats(
                selected, output_dir, my_name, on_progress
            )

            self._set_progress_bar(100)
            self._set_progress_text(
                f"Export complete: {success_count}/{len(selected)} chats exported to {output_dir}"
            )
            self.root.after(0, lambda: self.export_btn.config(state=tk.NORMAL))

            if errors:
                error_msg = "\n".join(errors[:15])
                if len(errors) > 15:
                    error_msg += f"\n... and {len(errors) - 15} more"
                self.root.after(
                    0,
                    lambda: messagebox.showwarning(
                        "Export Warnings",
                        f"Some chats could not be exported:\n\n{error_msg}",
                    ),
                )

            # Open output directory
            if success_count > 0:
                self.root.after(0, lambda: os.startfile(output_dir))

        threading.Thread(target=_worker, daemon=True).start()

    # ── Cleanup ──

    def on_closing(self):
        self.extractor.cleanup()
        self.root.destroy()


def main():
    # Clean up leftover files from a previous update
    cleanup_old_update_files()

    # Auto-elevate to admin if needed
    if not is_admin():
        script = os.path.abspath(sys.argv[0])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}"', None, 1
        )
        if ret > 32:
            # Elevation succeeded, new process spawned
            sys.exit(0)
        # If elevation failed/declined, continue anyway — will show error in GUI

    # ── Version check — auto-update if a newer version is available ──
    manifest = fetch_manifest()

    if manifest and is_update_available(manifest):
        ver = manifest.get("latest_version", "?")

        # Show a non-interactive splash while downloading
        splash = tk.Tk()
        splash.overrideredirect(True)
        splash.attributes("-topmost", True)
        w, h = 360, 80
        sx = (splash.winfo_screenwidth() - w) // 2
        sy = (splash.winfo_screenheight() - h) // 2
        splash.geometry(f"{w}x{h}+{sx}+{sy}")
        tk.Label(
            splash,
            text=f"Updating to v{ver}…\nPlease wait.",
            font=("Segoe UI", 11),
            justify="center",
        ).pack(expand=True)
        splash.update()

        path = download_update(manifest)
        splash.destroy()

        if path:
            apply_update(path)  # replaces exe and restarts — never returns
        # If the download failed, just continue with the current version

    root = tk.Tk()
    app = WeChatExtractorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()

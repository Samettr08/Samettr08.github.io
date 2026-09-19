#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SAMET-AV | SHA-256 Hash Çıkarıcı (Sürükle-Bırak Destekli)
Sadece dosyanın SHA-256 hash değerini hesaplar, ekranda gösterir ve panoya kopyalar.
"""

import os
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
from ctypes import wintypes

class SHA256ExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SAMET-AV | SHA-256 Çıkarıcı")
        self.root.geometry("640, 360")
        self.root.minsize(560, 300)
        self.root.configure(bg="#ece9d8")

        # XP Stili Pencere
        self.create_widgets()
        self.setup_drag_and_drop()

    def create_widgets(self):
        # Başlık Bannerı
        header_frame = tk.Frame(self.root, bg="#0055ea", height=50)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)

        lbl_title = tk.Label(
            header_frame, 
            text="🛡️ SAMET-AV SHA-256 HASH ÇIKARICI", 
            font=("Tahoma", 11, "bold"), 
            fg="white", 
            bg="#0055ea"
        )
        lbl_title.pack(anchor="w", padx=15, pady=(6, 0))

        lbl_sub = tk.Label(
            header_frame, 
            text="Herhangi bir dosyayı sürükleyip bırakın — Sadece temiz SHA-256 hash bilgisini verir", 
            font=("Tahoma", 8), 
            fg="#dcebff", 
            bg="#0055ea"
        )
        lbl_sub.pack(anchor="w", padx=15)

        # Ana Gövde
        body = tk.Frame(self.root, bg="#ece9d8", padx=15, pady=15)
        body.pack(fill=tk.BOTH, expand=True)

        # Sürükle Bırak Bırakma Kutusu
        self.drop_frame = tk.Frame(
            body, 
            bg="#ffffff", 
            bd=2, 
            relief="groove", 
            cursor="hand2"
        )
        self.drop_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.drop_frame.bind("<Button-1>", lambda e: self.select_file())

        self.lbl_drop = tk.Label(
            self.drop_frame,
            text="📂 DOSYAYI BURAYA SÜRÜKLEYİP BIRAKIN\n\nveya dosya seçmek için buraya tıklayın",
            font=("Tahoma", 10, "bold"),
            fg="#003399",
            bg="#ffffff"
        )
        self.lbl_drop.pack(expand=True)
        self.lbl_drop.bind("<Button-1>", lambda e: self.select_file())

        # Dosya Adı Bilgisi
        self.lbl_file_info = tk.Label(
            body,
            text="Henüz dosya seçilmedi.",
            font=("Tahoma", 8, "italic"),
            fg="#555555",
            bg="#ece9d8"
        )
        self.lbl_file_info.pack(anchor="w", pady=(0, 5))

        # SHA-256 Çıktı Kutusu
        lbl_res = tk.Label(
            body,
            text="SHA-256 Hash Değeri:",
            font=("Tahoma", 8, "bold"),
            bg="#ece9d8",
            fg="#000000"
        )
        lbl_res.pack(anchor="w")

        hash_frame = tk.Frame(body, bg="#ece9d8")
        hash_frame.pack(fill=tk.X, pady=(2, 10))

        self.txt_hash = tk.Entry(
            hash_frame,
            font=("Consolas", 10, "bold"),
            fg="#003300",
            bg="#fafffa",
            bd=2,
            relief="sunken"
        )
        self.txt_hash.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)

        btn_copy = tk.Button(
            hash_frame,
            text="📋 Panoya Kopyala",
            font=("Tahoma", 8, "bold"),
            bg="#ece9d8",
            command=self.copy_hash,
            cursor="hand2",
            padx=10
        )
        btn_copy.pack(side=tk.RIGHT, padx=(6, 0))

        # Alt Butonlar
        bottom_frame = tk.Frame(body, bg="#ece9d8")
        bottom_frame.pack(fill=tk.X)

        btn_browse = tk.Button(
            bottom_frame,
            text="📂 Dosya Seç...",
            font=("Tahoma", 8, "bold"),
            bg="#ece9d8",
            command=self.select_file,
            cursor="hand2",
            padx=12,
            pady=3
        )
        btn_browse.pack(side=tk.LEFT)

        self.lbl_status = tk.Label(
            bottom_frame,
            text="Hazır.",
            font=("Tahoma", 8),
            fg="#008800",
            bg="#ece9d8"
        )
        self.lbl_status.pack(side=tk.RIGHT)

    def select_file(self):
        file_path = filedialog.askopenfilename(title="SHA-256 Hesaplanacak Dosyayı Seçin")
        if file_path:
            self.process_file(file_path)

    def process_file(self, file_path):
        if not os.path.exists(file_path):
            messagebox.showerror("Hata", f"Dosya bulunamadı:\n{file_path}")
            return

        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            self.lbl_status.config(text="Hesaplanıyor...", fg="#0055ea")
            self.root.update_idletasks()

            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)

            hash_hex = sha256.hexdigest().lower()

            self.txt_hash.delete(0, tk.END)
            self.txt_hash.insert(0, hash_hex)

            # Otomatik panoya kopyala
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_hex)

            size_str = f"{file_size:,} bytes"
            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.2f} MB"
            elif file_size > 1024:
                size_str = f"{file_size / 1024:.2f} KB"

            self.lbl_file_info.config(text=f"Dosya: {file_name} ({size_str})")
            self.lbl_status.config(text="✅ Hash Çıkarıldı ve Panoya Kopyalandı!", fg="#008800")

        except Exception as ex:
            messagebox.showerror("Hata", f"Hash hesaplanırken hata oluştu:\n{str(ex)}")
            self.lbl_status.config(text="Hata oluştu!", fg="#cc0000")

    def copy_hash(self):
        h = self.txt_hash.get().strip()
        if h:
            self.root.clipboard_clear()
            self.root.clipboard_append(h)
            self.lbl_status.config(text="📋 Panoya Kopyalandı!", fg="#008800")
        else:
            messagebox.showwarning("Uyarı", "Kopyalanacak bir hash değeri yok!")

    def setup_drag_and_drop(self):
        """Windows API ile saf drag & drop desteği (harici kütüphane gerektirmez)"""
        if sys.platform != "win32":
            return

        try:
            # Pencere handle'ını al
            hwnd = self.root.winfo_id()
            shell32 = ctypes.windll.shell32

            # DragAcceptFiles(hwnd, True)
            shell32.DragAcceptFiles(hwnd, True)

            # Windows mesajlarını yakalamak için WNDPROC kancası
            GWL_WNDPROC = -4
            WM_DROPFILES = 0x0233

            WNDPROC = ctypes.WINFUNCTYPE(
                wintypes.LPARAM,
                wintypes.HWND,
                wintypes.UINT,
                wintypes.WPARAM,
                wintypes.LPARAM
            )

            # 64-bit / 32-bit uyumluluğu
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                SetWindowLong = ctypes.windll.user32.SetWindowLongPtrW
                GetWindowLong = ctypes.windll.user32.GetWindowLongPtrW
            else:
                SetWindowLong = ctypes.windll.user32.SetWindowLongW
                GetWindowLong = ctypes.windll.user32.GetWindowLongW

            old_wndproc = GetWindowLong(hwnd, GWL_WNDPROC)

            def wndproc(h_wnd, msg, w_param, l_param):
                if msg == WM_DROPFILES:
                    h_drop = w_param
                    # Dosya sayısını al
                    count = shell32.DragQueryFileW(h_drop, 0xFFFFFFFF, None, 0)
                    if count > 0:
                        buffer = ctypes.create_unicode_buffer(512)
                        shell32.DragQueryFileW(h_drop, 0, buffer, 512)
                        dropped_file = buffer.value
                        shell32.DragFinish(h_drop)
                        self.root.after(10, lambda f=dropped_file: self.process_file(f))
                        return 0
                    shell32.DragFinish(h_drop)
                    return 0

                return ctypes.windll.user32.CallWindowProcW(
                    old_wndproc, h_wnd, msg, w_param, l_param
                )

            self.new_wndproc = WNDPROC(wndproc)
            SetWindowLong(hwnd, GWL_WNDPROC, self.new_wndproc)

        except Exception as e:
            # Drag drop Windows API başarısız olsa bile dosya seç butonu çalışır
            pass

def main():
    root = tk.Tk()
    app = SHA256ExtractorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

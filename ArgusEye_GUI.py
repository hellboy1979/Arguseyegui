"""
ArgusEye GUI — wrapper grafico per ArgusEye.py.

NON modifica ArgusEye.py. Lancia ciascun modulo come subprocess
(`python -u -c "from ArgusEye import run_X; run_X()"`) e ne renderizza
l'output (incluse le sequenze ANSI di colorama) in una textbox.

Requisiti:
    pip install customtkinter

Avvio:
    python ArgusEye_GUI.py
"""

import os
import re
import sys
import queue
import threading
import subprocess
from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk


PROJECT_DIR = Path(__file__).parent.resolve()
ARGUSEYE_PY = PROJECT_DIR / "ArgusEye.py"

ANSI_RE = re.compile(r"\x1b\[(\d+(?:;\d+)*)m")

ANSI_COLOR_MAP = {
    "30": "#6272a4", "90": "#6272a4",
    "31": "#ff5555", "91": "#ff6e6e",
    "32": "#50fa7b", "92": "#69ff94",
    "33": "#f1fa8c", "93": "#ffffa5",
    "34": "#bd93f9", "94": "#caa9fa",
    "35": "#ff79c6", "95": "#ff92d0",
    "36": "#8be9fd", "96": "#a4ffff",
    "37": "#f8f8f2", "97": "#ffffff",
}

MODULES = [
    {
        "key": "scanner",
        "label": "1. Scanner CIDR",
        "func": "run_scanner",
        "needs_cidr": True,
        "confirm": False,
        "description": "Scansiona un range CIDR per host con porta 80 aperta. Salva in host.txt.",
    },
    {
        "key": "brute",
        "label": "2. Brute Force Hikvision",
        "func": "run_brute_force",
        "needs_cidr": False,
        "confirm": False,
        "description": "Brute force credenziali Hikvision usando host.txt + user.txt + pass.txt.",
    },
    {
        "key": "cve2017",
        "label": "3. CVE-2017-7921",
        "func": "run_cve_2017_7921",
        "needs_cidr": False,
        "confirm": False,
        "description": "Information disclosure su Hikvision. Legge host.txt.",
    },
    {
        "key": "uniview",
        "label": "4. Uniview Disclosure",
        "func": "run_uniview_disclosure",
        "needs_cidr": False,
        "confirm": False,
        "description": "Disclosure credenziali Uniview. Legge host.txt.",
    },
    {
        "key": "cve2021",
        "label": "5. CVE-2021-36260",
        "func": "run_cve_2021_36260",
        "needs_cidr": False,
        "confirm": True,
        "description": "Command injection Hikvision. ATTENZIONE: installa backdoor SSH sui vulnerabili.",
    },
]


class ArgusEyeGUI:
    def __init__(self):
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("ArgusEye — GUI")
        self.root.geometry("1180x780")
        self.root.minsize(900, 600)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.proc: subprocess.Popen | None = None
        self.output_queue: queue.Queue[str] = queue.Queue()
        self._current_ansi_color: str | None = None
        self._configured_tags: set[str] = set()

        self._build_ui()
        self.root.after(50, self._drain_queue)
        self.root.after(200, self._show_disclaimer)

    # ---------- UI ----------
    def _build_ui(self) -> None:
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # Banner top
        banner = ctk.CTkFrame(self.root, fg_color="#1f2937", corner_radius=0)
        banner.grid(row=0, column=0, columnspan=2, sticky="ew")
        banner.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            banner,
            text="ArgusEye — Security Testing GUI",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#8be9fd",
        ).grid(row=0, column=0, padx=16, pady=(10, 0), sticky="w")
        ctk.CTkLabel(
            banner,
            text="Uso autorizzato su dispositivi propri o con scope scritto. L'uso non autorizzato è illegale.",
            font=ctk.CTkFont(size=11),
            text_color="#f1fa8c",
        ).grid(row=1, column=0, padx=16, pady=(0, 10), sticky="w")

        # Sidebar controlli
        sidebar = ctk.CTkScrollableFrame(self.root, width=330, corner_radius=0)
        sidebar.grid(row=1, column=0, sticky="nsw", padx=(0, 0), pady=0)

        ctk.CTkLabel(
            sidebar,
            text="Moduli",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(12, 4))

        # CIDR input (solo scanner)
        cidr_frame = ctk.CTkFrame(sidebar)
        cidr_frame.pack(fill="x", padx=12, pady=(4, 12))
        ctk.CTkLabel(cidr_frame, text="CIDR (per Scanner)", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=8, pady=(6, 2))
        self.cidr_entry = ctk.CTkEntry(cidr_frame, placeholder_text="es. 192.168.1.0/24")
        self.cidr_entry.pack(fill="x", padx=8, pady=(0, 8))

        # Pulsanti modulo
        for mod in MODULES:
            block = ctk.CTkFrame(sidebar)
            block.pack(fill="x", padx=12, pady=6)
            color = "#7c2d12" if mod["confirm"] else None
            btn = ctk.CTkButton(
                block,
                text=mod["label"],
                command=lambda m=mod: self._launch(m),
                fg_color=color,
                hover_color="#991b1b" if mod["confirm"] else None,
            )
            btn.pack(fill="x", padx=8, pady=(8, 4))
            ctk.CTkLabel(
                block,
                text=mod["description"],
                font=ctk.CTkFont(size=10),
                text_color="#94a3b8",
                wraplength=280,
                justify="left",
            ).pack(anchor="w", padx=8, pady=(0, 8))

        # Controlli esecuzione
        ctrl = ctk.CTkFrame(sidebar)
        ctrl.pack(fill="x", padx=12, pady=(12, 12))
        ctk.CTkLabel(ctrl, text="Controlli", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=8, pady=(6, 4))
        ctk.CTkButton(ctrl, text="Stop processo", command=self._stop_process, fg_color="#b45309", hover_color="#92400e").pack(fill="x", padx=8, pady=4)
        ctk.CTkButton(ctrl, text="Pulisci output", command=self._clear_output, fg_color="#374151", hover_color="#1f2937").pack(fill="x", padx=8, pady=(4, 8))

        # Output a destra
        out_frame = ctk.CTkFrame(self.root, corner_radius=0)
        out_frame.grid(row=1, column=1, sticky="nsew")
        out_frame.grid_columnconfigure(0, weight=1)
        out_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            out_frame, text="Output", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        self.output = ctk.CTkTextbox(
            out_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word",
            fg_color="#0b1020",
            text_color="#e2e8f0",
        )
        self.output.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))
        self.output.configure(state="disabled")

        # Status bar
        self.status_var = ctk.StringVar(value="Pronto.")
        status = ctk.CTkLabel(
            self.root,
            textvariable=self.status_var,
            anchor="w",
            font=ctk.CTkFont(size=11),
            fg_color="#111827",
            text_color="#cbd5e1",
        )
        status.grid(row=2, column=0, columnspan=2, sticky="ew")

    # ---------- Disclaimer ----------
    def _show_disclaimer(self) -> None:
        messagebox.showwarning(
            "ArgusEye — Uso responsabile",
            "Questo strumento esegue test di sicurezza ATTIVI su telecamere "
            "Hikvision/Uniview (scansione, brute force credenziali, exploit CVE).\n\n"
            "USA SOLO su dispositivi di tua proprietà o per i quali hai "
            "autorizzazione scritta esplicita. L'uso non autorizzato contro "
            "sistemi di terzi è illegale e perseguibile penalmente.\n\n"
            "Il modulo CVE-2021-36260 installa una backdoor SSH sui dispositivi "
            "vulnerabili: assicurati che gli host in host.txt siano autorizzati.",
            parent=self.root,
        )

    # ---------- Subprocess ----------
    def _launch(self, mod: dict) -> None:
        if self.proc is not None and self.proc.poll() is None:
            messagebox.showinfo(
                "Modulo in esecuzione",
                "Un modulo è già in esecuzione. Attendi il termine o premi 'Stop processo'.",
                parent=self.root,
            )
            return

        if not ARGUSEYE_PY.exists():
            messagebox.showerror(
                "File mancante",
                f"Non trovo {ARGUSEYE_PY}. La GUI deve stare nella stessa cartella di ArgusEye.py.",
                parent=self.root,
            )
            return

        stdin_text = ""
        if mod["needs_cidr"]:
            cidr = self.cidr_entry.get().strip()
            if not cidr:
                messagebox.showwarning(
                    "CIDR mancante",
                    "Inserisci un range CIDR (es. 192.168.1.0/24) prima di avviare lo Scanner.",
                    parent=self.root,
                )
                return
            stdin_text = cidr + "\n"

        if mod["confirm"]:
            host_file = PROJECT_DIR / "host.txt"
            host_info = ""
            if host_file.exists():
                try:
                    lines = [l.strip() for l in host_file.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                    host_info = f"\n\nhost.txt contiene {len(lines)} host."
                except OSError:
                    pass
            ok = messagebox.askyesno(
                "Conferma CVE-2021-36260",
                "Stai per lanciare il modulo CVE-2021-36260.\n\n"
                "Questo modulo, su ogni host trovato vulnerabile, INSTALLA "
                "automaticamente una backdoor SSH sul dispositivo (vedi "
                "ArgusEye.py riga 792).\n\n"
                "Confermi che TUTTI gli host elencati in host.txt sono di "
                "tua proprietà o coperti da autorizzazione scritta?" + host_info,
                parent=self.root,
                icon="warning",
            )
            if not ok:
                self._append_plain("[GUI] CVE-2021-36260 annullato dall'utente.\n", "#f1fa8c")
                return

        self._clear_output()
        self._append_plain(f"[GUI] avvio {mod['func']}...\n", "#8be9fd")
        self.status_var.set(f"In esecuzione: {mod['func']}")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        # Suggerisce a colorama di non strippare i codici
        env["FORCE_COLOR"] = "1"
        env["CLICOLOR_FORCE"] = "1"

        cmd = [
            sys.executable,
            "-u",
            "-c",
            f"from ArgusEye import {mod['func']}; {mod['func']}()",
        ]

        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_DIR),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                bufsize=1,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as e:
            messagebox.showerror("Errore avvio", f"Impossibile avviare il subprocess: {e}", parent=self.root)
            self.status_var.set("Errore avvio")
            self.proc = None
            return

        try:
            if stdin_text:
                self.proc.stdin.write(stdin_text)
                self.proc.stdin.flush()
            self.proc.stdin.close()
        except OSError:
            pass

        threading.Thread(target=self._reader_thread, args=(self.proc,), daemon=True).start()

    def _reader_thread(self, proc: subprocess.Popen) -> None:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                self.output_queue.put(line)
        except Exception as e:
            self.output_queue.put(f"[GUI] errore lettura output: {e}\n")
        finally:
            rc = proc.wait()
            self.output_queue.put(f"\n[GUI] processo terminato (exit code {rc}).\n")
            self.output_queue.put("__STATUS__:Pronto.")

    def _stop_process(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self._append_plain("[GUI] arresto richiesto (terminate).\n", "#f1fa8c")
                self.status_var.set("Arresto richiesto...")
            except OSError as e:
                self._append_plain(f"[GUI] errore terminate: {e}\n", "#ff5555")
        else:
            self._append_plain("[GUI] nessun processo in esecuzione.\n", "#94a3b8")

    # ---------- Output / ANSI ----------
    def _drain_queue(self) -> None:
        try:
            while True:
                item = self.output_queue.get_nowait()
                if isinstance(item, str) and item.startswith("__STATUS__:"):
                    self.status_var.set(item.split(":", 1)[1])
                else:
                    self._append_ansi(item)
        except queue.Empty:
            pass
        self.root.after(50, self._drain_queue)

    def _ensure_tag(self, color_hex: str) -> str:
        tag = f"c_{color_hex.lstrip('#')}"
        if tag not in self._configured_tags:
            self.output.tag_config(tag, foreground=color_hex)
            self._configured_tags.add(tag)
        return tag

    def _insert_chunk(self, text: str, color: str | None) -> None:
        if not text:
            return
        if color:
            self.output.insert("end", text, self._ensure_tag(color))
        else:
            self.output.insert("end", text)

    def _append_ansi(self, text: str) -> None:
        self.output.configure(state="normal")
        pos = 0
        for m in ANSI_RE.finditer(text):
            chunk = text[pos : m.start()]
            self._insert_chunk(chunk, self._current_ansi_color)
            for code in m.group(1).split(";"):
                if code in ("", "0"):
                    self._current_ansi_color = None
                elif code in ANSI_COLOR_MAP:
                    self._current_ansi_color = ANSI_COLOR_MAP[code]
            pos = m.end()
        rest = text[pos:]
        self._insert_chunk(rest, self._current_ansi_color)
        self.output.configure(state="disabled")
        self.output.see("end")

    def _append_plain(self, text: str, color: str | None = None) -> None:
        self.output.configure(state="normal")
        self._insert_chunk(text, color)
        self.output.configure(state="disabled")
        self.output.see("end")

    def _clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self._current_ansi_color = None

    # ---------- Lifecycle ----------
    def _on_close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            ok = messagebox.askyesno(
                "Chiusura",
                "Un modulo è in esecuzione. Terminare il processo e uscire?",
                parent=self.root,
            )
            if not ok:
                return
            try:
                self.proc.terminate()
            except OSError:
                pass
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    if not ARGUSEYE_PY.exists():
        print(f"Errore: {ARGUSEYE_PY} non trovato. Posiziona ArgusEye_GUI.py nella stessa cartella di ArgusEye.py.")
        return 1
    ArgusEyeGUI().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

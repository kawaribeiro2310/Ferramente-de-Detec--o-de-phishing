import re
import tkinter as tk
from tkinter import ttk, messagebox


class PhishingScannerApp:

    def __init__(self, root):
        self.root = root
        self.root.title("ScanShield AI - Detector de Phishing")
        self.root.geometry("650x550")
        self.root.configure(bg="#12181f")
        self.root.resizable(False, False)

        # Paleta de Cores
        self.colors = {
            "bg_dark": "#12181f",
            "card_bg": "#1e2630",
            "card_border": "#2e3a48",
            "accent_blue": "#2563eb",
            "text_main": "#f1f5f9",
            "text_muted": "#94a3b8",
            "safe": "#22c55e",
            "danger": "#ef4444",
            "warning": "#f59e0b",
        }

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")

        # Configuração das Abas (Notebook)
        style.configure("TNotebook", background=self.colors["bg_dark"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#18202a",
            foreground=self.colors["text_muted"],
            padding=[20, 10],
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["card_bg"])],
            foreground=[("selected", self.colors["accent_blue"])],
        )

    def _build_ui(self):
        # Cabeçalho
        header_frame = tk.Frame(self.root, bg=self.colors["bg_dark"], pady=15)
        header_frame.pack(fill="x", padx=20)

        title_label = tk.Label(
            header_frame,
            text="🛡️ ScanShield AI",
            font=("Segoe UI", 16, "bold"),
            fg=self.colors["text_main"],
            bg=self.colors["bg_dark"],
        )
        title_label.pack(side="left")

        # Container Principal de Abas
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Aba 1: Email Scanner
        self.email_tab = tk.Frame(notebook, bg=self.colors["card_bg"], padx=20, pady=20)
        notebook.add(self.email_tab, text="✉️ Scanner de E-mail")
        self._build_email_tab()

        # Aba 2: Website Scanner
        self.web_tab = tk.Frame(notebook, bg=self.colors["card_bg"], padx=20, pady=20)
        notebook.add(self.web_tab, text="🌐 Scanner de Website")
        self._build_web_tab()

        # Painel de Resultado
        self.result_frame = tk.Frame(
            self.root,
            bg="#161d26",
            highlightbackground=self.colors["card_border"],
            highlightthickness=1,
            padx=15,
            pady=15,
        )
        self.result_frame.pack(fill="x", padx=20, pady=(0, 20))

        self.result_title = tk.Label(
            self.result_frame,
            text="Aguardando análise...",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors["text_muted"],
            bg="#161d26",
            anchor="w",
        )
        self.result_title.pack(fill="x")

        self.result_details = tk.Label(
            self.result_frame,
            text="Insira o texto de um e-mail ou uma URL acima para iniciar o escaneamento.",
            font=("Segoe UI", 9),
            fg=self.colors["text_muted"],
            bg="#161d26",
            justify="left",
            anchor="w",
            wraplength=570,
        )
        self.result_details.pack(fill="x", pady=(5, 0))

    def _build_email_tab(self):
        lbl = tk.Label(
            self.email_tab,
            text="Cole o conteúdo ou cabeçalho do e-mail:",
            font=("Segoe UI", 9),
            fg=self.colors["text_muted"],
            bg=self.colors["card_bg"],
        )
        lbl.pack(anchor="w", pady=(0, 5))

        # Corrigido: Fonte alterada para número inteiro (10)
        self.email_text = tk.Text(
            self.email_tab,
            height=6,
            bg="#161d26",
            fg=self.colors["text_main"],
            insertbackground="white",
            relief="solid",
            bd=1,
            highlightbackground=self.colors["card_border"],
            font=("Segoe UI", 10),
        )
        self.email_text.pack(fill="x", pady=(0, 15))

        btn = tk.Button(
            self.email_tab,
            text="Analisar E-mail",
            bg=self.colors["accent_blue"],
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            activebackground="#1d4ed8",
            activeforeground="white",
            cursor="hand2",
            command=self.scan_email,
        )
        btn.pack(fill="x", ipady=5)

    def _build_web_tab(self):
        lbl = tk.Label(
            self.web_tab,
            text="Digite ou cole a URL do site:",
            font=("Segoe UI", 9),
            fg=self.colors["text_muted"],
            bg=self.colors["card_bg"],
        )
        lbl.pack(anchor="w", pady=(0, 5))

        self.url_entry = tk.Entry(
            self.web_tab,
            bg="#161d26",
            fg=self.colors["text_main"],
            insertbackground="white",
            relief="solid",
            bd=1,
            highlightbackground=self.colors["card_border"],
            font=("Segoe UI", 10),
        )
        self.url_entry.pack(fill="x", ipady=8, pady=(0, 15))

        btn = tk.Button(
            self.web_tab,
            text="Analisar Website",
            bg=self.colors["accent_blue"],
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            activebackground="#1d4ed8",
            activeforeground="white",
            cursor="hand2",
            command=self.scan_website,
        )
        btn.pack(fill="x", ipady=5)

    def scan_email(self):
        content = self.email_text.get("1.0", tk.END).strip().lower()

        if not content:
            messagebox.showwarning("Aviso", "Por favor, insira o texto do e-mail.")
            return

        keywords = [
            "urgente",
            "senha",
            "recadastrar",
            "suspensa",
            "bloqueada",
            "clique aqui",
            "ganhou",
            "banco",
            "verificação",
            "atualizar",
        ]
        found = [kw for kw in keywords if kw in content]

        if len(found) >= 2:
            self._update_result(
                title="⚠️ Alto Risco de Phishing Detectado",
                details=f"O e-mail contém termos comumente usados em ataques de engenharia social:\n• Gatilhos encontrados: {', '.join(found)}\n• Recomendação: Não clique em links e evite fornecer credenciais.",
                status_color=self.colors["danger"],
            )
        else:
            self._update_result(
                title="✅ Conteúdo Limpo",
                details="Nenhum padrão crítico de indução ao erro ou urgência artificial foi identificado no texto.",
                status_color=self.colors["safe"],
            )

    def scan_website(self):
        url = self.url_entry.get().strip().lower()

        if not url:
            messagebox.showwarning("Aviso", "Por favor, insira uma URL válida.")
            return

        suspicious_tlds = [".xyz", ".top", ".tk", ".site", ".click", ".online"]
        has_http = url.startswith("http://")
        has_suspicious_tld = any(
            url.endswith(tld) or (tld + "/") in url for tld in suspicious_tlds
        )
        has_ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)

        if has_http or has_suspicious_tld or has_ip:
            reasons = []
            if has_http:
                reasons.append("Uso de conexão não segura (HTTP)")
            if has_suspicious_tld:
                reasons.append(
                    "Uso de TLD/extensão de domínio com alto índice de spam"
                )
            if has_ip:
                reasons.append(
                    "Uso direto de endereço IP em vez de nome de domínio"
                )

            self._update_result(
                title="⚠️ Alerta de Segurança no Domínio",
                details="A URL analisada apresenta fatores de risco:\n• "
                + "\n• ".join(reasons),
                status_color=self.colors["warning"],
            )
        else:
            self._update_result(
                title="✅ Domínio Sem Alertas Imediatos",
                details="A URL utiliza protocolos padrões e não acionou filtros básicos de risco.",
                status_color=self.colors["safe"],
            )

    def _update_result(self, title, details, status_color):
        self.result_title.config(text=title, fg=status_color)
        self.result_details.config(text=details)


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingScannerApp(root)
    root.mainloop()
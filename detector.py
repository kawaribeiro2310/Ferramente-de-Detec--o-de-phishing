import re
from urllib.parse import urlparse

class PhishingDetector:
    """
    Ferramenta de detecção de phishing baseada em heurística de URLs.
    Analisa padrões estruturais comuns em links maliciosos.
    """
    def __init__(self):
        # Palavras comumente usadas em golpes
        self.suspicious_keywords = [
            'login', 'update', 'free', 'bonus', 'secure', 'account', 
            'banking', 'verify', 'wallet', 'password', 'credential'
        ]
        # Lista de encurtadores populares
        self.shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd', 't.co', 'cutt.ly']

    def analyze_url(self, url):
        score = 0
        reasons = []

        # Tenta extrair o domínio da URL
        try:
            domain = urlparse(url).netloc
            if not domain: # Caso a URL não tenha http:// ou https://
                domain = urlparse("http://" + url).netloc
        except Exception:
            return {"status": "Erro", "reasons": ["URL inválida."]}

        # 1. Checar uso de IP no lugar do domínio
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score += 3
            reasons.append("Uso de endereço IP direto no domínio.")

        # 2. Checar tamanho da URL (URLs muito longas escondem a fraude)
        if len(url) > 75:
            score += 1
            reasons.append("URL excessivamente longa.")

        # 3. Presença de '@' (navegadores ignoram tudo antes do @, técnica comum para esconder domínio real)
        if '@' in url:
            score += 2
            reasons.append("Uso do caractere '@' na URL.")

        # 4. Uso de encurtadores de link
        if any(shortener in domain for shortener in self.shorteners):
            score += 2
            reasons.append("Uso de encurtador de URL.")

        # 5. Palavras suspeitas na URL
        for word in self.suspicious_keywords:
            if word in url.lower():
                score += 1
                reasons.append(f"Palavra suspeita encontrada: '{word}'.")

        # 6. Múltiplos subdomínios (ex: login.banco.com.br.site-falso.com)
        if domain.count('.') > 3:
            score += 1
            reasons.append("Múltiplos subdomínios detectados (possível spoofing).")

        # 7. Uso de hífens no domínio (muito comum em phishing)
        if '-' in domain:
            score += 1
            reasons.append("Uso de hífen no domínio.")

        return self._format_result(url, score, reasons)

    def _format_result(self, url, score, reasons):
        if score >= 4:
            status = "🔴 ALTO RISCO (Provável Phishing)"
        elif score >= 2:
            status = "🟡 Risco Moderado (Suspeito)"
        else:
            status = "🟢 Seguro"

        return {
            "url": url,
            "score": score,
            "status": status,
            "reasons": reasons
        }

# ==========================================
# Exemplo de uso para demonstração
# ==========================================
if __name__ == "__main__":
    print("🔍 Phishing URL Detector\n" + "="*45)
    detector = PhishingDetector()

    # URLs para teste
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/banco/login.php",
        "https://bit.ly/3xyz_update_account",
        "https://secure-login.paypal.com.br.verify-account.net"
    ]

    for url in test_urls:
        resultado = detector.analyze_url(url)
        print(f"\nURL: {resultado['url']}")
        print(f"Status: {resultado['status']} (Pontuação de Risco: {resultado['score']})")
        if resultado['reasons']:
            print("Motivos:")
            for motivo in resultado['reasons']:
                print(f"  - {motivo}")
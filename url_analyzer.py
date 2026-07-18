import re
from urllib.parse import urlparse

class URLAnalyzer:
    def __init__(self, url: str):
        self.url = url
        # Extrai os componentes da URL (ex: dominio, protocolo)
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc

    def check_ip_in_domain(self) -> bool:
        """Verifica se o domínio é um endereço IP direto (ex: 192.168.1.1)"""
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        return bool(re.match(ip_pattern, self.domain))

    def count_suspicious_characters(self) -> int:
        """Conta caracteres muito comuns em URLs de phishing (@, -, .)"""
        # Phishing adora usar hífens para imitar marcas: suporte-netflix.com
        points = 0
        points += self.domain.count('-') * 20
        points += self.domain.count('@') * 50  # O arroba pode mascarar o destino real
        return points

    def check_typosquatting(self) -> bool:
        """Verifica se o link tenta imitar marcas famosas errando letras"""
        target_brands = ['google', 'facebook', 'netflix', 'nubank', 'instagram']
        domain_lower = self.domain.lower()
        
        for brand in target_brands:
            # Se a marca está contida no domínio, mas não é exatamente ela ou o subdomínio padrão
            if brand in domain_lower and domain_lower != f"{brand}.com" and not domain_lower.endswith(f".{brand}.com"):
                # Exemplo: g00gle.com ou seguranca-nubank.com
                return True
        return False

    def calculate_risk_score(self) -> dict:
        """Calcula o score final de risco da URL"""
        score = 0
        reasons = []

        if self.check_ip_in_domain():
            score += 40
            reasons.append("O link usa um endereço IP direto em vez de um nome de domínio.")

        char_points = self.count_suspicious_characters()
        if char_points > 0:
            score += char_points
            reasons.append("O domínio contém excesso de caracteres especiais (hífens ou arrobas).")

        if self.check_typosquatting():
            score += 40
            reasons.append("O link parece tentar imitar uma marca famosa (Typosquatting).")

        # Limita o score máximo em 100
        final_score = min(score, 100)
        
        return {
            "url": self.url,
            "risk_score": f"{final_score}%",
            "is_suspicious": final_score >= 40,
            "alerts": reasons if reasons else ["Nenhum padrão óbvio de phishing detectado."]
        }
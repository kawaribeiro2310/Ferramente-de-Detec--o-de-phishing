from src.url_analyzer import URLAnalyzer

def test_detector():
    print("--- Testando o Analisador de Phishing ---\n")
    
    # Exemplo de URL suspeita
    url_suspeita = "http://login-seguro-nubank.com/recadastro"
    analyzer = URLAnalyzer(url_suspeita)
    resultado = analyzer.calculate_risk_score()
    
    print(f"Analisando: {resultado['url']}")
    print(f"Score de Risco: {resultado['risk_score']}")
    print(f"É suspeito?: {resultado['is_suspicious']}")
    print("Alertas encontrados:")
    for alert in resultado['alerts']:
        print(f" - {alert}")

if __name__ == "__main__":
    test_detector()
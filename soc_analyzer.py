print("Mini SOC Analyzer iniciado")

eventos = [
    {"ip": "192.168.0.10", "evento": "login_sucesso"},
    {"ip": "192.168.0.11", "evento": "login_falha"},
    {"ip": "192.168.0.11", "evento": "login_falha"},
    {"ip": "192.168.0.11", "evento": "login_falha"},
    {"ip": "10.0.0.5", "evento": "scan_porta"},
    {"ip": "10.0.0.5", "evento": "scan_porta"},
    {"ip": "172.16.0.7", "evento": "login_sucesso"},
    {"ip": "8.8.8.8", "evento": "acesso_externo"},
]


def contar_eventos(lista_eventos):
    contagem = {}

    for evento in lista_eventos:
        tipo = evento["evento"]

        if tipo in contagem:
            contagem[tipo] += 1
        else:
            contagem[tipo] = 1

    return contagem


def identificar_bruteforce(lista_eventos):
    falhas = {}

    for evento in lista_eventos:
        if evento["evento"] == "login_falha":
            ip = evento["ip"]

            if ip in falhas:
                falhas[ip] += 1
            else:
                falhas[ip] = 1

    suspeitos = []

    for ip, quantidade in falhas.items():
        if quantidade >= 3:
            suspeitos.append(ip)

    return suspeitos


def identificar_scanners(lista_eventos):
    scans = {}

    for evento in lista_eventos:
        if evento["evento"] == "scan_porta":
            ip = evento["ip"]

            if ip in scans:
                scans[ip] += 1
            else:
                scans[ip] = 1

    suspeitos = []

    for ip, quantidade in scans.items():
        if quantidade >= 2:
            suspeitos.append(ip)

    return suspeitos


def listar_ips_unicos(lista_eventos):
    ips = set()

    for evento in lista_eventos:
        ips.add(evento["ip"])

    return list(ips)


def gerar_relatorio(lista_eventos):

    print("=== MINI SOC ANALYZER ===\n")

    print("Total de eventos analisados:", len(lista_eventos), "\n")

    print("Resumo por tipo:")

    contagem = contar_eventos(lista_eventos)

    for tipo, quantidade in contagem.items():
        print(f"{tipo}: {quantidade}")

    print("\nIPs únicos monitorados:")

    ips = listar_ips_unicos(lista_eventos)

    for ip in ips:
        print(ip)

    print("\nPossível brute force:")

    bruteforce = identificar_bruteforce(lista_eventos)

    for ip in bruteforce:
        print(ip)

    print("\nPossível scanner:")

    scanners = identificar_scanners(lista_eventos)

    for ip in scanners:
        print(ip)


if __name__ == "__main__":
    gerar_relatorio(eventos)

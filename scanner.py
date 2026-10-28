import socket
import urllib.request
import urllib.error
import sys

def check_security_headers(url):
    print(f"\n[+] Analizando cabeceras de seguridad para: {url}")
    try:
        # Asegurarnos de que la URL tiene esquema
        if not url.startswith("http"):
            url = "http://" + url
            
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = response.info()
            
            # Cabeceras críticas de seguridad que toda web robusta debería tener
            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            print("-" * 50)
            for header in security_headers:
                if header in headers:
                    print(f" [V] {header}: Presente ({headers[header]})")
                else:
                    print(f" [!] {header}: FALTA (Posible vulnerabilidad de configuración)")
            print("-" * 50)
            
    except urllib.error.URLError as e:
        print(f"[-] Error al conectar con la URL: {e.reason}")
    except Exception as e:
        print(f"[-] Error inesperado: {e}")

def scan_ports(target):
    print(f"\n[+] Escaneando puertos comunes en: {target}")
    # Puertos típicos: FTP (21), SSH (22), HTTP (80), HTTPS (443), Alt-HTTP (8080)
    common_ports = [21, 22, 80, 443, 8080]
    
    print("-" * 50)
    for port in common_ports:
        try:
            # Crear socket TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f" [OPEN] Puerto {port} está ABIENTO")
            else:
                print(f" [CLOSED] Puerto {port} cerrado")
            s.close()
        except socket.gaierror:
            print("[-] No se pudo resolver el host.")
            break
        except socket.error:
            print("[-] No se pudo conectar al servidor.")
            break
    print("-" * 50)

if __name__ == "__main__":
    print("=== AUTOMATIZADOR DE RECONOCIMIENTO & AUDITORÍA BÁSICA ===")
    target_input = input("Introduce el dominio o IP a auditar (ej: scanme.nmap.org): ").strip()
    
    if target_input:
        scan_ports(target_input)
        check_security_headers(target_input)
        print("\n[✔] Auditoría completada con éxito.\n")
    else:
        print("[!] Debes introducir un objetivo válido.")

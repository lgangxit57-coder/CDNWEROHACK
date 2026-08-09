# CDNWEROHACK

Tool avanzado en temas de cyberseguridad

# CDNHACK — CDN WERO · DevFuryWero

Auditor de cámaras IP + fuerza bruta de servicios para pruebas de penetración **autorizadas** (red propia o cliente con alcance firmado).

## Características

- Descubrimiento de red LAN (ARP/nmap)
- Detección de cámaras IP con marca y modelo
- Credenciales por defecto (HTTP Basic + RTSP)
- Check de CVEs (Hikvision, Dahua, Xiongmai, Reolink, D-Link, TVT)
- Fuerza bruta integrada: ftp, ssh, http-basic, http-form, rtsp (usa Hydra como fallback)
- DevFuryWero: módulo de hardening y recomendaciones de protección
- Reporte TXT con todos los hallazgos

## Instalación

```bash
sudo apt install -y hydra arp-scan nmap python3-paramiko
git clone git@github.com:lgangxit57-coder/CDNWEROHACK.git
cd CDNWEROHACK
chmod +x cdnhack.py
sudo ln -s $(pwd)/cdnhack.py /usr/local/bin/cdnhack

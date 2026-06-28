"""Шаблон локальной конфигурации srouter.
Скопируй в srouter_config.py и впиши свои значения:
    cp srouter_config.example.py srouter_config.py
"""

VPS_IP = "203.0.113.10"          # legacy fallback; узлы-ускорители теперь в nodes.json (см. nodes.example.json)
GATEWAY = "192.168.1.1"          # физический шлюз (Wi-Fi роутер) для split-route
VPN_SERVER = "198.51.100.20"     # адрес VPN-сервера, если используешь (ping/детект)
VPN_EXIT_IP = "198.51.100.20"    # IP, под которым виден выход через VPN

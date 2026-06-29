"""Шаблон локальной конфигурации srouter.
Скопируй в srouter_config.py и впиши свои значения:
    cp srouter_config.example.py srouter_config.py
"""

# legacy: dashboard runtime теперь берёт активный узел из srouter.local.json (#2);
# это поле осталось только для ручных smoke/диагностики и не загружается dashboard.py.
VPS_IP = "203.0.113.10"
GATEWAY = "192.168.1.1"          # физический шлюз (Wi-Fi роутер) для split-route
VPN_SERVER = "198.51.100.20"     # адрес VPN-сервера, если используешь (ping/детект)
VPN_EXIT_IP = "198.51.100.20"    # IP, под которым виден выход через VPN

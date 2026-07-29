#!/usr/bin/env python3
"""srouter acceptance stub-helper: минимальный listener, эмулирующий «сервис поднялся на порту».

install_lib.py::_restart_component (issue #115, PR #118) poll'ит РЕАЛЬНЫЙ порт через
sys_probe.port_open (TCP-connect, install_lib.py:791/811/56 sys_probe.py) после `brew services
start` — не только rc=0 от brew. Тупой brew-stub (path 3, docker/README.md) не поднимает никакого
процесса → порт никогда не «busy» → install падает `<name>_restart_failed`.

dnsmasq (PORTS["dnsmasq"]=("udp", 53)) всё равно проверяется TCP-connect'ом (port_open не различает
proto — install_lib.py:811 зовёт один и тот же port_checker для всех компонентов). На реальном
macOS это не баг: настоящий dnsmasq — DNS-резолвер, слушает ОБА транспорта на 53 (TCP нужен для
больших ответов/AXFR, стандартное поведение DNS) — поэтому TCP-connect реально успешен против
живого dnsmasq. Стаб обязан воспроизводить то же самое — слушать TCP ВСЕГДА (для port_open-проверки
из _restart_component), плюс UDP при proto=="udp" (символическая точность: dnsmasq — DNS, отвечает
и на UDP).

Usage: port_listener.py <tcp|udp> <port> <pidfile>
Демонизируется через `&` в brew.sh; pidfile используется stop-веткой для kill.
"""
import os
import select
import socket
import sys


def main():
    proto, port_s, pidfile = sys.argv[1], sys.argv[2], sys.argv[3]
    port = int(port_s)

    # bind/listen может упасть (порт занят / EACCES) — без явного лога caller (brew.sh) видит
    # только «pidfile не появился» (poll timeout), причина теряется (канон: шумный лог лучше
    # отсутствия лога). brew.sh нohup'ит stdout/stderr в /dev/null — печатаем и в stderr (на случай
    # запуска не через brew.sh), и best-effort в pidfile-соседний .err для post-mortem.
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sock.bind(("127.0.0.1", port))
        tcp_sock.listen(5)
        tcp_sock.setblocking(False)

        udp_sock = None
        if proto == "udp":
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp_sock.bind(("127.0.0.1", port))
            udp_sock.setblocking(False)
    except OSError as exc:
        msg = f"port_listener: bind {proto}/{port} failed: {exc}"
        print(msg, file=sys.stderr)
        with open(f"{pidfile}.err", "w", encoding="utf-8") as f:
            f.write(msg + "\n")
        sys.exit(1)

    readers = [tcp_sock] + ([udp_sock] if udp_sock else [])

    with open(pidfile, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    while True:
        ready, _, _ = select.select(readers, [], [])
        for sock in ready:
            if sock is tcp_sock:
                conn, _ = tcp_sock.accept()
                conn.close()
            elif udp_sock is not None and sock is udp_sock:
                udp_sock.recvfrom(65536)


if __name__ == "__main__":
    main()

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 0.5
MAX_THREADS = 200


def scan_port(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None


def scan_ports(ip, start=20, end=1024, progress_callback=None):
    open_ports = []
    total = end - start
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in range(start, end)}

        for future in as_completed(futures):
            result = future.result()
            completed += 1

            if result:
                open_ports.append(result)

            # update progress
            if progress_callback:
                progress_callback(completed, total)

    return open_ports

import random
import time

OUTPUT_FILE = "big_access.log"
LINES = 1_000_000

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

URLS = [
    "/",
    "/home",
    "/login",
    "/logout",
    "/profile",
    "/admin",
    "/api/users",
    "/api/items",
    "/api/orders",
    "/search",
    "/cart",
    "/checkout",
    "/products",
    "/products/1",
    "/products/2",
]

# Более реалистичное распределение статусов
STATUSES = (
    [200] * 60 +
    [201] * 8 +
    [204] * 5 +
    [301] * 5 +
    [302] * 5 +
    [400] * 5 +
    [401] * 4 +
    [403] * 4 +
    [404] * 5 +
    [429] * 2 +
    [500] * 4 +
    [502] * 2 +
    [503] * 1
)

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def random_size(status):
    if 200 <= status < 300:
        return random.randint(200, 5000)
    elif 300 <= status < 400:
        return random.randint(50, 800)
    else:
        return random.randint(0, 1500)

def main():
    now = int(time.time())
    start_time = now - 30 * 24 * 3600  # последние 30 дней

    with open(OUTPUT_FILE, "w") as f:
        for i in range(LINES):
            ts = random.randint(start_time, now)
            ip = random_ip()
            method = random.choice(METHODS)
            url = random.choice(URLS)
            status = random.choice(STATUSES)
            size = random_size(status)

            line = f"{ts} {ip} {method} {url} {status} {size}\n"
            f.write(line)

            if i % 100_000 == 0 and i > 0:
                print(f"Generated {i} lines...")

    print(f"\nDone! File '{OUTPUT_FILE}' with {LINES} lines created.")

if __name__ == "__main__":
    main()

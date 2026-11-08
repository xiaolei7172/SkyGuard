import time, subprocess
from core.local_proxy import LocalProxy, MODE_SMART
from core.geo import get_classifier

geo = get_classifier()
print("IP 库:", geo.source, "段数:", geo.range_count)
p = LocalProxy(port=17890, mode=MODE_SMART, geo=geo)
print("启动:", p.start())
time.sleep(0.3)

def curl(url):
    t0 = time.time()
    r = subprocess.run(["curl","-s","-o","/dev/null","-w","%{http_code}", "--max-time","12",
                        "-x","http://127.0.0.1:17890", url], capture_output=True, text=True, timeout=20)
    return f"{r.stdout.strip():>3}  {time.time()-t0:5.2f}s"

for url in ["https://www.baidu.com", "https://github.com", "https://www.36kr.com",
            "https://www.google.com", "https://www.qq.com"]:
    print(f"{url:32s} {curl(url)}")

time.sleep(0.4)
for r in p.stats.snapshot()["recent"]:
    print(f"  {r['host']:26s} {r['action']:7s} {r['rule']:12s} {r['node'] or '-':8s} {r['result']}")
print("geo verdict 缓存:", len(geo._verdict), " DNS 缓存:", len(geo._dns))
p.stop()

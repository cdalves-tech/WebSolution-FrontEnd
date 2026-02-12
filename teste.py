import re
import asyncio
import aiohttp
import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

MAX_PAGES = 100
TIMEOUT = 10
OUTPUT_FILE = "subdominios.txt"

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

saved_subs = set()
visited_urls = set()


# ----------------------------
# SALVAR SUBDOMÍNIOS
# ----------------------------
def save_subdomain(sub):
    if sub not in saved_subs:
        saved_subs.add(sub)
        with open(OUTPUT_FILE, "a") as f:
            f.write(sub + "\n")
        print(f"[+] Subdomínio: {sub}")


# ----------------------------
# EXTRAIR SUBDOMÍNIOS
# ----------------------------
def extract_subdomains(text, domain):
    pattern = rf"[a-zA-Z0-9_\-\.]+\.{re.escape(domain)}"
    return set(re.findall(pattern, text))


# ----------------------------
# GERAR DORKS
# ----------------------------
def generate_dorks(domain):
    return [
        f"site:{domain}",
        f"site:*.{domain}",
        f"inurl:{domain}",
        f"\"{domain}\"",
        f"site:{domain} ext:js",
        f"site:{domain} ext:json",
        f"site:{domain} ext:env",
    ]


# ----------------------------
# BUSCA NOS SEARCH ENGINES
# ----------------------------
def search_engine_links(domain):
    links = set()
    dorks = generate_dorks(domain)

    for dork in dorks:
        urls = [
            f"https://html.duckduckgo.com/html/?q={dork}",
            f"https://www.bing.com/search?q={dork}"
        ]

        for url in urls:
            try:
                r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
                soup = BeautifulSoup(r.text, "html.parser")

                for a in soup.find_all("a", href=True):
                    href = a["href"]

                    # pegar apenas links reais
                    if href.startswith("http"):
                        parsed = urlparse(href)

                        # ignorar links de buscadores
                        if any(x in parsed.netloc for x in [
                            "bing.com",
                            "duckduckgo.com",
                            "microsoft.com"
                        ]):
                            continue

                        links.add(href)

            except:
                pass

    return links



# ----------------------------
# CRAWLER
# ----------------------------
async def fetch(session, url):
    try:
        async with session.get(url, timeout=TIMEOUT) as resp:
            return await resp.text()
    except:
        return ""


async def crawl(urls, domain):
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:

        queue = list(urls)

        while queue and len(visited_urls) < MAX_PAGES:
            url = queue.pop(0)

            if url in visited_urls:
                continue

            visited_urls.add(url)
            print(f"[*] Crawling: {url}")

            html = await fetch(session, url)

            if not html:
                continue

            # extrair subdomínios
            subs = extract_subdomains(html, domain)
            for sub in subs:
                save_subdomain(sub)

            # extrair links internos
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])

                if domain in link and link not in visited_urls:
                    queue.append(link)


# ----------------------------
# FUNÇÃO PRINCIPAL
# ----------------------------
def run(domain):
    print(f"[+] Iniciando recon em: {domain}")

    open(OUTPUT_FILE, "w").close()

    print("[+] Buscando links com dorks...")
    links = search_engine_links(domain)

    print(f"[+] {len(links)} links encontrados")

    asyncio.run(crawl(links, domain))

    print(f"[+] Total de subdomínios: {len(saved_subs)}")
    print(f"[+] Salvos em: {OUTPUT_FILE}")


# ----------------------------
# CLI
# ----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdorker")
    parser.add_argument("-d", "--domain", help="Domínio alvo")

    args = parser.parse_args()

    if args.domain:
        run(args.domain)
    else:
        alvo = input("Digite o domínio: ").strip()
        run(alvo)

import requests
from bs4 import BeautifulSoup
from urllib.parse import quote

def _getCVEData(url):
    pass

def search(query: str):
    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + quote(query)
    page = requests.get(url)

    soup = BeautifulSoup(page.text, "html.parser")

    table = soup.find_all("table")[2]

    for child in table.children:
        for td in child:
            if hasattr(td, "a"):
                if td.a != None:
                    start = str(td.a).index("\"") + 1
                    end = str(td.a).rindex("\"")
                    ext = str(td.a)[start:end]
                    url = "https://cve.mitre.org" + ext
                    data = _getCVEData(url)
                    # TODO: Scrape data out of CVE URLs

# search("OpenSSH 6.1.1")

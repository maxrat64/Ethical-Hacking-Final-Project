import requests
from bs4 import BeautifulSoup
from urllib.parse import quote

def _getNVDData(url: str) -> dict:
    # TODO: Scrape data from NVD (url obtained in CVD webpage)
    return dict()

def _getCVEData(url: str) -> dict:
    page = requests.get(url)
    soup = BeautifulSoup(page.text, "html.parser")
    table = soup.find_all("table")[2].contents

    DESC_IDX = 7
    REF_IDX = 13
    CNA_IDX = 17
    DATE_IDX = 21

    description = table[DESC_IDX].contents[1].text.strip()

    references = []
    tags_references = table[REF_IDX].contents[1].find_all("a")
    for tag in tags_references:
        references.append(tag.text)

    cna_assigned = table[CNA_IDX].contents[1].text
    date_assigned = table[DATE_IDX].contents[1].text

    return {"description" : description, "references" : references, \
            "cna": cna_assigned, "date": date_assigned}

def _getData(url: str) -> dict:
    result = _getCVEData(url)
    result.update(_getNVDData(url))
    return result

def search(query: str) -> list[dict]:
    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + quote(query)
    page = requests.get(url)
    soup = BeautifulSoup(page.text, "html.parser")
    table = soup.find_all("table")[2]
    result = []

    for child in table.children:
        for td in child:
            if hasattr(td, "a"):
                if td.a != None:
                    start = str(td.a).index("\"") + 1
                    end = str(td.a).rindex("\"")
                    ext = str(td.a)[start:end]
                    url = "https://cve.mitre.org" + ext
                    data = _getCVEData(url)
                    result.append(data)

    return result

print(_getCVEData("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29262"))

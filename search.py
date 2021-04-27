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

    NAME_IDX = 3
    DESC_IDX = 7
    REF_IDX = 13
    CNA_IDX = 17
    DATE_IDX = 21

    name = table[NAME_IDX].find("h2").text

    # print(table[NAME_IDX])

    description = table[DESC_IDX].contents[1].text.strip()

    references = []
    tags_references = table[REF_IDX].contents[1].find_all("a")
    for tag in tags_references:
        references.append(tag.text)

    cna_assigned = table[CNA_IDX].contents[1].text
    date_assigned = table[DATE_IDX].contents[1].text

    result = {"name": name, "description" : description, \
            "references" : references, "cna": cna_assigned, \
            "date": date_assigned}
    result.update(_getNVDData(""))
    return result

def search(query: str) -> list[dict]:
    return [cve for cve in searchIter(query)]

def searchIter(query: str):
    """
    Use this method to return an iterator for results. Useful for cases with a very
    large amount of results that would take too long to load before displaying
    data. This can be useful for implementing pagination where you want to load x
    results at a time.

    Example - Printing the first 20 results:
        iter = searchIter("test")
        for _ in range(20):
            print(next(iter))
    """

    url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + quote(query)
    page = requests.get(url)
    soup = BeautifulSoup(page.text, "html.parser")
    table = soup.find_all("table")[2]

    for child in table.children:
        for td in child:
            if hasattr(td, "a"):
                if td.a != None:
                    ext = td.a.get("href")
                    url = "https://cve.mitre.org" + ext
                    data = _getCVEData(url)
                    yield data

# print(_getCVEData("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29262"))

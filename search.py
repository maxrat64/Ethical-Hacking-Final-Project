import os
import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import quote

# TODO: After finishing most of the web scraper, I discovered an API from NIST
# that might be better than web scraping. Maybe I should implement search
# using this instead?
# https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf

_databaseUpdated = False

def updateDatabase():
    """
    Updates the database from the git repo. This should be called when the
    program is initiallized!
    """
    global _databaseUpdated
    if (os.path.isdir("./cvelist")):
        os.system("cd ./cvelist; git pull")
    else:
        os.system("git clone https://github.com/CVEProject/cvelist.git")

    _databaseUpdated = True

def _getNVDData(name: str) -> dict:
    # TODO: Scrape data from NVD (url obtained in CVD webpage)
    return dict()

def _getCVEData(name: str) -> dict:
    assert _databaseUpdated == True, "Need to call updateDatabase() first!"

    _, year, idNum = name.split("-")
    idPath = idNum[:-3] + "xxx"
    path = f'./cvelist/{year}/{idPath}/{name}.json'

    result = {"name": name, "year": int(year), "numerical_id": int(idNum)}
    with open(path) as f:
        data = json.load(f)
        description = data["description"]["description_data"][0]["value"]
        references = []
        for entry in data["references"]["reference_data"]:
            references.append(entry["url"])
        result.update({"description": description, "references": references})
    return result

def search(query: str) -> list[dict]:
    return [cve for cve in searchIter(query)]

def searchIter(query: str):
    """
    Use this method to get an iterator/generator for results.
    This can be useful for implementing pagination where you want to load x
    results at a time.
    This is also useful for queries with a very large amount of results.

    Example - Printing the next 20 results of searching "apache":
        iter = searchIter("apache")
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
                    name = td.a.text
                    data = _getCVEData(name)
                    yield data

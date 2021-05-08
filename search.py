#!/usr/bin/env python3

from bs4 import BeautifulSoup
from statistics import mean
import requests

url="https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cpe_version="

def getCVEData(cpe_info):

    # Create request url
    request_url = url + cpe_info

    # Get response from server
    page = requests.get(request_url)

    # Make bs from the response
    soup = BeautifulSoup(page.text, "html.parser")

    # Get number of vulnerabilities
    n_vulns_att = soup.find(attrs={"data-testid":"vuln-matching-records-count"})
    n_vulns_txt = n_vulns_att.text.replace(",", "")
    n_vulns = int(n_vulns_txt)

    # Get CVSS severity scores
    scores = []
    for i in range(20):
        val = "vuln-cvss2-link-" + str(i)
        cvss_score = soup.find(attrs={"data-testid": val})
        if cvss_score is not None:
            raw_score = cvss_score.text.split(" ")[0]
            scores.append(float(raw_score))
    
    return (request_url, n_vulns, max(scores), mean(scores))
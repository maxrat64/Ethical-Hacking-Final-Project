import requests
import json

def search(cpe_uri: str, num_results=None, start_index=0) -> list[dict]:
    """
    Takes in a CPE URI to search for matching vulnerabilities. Returns a list
    of dictionaries pertaining to CVEs.

    Includes some optional parameters for convienience:
        num_results = the number of results returned.
        start_index = the result to start pulling entries from.
    If neither are specified, returns all results possible.

    Each dictionary object contains string keys. These include name, description,
    references, and impact.
        dict["id"] = id/name of CVE
        dict["description"] = description of CVE
        dict["references"] = a list of URLs as reference
        dict["impact"] = a dict containing data pertaining to severity ratings,
                         vector strings, etc. Details on the dict can be found
                         on page 20-21 of the NVD API documentation:
                         https://nvd.nist.gov/vuln/data-feeds
                         NOTE: this is not always availiable,
                         and if not found will contain None.
    """
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/1.0?addons=dictionaryCpes?cpeMatchString=" + cpe_uri
    endpoint += "?startIndex=" + str(start_index)
    if num_results != None:
        endpoint += "?resultsPerPage=" + str(num_results)

    rq = requests.get(endpoint)
    response = json.loads(rq.text)

    cve_items = response["result"]["CVE_Items"]

    result = []
    for item in cve_items:
        cve = item["cve"]
        entry = dict()
        entry["id"] = cve["CVE_data_meta"]["ID"]
        entry["description"] = cve["description"]["description_data"][0]["value"]
        entry["references"] = [e["url"] for e in cve["references"]["reference_data"]]
        try:
            entry["impact"] = item["impact"]
        except KeyError:
            entry["impact"] = None
        result.append(entry)

    return result

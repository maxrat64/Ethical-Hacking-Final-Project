import os
import json

# TODO: Test file enumeration on slower machine to see if performance is good
# enough.

# Updates the database from the git repo. Should be called once at start of
# program.
def updateDatabase():
    if (os.path.isdir("./cvelist")):
        os.system("cd ./cvelist; git pull")
    else:
        os.system("git clone https://github.com/CVEProject/cvelist.git")

# Executes a search from the database given a query. The output is an
# array of JSON objects as python dicts.
def search(query: str) -> list[dict]:
    if (os.path.isdir("./cvelist")):
        raise FileNotFoundError("Database not found! Call updateDatabase() first!")

    result = []
    for root, _, files in os.walk("./cvelist"):
        for name in files:
            path = os.path.join(root, name)
            if path[-5:] == ".json":
                with open(path) as f:
                    json.load(f)
                    # TODO: Create some kind of search metric to find matches
    return result

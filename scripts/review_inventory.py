"""Read every tracked file, inventory hashes and security-sensitive source sites. Never scans runtime secrets."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess

PATTERNS=["TODO","FIXME","pass","placeholder","mock","fake","shell=True","eval(","exec(","pickle",
          "joblib","subprocess","os.system","tempfile","Path(","open(","UploadFile","innerHTML"]


def main():
    files=subprocess.check_output(["git","ls-files"],text=True).splitlines()
    inventory=[]
    sites: dict[str, list[dict[str, str | int]]] = {pattern: [] for pattern in PATTERNS}
    for filename in files:
        path=Path(filename)
        data=path.read_bytes()
        entry={"path":filename,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
        inventory.append(entry)
        if path.suffix in (".pcap",".pcapng",".png"):
            continue
        content=data.decode("utf-8")
        if path.suffix==".py":
            ast.parse(content,filename=filename)
        for number,line in enumerate(content.splitlines(),1):
            for pattern in PATTERNS:
                if pattern in line:
                    sites[pattern].append({"path":filename,"line":number})
    destination=Path("runtime/final-review-inventory.json")
    destination.write_text(json.dumps({"files":inventory,"sites":sites},indent=2)+"\n")
    print(json.dumps({"tracked_files":len(files),"pattern_matches":{k:len(v) for k,v in sites.items()}},indent=2))


if __name__=="__main__":
    main()

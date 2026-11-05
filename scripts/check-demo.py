import json
import sys

good, bad = [json.load(open(path)) for path in sys.argv[1:]]
assert good["status"] == "ready", good["findings"]
assert good["isolation"]["verified"]
assert len(good["scenarios"]) == 4 and all(s["passed"] for s in good["scenarios"])
assert bad["status"] == "not_ready"
assert any(not s["passed"] for s in bad["scenarios"])
assert any(s["name"] == "inference" and s["state"] != "running" for s in bad["services"])
assert any(o["external"] for o in bad["observations"]), "remote model attempt was not observed"
print("Confirmed: packaged inference, PostgreSQL, Redis, and recovery pass; remote model fails offline.")

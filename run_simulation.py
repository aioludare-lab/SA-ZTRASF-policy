#!/usr/bin/env python3
"""SA-ZTRASF synthetic policy comparison. Standard library only.
Inputs are stipulated flags; this does NOT test independent attack detection.
"""
import csv, json
from pathlib import Path
OUT = Path(__file__).resolve().parent
N_PER_SCENARIO = 500
scenarios = [
    ("Legitimate authorised commands", "legitimate", (1,1,1,1)),
    ("Credential compromise", "adversarial", (0,1,1,1)),
    ("Authentication-token replay", "adversarial", (1,0,1,1)),
    ("Session hijacking", "adversarial", (1,0,1,1)),
    ("Privilege misuse", "adversarial", (1,1,0,1)),
    ("Unsafe supervisory command", "adversarial", (1,1,1,0)),
]
def conventional(I,S,P,O): return I
def simplified_zero_trust(I,S,P,O): return I & S & P
def sa_ztrasf(I,S,P,O): return I & S & P & O
policies = [
    ("Conventional authenticated access", conventional),
    ("Simplified Zero Trust", simplified_zero_trust),
    ("SA-ZTRASF", sa_ztrasf),
]
def save_csv(filename, rows, columns):
    with (OUT / filename).open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=columns); w.writeheader(); w.writerows(rows)

requests=[]
counts={}
for name, label, bits in scenarios:
    for i in range(N_PER_SCENARIO):
        request_id=f"{scenarios.index((name,label,bits))+1:02d}-{i+1:04d}"
        for policy_name, policy in policies:
            decision = "permit" if policy(*bits) else "deny"
            requests.append(dict(request_id=request_id,scenario=name,request_class=label,
                                 I=bits[0],S=bits[1],P=bits[2],O=bits[3],
                                 configuration=policy_name,decision=decision))
            key=(name,policy_name)
            counts[key]=counts.get(key,0)+int(decision=="deny")
save_csv("request_decisions.csv",requests,
         ["request_id","scenario","request_class","I","S","P","O","configuration","decision"])
scenario_rows=[]
for name,label,bits in scenarios:
    row={"scenario":name,"request_class":label,"requests":N_PER_SCENARIO}
    for policy_name,_ in policies: row[policy_name+"_denied"]=counts[(name,policy_name)]
    scenario_rows.append(row)
save_csv("scenario_summary.csv",scenario_rows,
         ["scenario","request_class","requests"]+[n+"_denied" for n,_ in policies])
summary=[]
for policy_name,_ in policies:
    denied=sum(counts[(name,policy_name)] for name,label,_ in scenarios if label=="adversarial")
    permitted_legit=N_PER_SCENARIO-counts[(scenarios[0][0],policy_name)]
    summary.append(dict(configuration=policy_name,adversarial_requests=2500,
                        adversarial_denied=denied,adversarial_rejection_pct=100*denied/2500,
                        legitimate_requests=500,legitimate_permitted=permitted_legit,
                        legitimate_permission_pct=100*permitted_legit/500))
save_csv("aggregate_summary.csv",summary,list(summary[0]))
execution={"scenarios":len(scenarios),"requests_per_scenario":N_PER_SCENARIO,
           "unique_synthetic_requests":len(scenarios)*N_PER_SCENARIO,
           "policy_configurations":len(policies),"policy_evaluations":len(requests),
           "synthetic_condition_assignment":"Fixed binary flags assigned by scenario; no independent detectors",
           "statistical_independence":"500 repeated identical-in-condition requests per scenario; no independent trials"}
(OUT/"simulation_metadata.json").write_text(json.dumps(execution,indent=2),encoding="utf-8")
assert len(requests)==9000
assert [r["adversarial_rejection_pct"] for r in summary]==[20,80,100]
print("Synthetic decisions:",len(requests),"; adversarial rejection: 20%, 80%, 100%")

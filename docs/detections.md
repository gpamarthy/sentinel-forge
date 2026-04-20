# Detection Plan

## Detection quality standard

Each detection should define:

- purpose
- required data sources
- trigger logic
- evidence fields
- false-positive notes
- analyst next steps

## Phase 1 detections

1. Root account usage
2. Console login without MFA
3. New geography or ASN for access key usage
4. Suspicious privileged `AssumeRole`
5. IAM privilege increase
6. CloudTrail tampering
7. GuardDuty plus CloudTrail corroboration
8. Public exposure of sensitive ports
9. Secrets access spike
10. Denied API burst followed by success
11. Suspicious Lambda change on privileged path
12. Dormant principal becomes active

## Rule authoring notes

- rules should be explainable from the event data alone
- correlation logic should stay narrow in the MVP
- avoid detections that only make sense in contrived lab conditions

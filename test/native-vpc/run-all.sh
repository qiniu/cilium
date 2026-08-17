#!/usr/bin/env bash
# Runs the whole suite from a clean slate and reports a single verdict.
set -uo pipefail
cd "$(dirname "$0")"

rc=0
# Order matters: fixtures, state, policies, behaviour, observability, datapath
# and tooling, service plane, and finally lifecycle (which restarts the agent
# and deletes a pod, so it must run last).
for step in 00-setup.sh 10-verify-vni.sh 20-policies.sh 30-connectivity.sh \
            35-policymap.sh 40-observability.sh 45-hubble-vni.sh 50-datapath.sh \
            60-service.sh 70-lifecycle.sh 80-logs.sh; do
  echo
  echo "################ ${step} ################"
  bash "./${step}" || rc=1
done

echo
echo "################ verdict ################"
if [[ $rc -eq 0 ]]; then
  echo "native-vpc three-VPC overlap suite: PASSED"
else
  echo "native-vpc three-VPC overlap suite: FAILED"
fi
echo "(run ./90-cleanup.sh to remove the fixtures)"
exit $rc

#!/bin/sh
# Download public sample logs into ./samples for trying petrify on logs it
# did not write itself. The directory is git-ignored: the samples belong to
# their publishers and are not part of this repository.
#
# Needs git, curl and the GitHub CLI (gh). Run from the repository root:
#
#     scripts/fetch_samples.sh
#     petrify show samples/invictus-aws/CloudTrail
set -eu

mkdir -p samples
cd samples

# CloudTrail delivery files from a real account during an attack simulation
# (Invictus IR, MIT licence).
if [ ! -d invictus-aws ]; then
  git clone --quiet --depth 1 https://github.com/invictus-ir/aws_dataset.git invictus-aws
  rm -rf invictus-aws/.git
fi

# Test inputs of Elastic's integrations (Elastic licence: use, do not
# redistribute). One directory per log format.
elastic() { # elastic <directory> <package path>
  [ -d "$1" ] && return
  mkdir -p "$1"
  path="packages/$2/_dev/test/pipeline"
  gh api "repos/elastic/integrations/contents/$path" \
      --jq '.[] | select(.type == "file") | .name | select(test("expected|config|\\.yml$") | not)' |
    while read -r name; do
      gh api "repos/elastic/integrations/contents/$path/$name" \
        -H "Accept: application/vnd.github.raw" > "$1/$name"
    done
}
elastic elastic-cloudtrail aws/data_stream/cloudtrail
elastic elastic-awsflow aws/data_stream/vpcflow
elastic elastic-azure-activity azure/data_stream/activitylogs
elastic elastic-azure-vnet azure_network_watcher_vnet/data_stream/log
elastic elastic-azure-nsg azure_network_watcher_nsg/data_stream/log
elastic elastic-gcp-audit gcp/data_stream/audit
elastic elastic-gcp-flow gcp/data_stream/vpcflow

# Attack datasets from Splunk (Apache-2.0), stored in Git LFS.
mkdir -p splunk
for file in \
    T1078.004/azure_automation_runbook/azure-activity.log \
    T1530/aws_exfil_high_no_getobject/cloudtrail.json \
    T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.json \
    T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.json; do
  out="splunk/$(echo "$file" | tr / _)"
  [ -f "$out" ] || curl -sSfL -o "$out" \
    "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/$file"
done

du -sh . | cut -f1

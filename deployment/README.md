# Single Windows 11 VM: deployment readiness

[Portfolio](../README.md) · [Specification](windows11-spec.json) · [Offline preflight](preflight.py)

This package contains the original VM specification and an offline preflight. The November 13, 2026 UTC inventory found one running Windows VM with the expected size, Standard SSD, assigned subnet and no public IP or NIC NSG. Run Command works; the operator confirmed Bastion desktop access. Preserve this VM. The preflight performs no deployment.

The deployed image configuration uses `version: latest`, with Azure reporting `exactVersion: 26200.9974.261109`. Its resolved version matches the proposal, but the creation input was not pinned. Record that provenance difference; do not change or recreate the VM to conceal it. Trusted Launch, Secure Boot and vTPM are observed enabled. Disk capacity was absent from the VM response. The proposed 128 GiB size still needs verification. Shared subnet NSG inspection was denied by RBAC and was not bypassed. Later authorized baseline and follow-up scans demonstrated scanner connectivity with the approved temporary Windows prerequisites; this does not establish visibility into the shared NSG rules. See the [assessment record](../docs/windows-stig-validation.md).

## Proposed configuration

The machine-readable specification is [windows11-spec.json](windows11-spec.json). It intentionally contains no subscription, tenant, student-group or shared-network identifiers. Resolve those from the operator's private assignment record.

| Component | Proposal |
|---|---|
| Image | Windows 11 Pro, `MicrosoftWindowsDesktop:windows-11:win11-25h2-pro:26200.9974.261109`; pinned version from the prior bounded preflight, availability must be rechecked. |
| Compute | `Standard_D2als_v6`, 2 vCPUs, East US 2, no availability zone. Do not substitute another size or select a restricted zone silently. |
| OS disk | 128 GiB, `StandardSSD_LRS`; confirm image minimum size and applicable policy. No data disks. |
| Security | Proposed Trusted Launch, Secure Boot and vTPM; verify image/size support and policy before creation. |
| Network | One NIC in the assigned student group, attached to the existing approved subnet in its hosting group. No public IP and no new VNet/subnet. |
| NSG | Preserve the shared subnet NSG; no extra NIC NSG in this proposal. Management and authenticated scanning were observed working, but shared-rule inspection remains unavailable. Revalidate authorization and the required path before future operations; never modify the shared NSG. |
| Management | Bastion desktop access is operator-confirmed and Run Command execution observed. A peering alone still does not establish scanner or management reachability. |
| Lifecycle | Exactly one VM, preserved across activities. No automatic recreate, delete, reset, replacement or second recovery VM. |

Windows client licensing entitlement must be confirmed for this use; image visibility is insufficient. The correct entitlement and any `Windows_Client` licensing declaration must be established with the range administrator before constructing a deployment. Do not silently change to Enterprise or multi-session. [Microsoft Windows client images](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/client-images), [Windows 11 hosting guidance](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/windows-desktop-multitenant-hosting-deployment).

The Windows 11 image is deliberately pinned to an exact Marketplace version. Before any future deployment, revalidate that version's availability in the assigned subscription/region and the applicable licensing, policy, architecture, VM-size, disk and security-feature constraints. Prior availability is not a guarantee of future availability. Updating the pin requires deliberate reconciliation of [windows11-spec.json](windows11-spec.json), the associated checks in [preflight.py](preflight.py), and their regression tests, followed by review. Stop if the image is unavailable or incompatible. Any replacement needs a deliberate specification and preflight update.

## Reproducible read-only preflight procedure

Use the creation preflight only for a separately approved future deployment. The current VM is already present. Use the existing isolated Azure configuration explicitly on every CLI invocation. Set `range_config`, `range_subscription`, `student_group`, `network_group`, `range_vnet` and `range_subnet` privately from the established assignment. Do not call `az account set`, inspect token files or install extensions.

The following built-in read-only commands limit output and scope. Check command success before transcribing an observation; an error leaves the value unknown. Stop on access denial and request the relevant administrator's confirmation. Do not inspect another group's VMs or traverse peering targets.

```bash
AZURE_CONFIG_DIR="$range_config" az account show --subscription "$range_subscription" \
  --query '{name:name,state:state}' --output json
AZURE_CONFIG_DIR="$range_config" az group show --subscription "$range_subscription" \
  --resource-group "$student_group" --query '{name:name,location:location,state:properties.provisioningState}' --output json
AZURE_CONFIG_DIR="$range_config" az vm list --subscription "$range_subscription" \
  --resource-group "$student_group" --query 'length(@)' --output json
AZURE_CONFIG_DIR="$range_config" az network vnet subnet show --subscription "$range_subscription" \
  --resource-group "$network_group" --vnet-name "$range_vnet" --name "$range_subnet" \
  --query '{state:provisioningState,delegations:delegations[].serviceName}' --output json
AZURE_CONFIG_DIR="$range_config" az vm image show --subscription "$range_subscription" \
  --location eastus2 --urn 'MicrosoftWindowsDesktop:windows-11:win11-25h2-pro:26200.9974.261109' \
  --query '{version:name,architecture:architecture,generation:hyperVGeneration,diskGiB:osDiskImage.sizeInGb,features:features}' --output json
AZURE_CONFIG_DIR="$range_config" az vm list-skus --subscription "$range_subscription" \
  --location eastus2 --resource-type virtualMachines --size Standard_D2als_v6 --all \
  --query "[?name=='Standard_D2als_v6'].{name:name,restrictions:restrictions,capabilities:capabilities}" --output json
AZURE_CONFIG_DIR="$range_config" az vm list-usage --subscription "$range_subscription" --location eastus2 \
  --query "[?name.value=='cores' || name.value=='standardDalv6Family'].{name:name.value,current:currentValue,limit:limit}" --output json
```

Privately confirm the subscription ID against the assignment; a display-name match alone is insufficient. Before use, verify these command arguments against the installed CLI help. Resolve missing image minimum-disk metadata through authoritative image information; do not replace an unknown value with zero.

At the assigned group and exact subnet scopes, confirm the effective permissions needed for VM, managed-disk, NIC and deployment writes and `Microsoft.Network/virtualNetworks/subnets/join/action`. A role name or successful read does not prove these actions are permitted. Consider inherited denies, role conditions, locks, provider registration, regional quota and applicable policy. Only inspect these permitted scopes; ask the administrator to resolve any missing visibility. Subnet-join permission was already established in the previous investigation; recheck only if access or assignments change.

Preserve the now-working Bastion and Run Command paths and record their private recovery procedures. The historical limited Bastion inventory did not locate a host; the subsequent successful desktop connection supersedes the connectivity uncertainty without authorizing inspection of its hosting subscription. Do not inspect another subscription or peer VNet without authorization. Public RDP is not a fallback.

Resolve conflicting shutdown schedules/timezones and the inactivity-purge policy with the administrator, including what activity resets the timer and how approved evidence and same VM identity survive interruptions. Portal viewing must not be assumed to prevent purge.

## Offline gate

```bash
python3 -B deployment/preflight.py
python3 -B deployment/preflight.py --template
python3 -B deployment/preflight.py --observations /approved/private/preflight.json
```

No-argument execution exits 1 with a non-deploying blocker. `--template` prints the complete observation schema, with unknown fields left null. Populate it privately from scoped observations and explicit decisions. Do not put populated scope values in Git.

The tool requires matching expected/observed assignment fields, a capture no more than 30 minutes old, exact proposed image/size/region, sufficient two-core family and regional quota, supported disk size/Trusted Launch, successful undelegated subnet with confirmed capacity, permissions and explicit licensing, policy, NSG, management and lifecycle decisions. Capacity confirmation must come from an authorized source; do not enumerate shared subnet occupants or address ranges to obtain it. Unknown, failed or stale checks block readiness. The 30-minute freshness limit is a local check.

`management_prerequisites_confirmed` means that the approved service, permissions and planned network path have been confirmed before creation. Test the VM connection after authorized creation and before any scan or remediation.

For no existing VM, leave `expected_vm_fingerprint` null and `existing_vms` empty. Immediately after separately authorized creation, record a private SHA-256 fingerprint of the exact VM resource ID **and Azure VM ID**, using an unambiguous canonical representation, and preserve the inputs privately. For subsequent checks, supply the same expected fingerprint and the actual VM's `identity_fingerprint`/`conforms_to_spec`. An existing VM always changes the action to preserve it; unknown identity or more than one VM blocks progress. A missing previously preserved VM requires a recovery decision and cannot become a new-create proposal.

Output always has `deploy: false`, even when `ready_for_deployment_review` is true. Exit 0 means the supplied observations passed. Provisioning still needs approval. Exit 1 indicates blockers and exit 2 invalid input. Scanner authorization/connectivity are separate baseline dependencies. The tool does not authenticate observations, verify private evidence, eliminate concurrent-creation races or establish Azure capacity. Recheck VM count and identity immediately before any approved create operation and coordinate with other operators. Never implement duplicate prevention by deleting an existing VM.

After approval and actual creation, verify the same VM identity, image, size, disk, no public IP, effective NSGs and authorized management path. Preserve credentials and resource identifiers privately. Proceed to the [Tenable workflow](../stig-remediations/evidence-workflow.md) only with scan authorization and a verified assigned scanner path.

export const PILOT = Object.freeze({
  provider: 'Nebius', instance: null, os: 'Ubuntu 24.04',
  target_configuration: '/etc/aukora-prime/pilot-target.json',
  target_status: 'PROTECTED_OPERATOR_CONFIGURATION_REQUIRED',
  cpu: 2, memory_gib: 8, disk_gib: 40, new_cpu_disk_ip_usd_day_cap: '2.00',
  paid_inference: false, gpu: false, deployed: false,
  invoice_reconciliation: 'PENDING', hard_provider_cost_stop: 'NOT_IMPLEMENTED',
  permissions_needed: [
    'Existing independently verified SSH host identity; no host-key bypass',
    'Install exact pinned runtime/build packages after license/hash review',
    'Create named runtime/broker UIDs and approved directories with fixed ownership',
    'Install/enable resource-bounded systemd service and separate broker IPC/security controls',
    'Transfer/start exact owner-approved artifact; localhost binding only',
    'Approve PostgreSQL storage/runtime configuration and retention/recovery reconciliation',
    'Approve provider stop-watchdog access using existing credentials if available',
    'Any additional network access, credentials, backup storage or inference spend separately'
  ]
})

/** Template rendering only. No SSH, sudo, package manager, service activation or keys. */
export function unitTemplate() {
  return `[Unit]
Description=AUKORA Prime pilot
After=network.target

[Service]
Type=simple
User=aukora-prime
Group=aukora-prime
WorkingDirectory=/opt/aukora-prime/current
ExecStart=/opt/aukora-prime/current/prime boot
Environment=NODE_OPTIONS=--max-old-space-size=1536
Environment=AUKORA_PRIME_PAID_INFERENCE=disabled
Environment=AUKORA_PRIME_GPU=disabled
Restart=no
KillMode=control-group
TimeoutStopSec=15
CPUQuota=150%
MemoryMax=5G
TasksMax=128
LimitNOFILE=4096
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/aukora-prime/runtime
# Executor/broker/database UIDs, socket ACLs and mounts require explicit approved setup.
# Tokens, tool steps, worker leases and billed cost need separate enforced admission/watchdog.

[Install]
WantedBy=multi-user.target
`
}

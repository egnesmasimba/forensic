"""Where each containment action is actually enforced.

Feature 79 lists a dozen "automatic blocking" controls, but they are not
equivalent, and collapsing them into one checkbox is how a product ends up
promising a block it cannot deliver. The agent can only act inside its own
process and the machine it runs on. Refusing a clipboard copy is something the
agent can do; refusing an email that has already left the building is not.

Each entry records where enforcement genuinely lives, whether the agent can
perform it, whether the agent can merely observe it, and whether it may ever be
dispatched without a human present. The UI reads this to avoid offering an
affordance that does nothing.
"""

# Enforcement locations.
AGENT = "agent"
OPERATING_SYSTEM = "operating_system"
IDENTITY_PROVIDER = "identity_provider"
MAIL_TRANSPORT = "mail_transport"
PRINT_SERVER = "print_server"
FILE_SERVER = "file_server"
NETWORK_CONTROL = "network_control"
NONE = "not_implemented"

CAPABILITIES = (
    {
        "key": "process_terminate",
        "label": "Terminate a running process",
        "enforced_by": AGENT,
        "implemented": True,
        "agent_can_enforce": True,
        "agent_can_observe": True,
        "automatable": True,
        "enforcement_point": "Endpoint agent via psutil",
        "note": "Confined to the endpoint. The process can simply be restarted or run from a copy elsewhere.",
    },
    {
        "key": "isolate",
        "label": "Isolate the endpoint from the network",
        "enforced_by": AGENT,
        "implemented": True,
        "agent_can_enforce": True,
        "agent_can_observe": True,
        # Isolation without a recovery path strands a user offline, so this is
        # not safe to fire unattended until pairing with automatic release is built.
        "automatable": False,
        "enforcement_point": "Windows firewall rules applied by the agent",
        "note": "Management addresses must be pre-declared as exceptions so containment cannot cut off the channel used to undo it.",
    },
    {
        "key": "file_snapshot_rollback",
        "label": "Snapshot and roll back files or a Windows restore point",
        "enforced_by": AGENT,
        "implemented": True,
        "agent_can_enforce": True,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Volume Shadow Copy / Windows System Restore",
        "note": "Rollback is confirmed by a separate verification command; an unverified rollback is never reported as success.",
    },
    {
        "key": "live_desktop_response",
        "label": "Live view or control of the endpoint desktop",
        "enforced_by": AGENT,
        "implemented": True,
        "agent_can_enforce": True,
        "agent_can_observe": True,
        # Injecting clicks and keystrokes at a human being's workstation without
        # a human in the loop is not something automation should be able to do.
        "automatable": False,
        "enforcement_point": "Endpoint agent desktop adapter",
        "note": "Control mode is restricted to the operator who opened the session, and typed text is not retained after dispatch.",
    },
    {
        "key": "account_lockout",
        "label": "Lock the user account",
        "enforced_by": IDENTITY_PROVIDER,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": False,
        "automatable": False,
        "enforcement_point": "Active Directory or the identity provider",
        "note": "Account state lives in the directory. An agent-side flag would leave the user able to authenticate on another host, which is worse than appearing to work.",
    },
    {
        "key": "session_logoff",
        "label": "Terminate the user's interactive session",
        "enforced_by": IDENTITY_PROVIDER,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Session manager or identity provider",
        "note": "The agent can terminate processes it owns; ending the whole session is a directory/session-manager operation.",
    },
    {
        "key": "email_send_block",
        "label": "Block outbound email",
        "enforced_by": MAIL_TRANSPORT,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Mail transport rules or a DLP gateway",
        "note": "The agent observes a send click, which is intent, not delivery. Once mail leaves the host it cannot be recalled.",
    },
    {
        "key": "print_block",
        "label": "Block printing",
        "enforced_by": PRINT_SERVER,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Print server or driver policy",
        "note": "Print jobs are spooled outside the agent's control; the agent reads spooler metadata and can withhold capture, but not the print itself.",
    },
    {
        "key": "clipboard_block",
        "label": "Block clipboard transfer",
        "enforced_by": OPERATING_SYSTEM,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Group Policy clipboard restrictions",
        "note": "The agent can decline to capture the clipboard; preventing the copy itself is an OS policy.",
    },
    {
        "key": "usb_block",
        "label": "Block removable storage",
        "enforced_by": OPERATING_SYSTEM,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Device access control policy or endpoint agent self-restriction",
        "note": "An agent can restrict itself, which raises cost for the user but does not prevent use of another copy of the same media.",
    },
    {
        "key": "cloud_upload_block",
        "label": "Block cloud upload",
        "enforced_by": NETWORK_CONTROL,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "Proxy or DLP gateway",
        "note": "Observed by domain and upload volume; enforcement belongs on the network path.",
    },
    {
        "key": "network_share_block",
        "label": "Block network share access",
        "enforced_by": FILE_SERVER,
        "implemented": False,
        "agent_can_enforce": False,
        "agent_can_observe": True,
        "automatable": False,
        "enforcement_point": "SMB share permissions or file server ACLs",
        "note": "Access is granted by the file server, so revocation has to happen there.",
    },
)

BY_KEY = {entry["key"]: entry for entry in CAPABILITIES}


def automatable_actions() -> tuple[str, ...]:
    """Response actions a playbook may dispatch without an operator present."""
    return tuple(
        entry["key"]
        for entry in CAPABILITIES
        if entry["implemented"] and entry["automatable"]
    )
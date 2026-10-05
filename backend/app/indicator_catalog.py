"""Versioned first-party definitions; not a reproduction of a vendor catalog.

Each signal is an observed fact, not an assertion inferred from its absence.
The catalog explicitly distinguishes daily/weekly measures and detection windows.
"""
CATALOG_VERSION = 2
SIGNALS = {
    'identity': 'login_failure mfa_failure password_reset account_lockout dormant_login service_account_login shared_account_login privileged_login new_device_login unusual_location_login',
    'access': 'permission_denied privileged_role_change access_grant access_revoke sensitive_record_access customer_record_access cross_department_access bulk_record_access directory_enumeration database_query',
    'data': 'usb_write cloud_upload personal_email_transfer large_download large_export archive_creation encryption_action sensitive_clipboard print_sensitive file_delete',
    'network': 'port_scan host_scan c2_indicator malware_callback periodic_beacon unknown_protocol protocol_port_mismatch tcp_overlap dns_tunnel_indicator external_connection',
    'system': 'security_agent_stop audit_log_clear logging_disabled antivirus_disabled firewall_change persistence_change unsigned_process credential_tool remote_session_start system_time_change',
    'financial': 'beneficiary_change address_change dormant_account_access attribute_change payment_override transfer_reversal high_value_transfer split_transfer approval_bypass payee_creation',
    'communication': 'external_email mass_email personal_webmail recipient_mismatch restricted_domain secret_in_message external_chat file_share_link mailbox_forwarding mailbox_rule_change',
    'policy': 'out_of_hours_access restricted_app policy_violation warning_ignored training_overdue consent_withdrawal unmanaged_device remote_access_denied biometric_mismatch concurrent_account_use',
}
UNITS = {signal: 'observed occurrences' for group in SIGNALS.values() for signal in group.split()}
REQUIRED_FACTS = tuple(UNITS)
assert len(REQUIRED_FACTS) == 80


def behavior_catalog():
    for category, signals in SIGNALS.items():
        for signal in signals.split():
            for period in ('day', 'week'):
                yield {'key': f'bi_{signal}_{period}', 'label': f'{signal.replace("_", " ").capitalize()} per {period}',
                       'fact_name': signal, 'measure': 'count', 'period': period, 'window_days': 90,
                       'category': category, 'unit': 'observed occurrences', 'origin': 'first-party',
                       'required_evidence': f'One {signal} fact for each observation; no automatic inference from missing data'}


def threat_catalog():
    for category, signals in SIGNALS.items():
        for signal in signals.split():
            for suffix, days, measure, threshold in [('acute', 1, 'count', 3), ('weekly', 7, 'count', 10), ('monthly', 30, 'count', 30), ('targets', 7, 'distinct', 3)]:
                yield {'key': f'it_{signal}_{suffix}', 'framework': 'local',
                       'name': f'{signal.replace("_", " ").capitalize()}: {suffix} threshold', 'fact_name': signal,
                       'measure': measure, 'window_days': days, 'threshold': threshold, 'score': 70,
                       'category': category, 'origin': 'first-party',
                       'required_evidence': 'Distinct-target variants require target references in text_value' if measure == 'distinct' else 'One fact per observed occurrence',
                       'rationale': 'Review volume exceeding the configured threshold; calibrate to the organization before operational use'}

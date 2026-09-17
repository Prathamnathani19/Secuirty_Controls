from django.urls import path

from .fail2ban_custom import (
    fail2ban_custom_jails,
    fail2ban_custom_jail_validate,
    fail2ban_custom_jail_detail,
)

from .reports import (
    reports,
    report_csv,
    report_pdf,
)

from .views import (
    auth_login,
    auth_logout,
    auth_me,
    csrf_token_view,
    fail2ban_info,
    firewall_info,
    firewall_rule_detail,
    firewall_rules,
    health,
    logs_info,
    services,
    system_info,
    snort_info,
    snort_custom_rules,
    snort_custom_rule_validate,
    snort_custom_rule_detail,
    suricata_info,
        suricata_rules,
        suricata_rule_list,
        suricata_custom_rules,
        suricata_custom_rule_validate,
        suricata_custom_rule_detail,
    hpc_blocked_ips,
    hpc_unblock_ip,
    hpc_block_decisions,
    hpc_approve_block_decision,
    hpc_deny_block_decision,
)

urlpatterns = [
    path("health/", health, name="health"),
    path("system/", system_info, name="system"),
    path("services/", services, name="services"),

    path("firewall/", firewall_info, name="firewall"),
    path(
        "firewall/rules/",
        firewall_rules,
        name="firewall-rules",
    ),
    path(
        "firewall/rules/<str:rule_id>/",
        firewall_rule_detail,
        name="firewall-rule-detail",
    ),

    path("logs/", logs_info, name="logs"),
    path("reports/", reports, name="reports"),
    path("reports/download/csv/", report_csv, name="reports-csv"),
    path("reports/download/pdf/", report_pdf, name="reports-pdf"),
    path("fail2ban/", fail2ban_info, name="fail2ban"),
    path(
        "fail2ban/custom-jails/",
        fail2ban_custom_jails,
        name="fail2ban-custom-jails",
    ),
    path(
        "fail2ban/custom-jails/validate/",
        fail2ban_custom_jail_validate,
        name="fail2ban-custom-jail-validate",
    ),
    path(
        "fail2ban/custom-jails/<str:name>/",
        fail2ban_custom_jail_detail,
        name="fail2ban-custom-jail-detail",
    ),

    path("suricata/", suricata_info, name="suricata"),
    path("suricata/rules/", suricata_rules, name="suricata-rules"),
    path("suricata/rules/list/", suricata_rule_list, name="suricata-rule-list"),
    path(
        "suricata/custom-rules/",
        suricata_custom_rules,
        name="suricata-custom-rules",
    ),
    path(
        "suricata/custom-rules/validate/",
        suricata_custom_rule_validate,
        name="suricata-custom-rule-validate",
    ),
    path(
        "suricata/custom-rules/<str:sid>/",
        suricata_custom_rule_detail,
        name="suricata-custom-rule-detail",
    ),
    path(
        "suricata/blocked-ips/",
        hpc_blocked_ips,
        name="suricata-blocked-ips",
    ),
    path(
        "suricata/blocked-ips/<str:ip>/",
        hpc_unblock_ip,
        name="suricata-unblock-ip",
    ),
    path(
        "suricata/block-decisions/",
        hpc_block_decisions,
        name="suricata-block-decisions",
    ),
    path(
        "suricata/block-decisions/<str:ip>/approve/",
        hpc_approve_block_decision,
        name="suricata-approve-block-decision",
    ),
    path(
        "suricata/block-decisions/<str:ip>/deny/",
        hpc_deny_block_decision,
        name="suricata-deny-block-decision",
    ),
    path("snort/", snort_info, name="snort"),
    path("snort/custom-rules/", snort_custom_rules, name="snort-custom-rules"),
    path("snort/custom-rules/validate/", snort_custom_rule_validate, name="snort-custom-rule-validate"),
    path("snort/custom-rules/<str:sid>/", snort_custom_rule_detail, name="snort-custom-rule-detail"),

    path("auth/csrf/", csrf_token_view, name="auth-csrf"),
    path("auth/login/", auth_login, name="auth-login"),
    path("auth/logout/", auth_logout, name="auth-logout"),
    path("auth/me/", auth_me, name="auth-me"),
]

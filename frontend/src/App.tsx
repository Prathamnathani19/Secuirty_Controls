import { useEffect, useState, type ReactNode } from "react";

import {
  AppBar,
  Box,
  Chip,
  CircularProgress,
  CssBaseline,
  Divider,
  Drawer,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControlLabel,
  Checkbox,
  TextField,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Pagination,
          Toolbar,
  Typography,
  ThemeProvider,
  createTheme,
  Alert,
} from "@mui/material";

import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  SwapHoriz as NatIcon,
  BugReport as SuricataIcon,
  GppBad as Fail2BanIcon,
  Description as LogsIcon,
  Assessment as ReportsIcon,
  Dns as SystemIcon,
  Backup as BackupIcon,
  Settings as SettingsIcon,
  Menu as MenuIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Router as RouterIcon,
  Memory as MemoryIcon,
  Lan as LanIcon,
  SwapVert as ForwardIcon,
  Rule as RuleIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
} from "@mui/icons-material";

const drawerWidth = 250;

const theme = createTheme({
  palette: {
    mode: "dark",
    background: {
      default: "#0b1220",
      paper: "#111827",
    },
    primary: {
      main: "#42a5f5",
    },
    success: {
      main: "#4caf50",
    },
    warning: {
      main: "#ffb300",
    },
    error: {
      main: "#ef5350",
    },
  },
  typography: {
    fontFamily: "Inter, Roboto, Arial, sans-serif",
  },
});

const menuItems = [
  { label: "Dashboard", icon: <DashboardIcon /> },
  { label: "Firewall", icon: <SecurityIcon /> },
  { label: "NAT", icon: <NatIcon /> },
  { label: "Suricata IPS", icon: <SuricataIcon /> },
  { label: "Snort", icon: <SuricataIcon /> },
  { label: "Fail2Ban", icon: <Fail2BanIcon /> },
  { label: "Logs", icon: <LogsIcon /> },
  { label: "Reports", icon: <ReportsIcon /> },
  { label: "System", icon: <SystemIcon /> },
  { label: "Backup", icon: <BackupIcon /> },
  { label: "Settings", icon: <SettingsIcon /> },
];


interface ReportEvent {
  timestamp: string | null;
  message: string;
  source: string;
  action?: string | null;
  severity?: number | string | null;
  src_ip?: string | null;
  dest_ip?: string | null;
  protocol?: string | null;
  priority?: number | string | null;
  hostname?: string | null;
  unit?: string | null;
}

interface SecurityReport {
  period: {
    start: string;
    end: string;
  };
  summary: {
    total_events: number;
    blocked_events: number;
    detected_events: number;
    fail2ban_bans: number;
  };
  controls: Record<string, number>;
  top_sources: Array<{
    ip: string;
    count: number;
  }>;
  events: ReportEvent[];
}

interface ReportsApiResponse {
  success: boolean;
  report?: SecurityReport;
  error?: string;
}

interface StatusCardProps {
  title: string;
  status: string;
  detail: string;
  icon: ReactNode;
  active: boolean;
}

interface ServiceStatus {
  service: string;
  active: boolean;
  status: string;
}

interface ServicesResponse {
  services: ServiceStatus[];
}

interface SuricataAlert {
  timestamp: string | null;
  source: string;
  severity: string;
  priority: number | null;
  classification: string | null;
  message: string;
  src_ip: string | null;
  src_port: string | null;
  dest_ip: string | null;
  dest_port: string | null;
  protocol: string | null;
  action: string | null;
}

interface SnortAlert {
  timestamp: string | null;
  source: string;
  severity: string;
  priority: number | null;
  classification: string | null;
  message: string;
  src_ip: string | null;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  protocol: string | null;
  action: string | null;
  interface: string | null;
  service: string | null;
  sid: number | null;
  gid: number | null;
  rev: number | null;
  rule: string | null;
}

interface AuthUser {
  id: number;
  username: string;
  email: string;
  is_staff: boolean;
  is_superuser: boolean;
}

interface AuthResponse {
  authenticated: boolean;
  user: AuthUser | null;
}

interface SnortResponse {
  service: {
    service: string;
    active: boolean;
    status: string;
  };
  alerts: {
    available: boolean;
    lines: SnortAlert[];
    error: string | null;
  };
}

interface SuricataRulesInventory {
  available: boolean;
  path: string;
  total_rules: number;
  alert_rules: number;
  drop_rules: number;
  reject_rules: number;
  disabled_rules: number;
  file_size: number | null;
  modified: string | null;
  error: string | null;
}

interface SuricataUpdateStatus {
  source: string;
  managed_drop_rules: number;
  total_drop_rules: number;
  last_update: string | null;
  last_update_status: string;
  validation: string;
  reload: string;
  automatic_update: string;
  error: string | null;
}

interface SuricataRulesResponse {
  rules: SuricataRulesInventory;
  update: SuricataUpdateStatus;
}

interface BlockDecision {
  ip: string;
  decision: string;
  source: string;
  reason: string;
  created_at: string;
  updated_at: string;
}

interface BlockDecisionsResponse {
  available: boolean;
  count: number;
  decisions: BlockDecision[];
  error: string | null;
}

interface CustomSuricataRule {
  sid: number;
  rule: string;
}

interface CustomSuricataRulesResponse {
  available: boolean;
  path: string;
  sid_min: number;
  sid_max: number;
  count: number;
  rules: CustomSuricataRule[];
  error: string | null;
}

interface BlockedIpsResponse {
  available: boolean;
  ipset: string;
  count: number;
  blocked_ips: string[];
  error: string | null;
}

interface SuricataRule {
  line: number;
  action: string;
  protocol: string;
  source: string;
  source_port: string;
  direction: string;
  destination: string;
  destination_port: string;
  message: string | null;
  sid: number | null;
  rev: number | null;
  classtype: string | null;
}

interface SuricataRuleListResponse {
  rules: {
    available: boolean;
    page: number;
    limit: number;
    total_matches: number;
    rules: SuricataRule[];
    error: string | null;
  };
}

interface SuricataResponse {
  service: {
    service: string;
    active: boolean;
    status: string;
  };
  build: {
    version: string | null;
    af_packet: boolean;
    nfqueue: boolean;
    unix_socket: boolean;
    detection: boolean;
    error?: string;
  };
  stats: {
    uptime: number | null;
    packets: number | null;
    bytes: number | null;
    accepted: number | null;
    blocked: number | null;
    rejected: number | null;
    signature_drops: number | null;
    flow_drops: number | null;
    nfq_errors: number | null;
    stream_midstream: number | null;
    rules_loaded: number | null;
  };
  alerts: {
    available: boolean;
    lines: SuricataAlert[];
    error: string | null;
  };
}

interface Fail2BanJail {
  name: string;
  currently_failed: number;
  total_failed: number;
  currently_banned: number;
  total_banned: number;
  banned_ips: string[];
  file_list: string[];
  journal_matches: string[];
  error: string | null;
}

interface Fail2BanCustomJail {
  name: string;
  jail_name: string;
  filter: string;
  logpath: string;
  maxretry: string;
  findtime: string;
  bantime: string;
  failregex: string;
  ignoreregex: string;
  active: boolean;
  jail_path: string;
  filter_path: string;
  error: string | null;
}

interface Fail2BanCustomJailsResponse {
  available: boolean;
  count: number;
  jails: Fail2BanCustomJail[];
  jail_directory: string;
  filter_directory: string;
  error: string | null;
}

interface Fail2BanResponse {
  service: {
    service: string;
    active: boolean;
    status: string;
  };
  jails: Fail2BanJail[];
  error?: string;
}

interface LogSource {
  available: boolean;
  lines: string[] | LogRecord[];
  error: string | null;
}

interface LogRecord {
  timestamp: string | null;
  source: string;
  severity: string;
  priority: number | null;
  classification: string | null;
  message: string;
  src_ip: string | null;
  src_port: string | null;
  dest_ip: string | null;
  dest_port: string | null;
  protocol: string | null;
  action: string | null;
}

interface LogsResponse {
  sources: {
    suricata: LogSource;
    snort: LogSource;
    ssh: LogSource;
    nginx_access: LogSource;
    nginx_error: LogSource;
    fail2ban: LogSource;
    firewalld: LogSource;
    system: LogSource;
  };
}

interface SystemInfo {
  hostname: string;
  os: string;
  kernel: string;
  architecture: string;
  cpu: {
    logical: number;
    physical: number;
    usage_percent: number;
  };
  memory: {
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    usage_percent: number;
  };
  uptime_seconds: number;
}

interface FirewallZone {
  name: string;
  target: string | null;
  interfaces: string[];
  sources: string[];
  services: string[];
  ports: string[];
  protocols: string[];
  forward: boolean;
  masquerade: boolean;
  forward_ports: string[];
  source_ports: string[];
  icmp_blocks: string[];
  rich_rules: string[];
}

interface ActiveZone {
  name: string;
  interfaces: string[];
}

interface FirewallResponse {
  firewalld: {
    running: boolean;
    state: string;
  };
  active_zones: ActiveZone[];
  zones: FirewallZone[];
}

interface FirewallRule {
  id: string;
  rule: string;
}

interface FirewallRulesResponse {
  zone: string;
  rules: FirewallRule[];
}

function StatusCard({
  title,
  status,
  detail,
  icon,
  active,
}: StatusCardProps) {
  return (
    <Paper
      elevation={0}
      sx={{
        p: 2.5,
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 2,
        height: "100%",
        backgroundColor: "#111827",
      }}
    >
      <Box
        sx={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
        }}
      >
        <Box>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {title}
          </Typography>

          <Typography
            variant="h5"
            sx={{
              mt: 1,
              fontWeight: 700,
              color: active ? "success.main" : "error.main",
            }}
          >
            {status}
          </Typography>

          <Typography
            variant="body2"
            sx={{
              mt: 0.5,
              color: "text.secondary",
            }}
          >
            {detail}
          </Typography>
        </Box>

        <Box sx={{ color: active ? "success.main" : "error.main" }}>
          {icon}
        </Box>
      </Box>
    </Paper>
  );
}

function formatBytes(bytes: number): string {
  const gb = bytes / 1024 / 1024 / 1024;
  return `${gb.toFixed(1)} GB`;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  return `${days}d ${hours}h ${minutes}m`;
}

function FirewallPage({
  firewall,
  loading,
  error,
}: {
  firewall: FirewallResponse | null;
  loading: boolean;
  error: boolean;
}) {
  const [firewallRules, setFirewallRules] =
    useState<FirewallRulesResponse | null>(null);

  const [rulesLoading, setRulesLoading] =
    useState(false);

  const [rulesError, setRulesError] =
    useState("");

  const [ruleDialogOpen, setRuleDialogOpen] =
    useState(false);

  const [editingRule, setEditingRule] =
    useState<FirewallRule | null>(null);

  const [ruleSaving, setRuleSaving] =
    useState(false);

  const [ruleDeleting, setRuleDeleting] =
    useState(false);

  const [ruleZone, setRuleZone] =
    useState("public");

  const [action, setAction] =
    useState("accept");

  const [protocol, setProtocol] =
    useState("tcp");

  const [family, setFamily] =
    useState("ipv4");

  const [sourceType, setSourceType] =
    useState("any");

  const [sourceAddress, setSourceAddress] =
    useState("");

  const [sourceIpSet, setSourceIpSet] =
    useState("");

  const [sourceNot, setSourceNot] =
    useState(false);

  const [sourcePort, setSourcePort] =
    useState("");

  const [destinationAddress, setDestinationAddress] =
    useState("");

  const [destinationPort, setDestinationPort] =
    useState("");

  const [priority, setPriority] =
    useState("");

  const getCsrfToken = async (): Promise<string> => {
    const response = await fetch("/api/auth/csrf/", {
      credentials: "same-origin",
    });

    if (!response.ok) {
      throw new Error("Unable to obtain CSRF token");
    }

    const cookie = document.cookie
      .split("; ")
      .find((row) => row.startsWith("csrftoken="));

    if (!cookie) {
      throw new Error("CSRF cookie not available");
    }

    return decodeURIComponent(cookie.split("=")[1]);
  };

  const fetchFirewallRules = async (
    zone = ruleZone,
  ) => {
    try {
      setRulesLoading(true);
      setRulesError("");

      const response = await fetch(
        `/api/firewall/rules/?zone=${encodeURIComponent(zone)}`,
        {
          credentials: "same-origin",
        },
      );

      if (!response.ok) {
        throw new Error("Unable to load firewall rules");
      }

      const data: FirewallRulesResponse =
        await response.json();

      setFirewallRules(data);
    } catch (err) {
      console.error("Firewall rules error:", err);

      setRulesError(
        err instanceof Error
          ? err.message
          : "Unable to load firewall rules",
      );
    } finally {
      setRulesLoading(false);
    }
  };

  useEffect(() => {
    if (!firewall) {
      return;
    }

    const availableZones =
      firewall.zones.map((zone) => zone.name);

    const selectedZoneIsValid =
      availableZones.includes(ruleZone);

    const zoneToLoad =
      selectedZoneIsValid
        ? ruleZone
        : (
            firewall.active_zones[0]?.name ??
            availableZones[0] ??
            "public"
          );

    if (zoneToLoad !== ruleZone) {
      setRuleZone(zoneToLoad);
      return;
    }

    fetchFirewallRules(zoneToLoad);
  }, [firewall, ruleZone]);

  const resetForm = () => {
    setAction("accept");
    setProtocol("tcp");
    setFamily("ipv4");
    setSourceType("any");
    setSourceAddress("");
    setSourceIpSet("");
    setSourceNot(false);
    setSourcePort("");
    setDestinationAddress("");
    setDestinationPort("");
    setPriority("");
  };

  const parseExistingRule = (rule: string) => {
    const getValue = (
      pattern: RegExp,
    ): string => {
      const match = rule.match(pattern);
      return match?.[1] ?? "";
    };

    const parsedAction =
      rule.includes(" drop")
        ? "drop"
        : rule.includes(" reject")
          ? "reject"
          : "accept";

    const parsedFamily =
      rule.includes('family="ipv6"')
        ? "ipv6"
        : "ipv4";

    const parsedProtocol =
      getValue(/protocol="([^"]+)"/) || "tcp";

    const parsedSource =
      getValue(/source address="([^"]+)"/);

    const parsedIpSet =
      getValue(/source(?:\s+NOT)?\s+ipset="([^"]+)"/);

    const parsedSourceNot =
      /source\s+NOT\s+(?:address|ipset)=/i.test(rule);

    const parsedDestination =
      getValue(/destination address="([^"]+)"/);

    const parsedPort =
      getValue(/port port="([^"]+)"/);

    const parsedSourcePort =
      getValue(/source-port port="([^"]+)"/);

    const parsedPriority =
      getValue(/priority="([^"]+)"/);

    setAction(parsedAction);
    setFamily(parsedFamily);
    setProtocol(parsedProtocol);

    setSourceType(
      parsedIpSet
        ? "ipset"
        : parsedSource
          ? "address"
          : "any",
    );

    setSourceAddress(parsedSource);
    setSourceIpSet(parsedIpSet);
    setSourceNot(parsedSourceNot);

    setDestinationAddress(parsedDestination);
    setDestinationPort(parsedPort);
    setSourcePort(parsedSourcePort);
    setPriority(parsedPriority);
  };

  const openAddRule = () => {
    resetForm();
    setEditingRule(null);
    setRulesError("");
    setRuleDialogOpen(true);
  };

  const openEditRule = (
    rule: FirewallRule,
  ) => {
    resetForm();

    // The rules API is queried for a specific zone, so the
    // current firewallRules.zone is the authoritative zone
    // for the rule being edited.
    setRuleZone(firewallRules?.zone ?? ruleZone);

    parseExistingRule(rule.rule);

    setEditingRule(rule);
    setRulesError("");
    setRuleDialogOpen(true);
  };

  const closeRuleDialog = () => {
    if (ruleSaving) {
      return;
    }

    setRuleDialogOpen(false);
    setEditingRule(null);
    resetForm();
  };

  const buildFirewallRule = (): string => {
    const parts: string[] = [
      "rule",
    ];

    if (priority.trim()) {
      parts.push(
        `priority="${priority.trim()}"`,
      );
    }

    parts.push(`family="${family}"`);

    /*
     * Source
     *
     * The source type determines which firewalld
     * source expression is generated.
     */
    if (sourceType === "address" && sourceAddress.trim()) {
      parts.push(
        `source${sourceNot ? " NOT" : ""} address="${sourceAddress.trim()}"`,
      );
    } else if (
      sourceType === "ipset" &&
      sourceIpSet.trim()
    ) {
      parts.push(
        `source${sourceNot ? " NOT" : ""} ipset="${sourceIpSet.trim()}"`,
      );
    }

    /*
     * Destination address.
     */
    if (destinationAddress.trim()) {
      parts.push(
        `destination address="${destinationAddress.trim()}"`,
      );
    }

    /*
     * Source port.
     */
    if (
      sourcePort.trim() &&
      protocol !== "icmp" &&
      protocol !== "icmpv6" &&
      protocol !== "any"
    ) {
      parts.push(
        `source-port port="${sourcePort.trim()}"`,
      );
    }

    /*
     * Protocol / destination port.
     *
     * firewalld requires the protocol together with
     * the port expression.
     */
    if (
      destinationPort.trim() &&
      protocol !== "icmp" &&
      protocol !== "icmpv6" &&
      protocol !== "any"
    ) {
      parts.push(
        `port port="${destinationPort.trim()}" protocol="${protocol}"`,
      );
    } else if (
      protocol &&
      protocol !== "any"
    ) {
      parts.push(
        `protocol="${protocol}"`,
      );
    }

    parts.push(action);

    return parts.join(" ");
  };

  const saveRule = async () => {
    if (
      (sourcePort.trim() ||
        destinationPort.trim()) &&
      (protocol === "icmp" ||
        protocol === "icmpv6")
    ) {
      setRulesError(
        "Ports cannot be used with ICMP or ICMPv6.",
      );
      return;
    }

    if (
      destinationPort.trim() &&
      !/^[0-9]+(-[0-9]+)?$/.test(
        destinationPort.trim(),
      )
    ) {
      setRulesError(
        "Destination port must be a number or range such as 443 or 8000-8080.",
      );
      return;
    }

    if (
      sourcePort.trim() &&
      !/^[0-9]+(-[0-9]+)?$/.test(
        sourcePort.trim(),
      )
    ) {
      setRulesError(
        "Source port must be a number or range such as 22 or 1000-2000.",
      );
      return;
    }

    if (
      priority.trim() &&
      !/^-?[0-9]+$/.test(
        priority.trim(),
      )
    ) {
      setRulesError(
        "Priority must be an integer.",
      );
      return;
    }

    try {
      setRuleSaving(true);
      setRulesError("");

      const csrfToken =
        await getCsrfToken();

      const rule = buildFirewallRule();

      const url = editingRule
        ? `/api/firewall/rules/${editingRule.id}/`
        : "/api/firewall/rules/";

      const method = editingRule
        ? "PUT"
        : "POST";

      const response = await fetch(url, {
        method,
        credentials: "same-origin",
        headers: {
          "Content-Type":
            "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({
          zone: ruleZone,
          rule,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to save firewall rule",
        );
      }

      setRuleDialogOpen(false);
      setEditingRule(null);
      resetForm();

      await fetchFirewallRules(ruleZone);
    } catch (err) {
      console.error(
        "Firewall rule save error:",
        err,
      );

      setRulesError(
        err instanceof Error
          ? err.message
          : "Unable to save firewall rule",
      );
    } finally {
      setRuleSaving(false);
    }
  };

  const deleteRule = async (
    rule: FirewallRule,
  ) => {
    const confirmed =
      window.confirm(
        `Delete this firewall rule?\n\n${rule.rule}`,
      );

    if (!confirmed) {
      return;
    }

    try {
      setRuleDeleting(true);
      setRulesError("");

      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        `/api/firewall/rules/${rule.id}/?zone=${encodeURIComponent(ruleZone)}`,
        {
          method: "DELETE",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": csrfToken,
          },
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to delete firewall rule",
        );
      }

      await fetchFirewallRules(ruleZone);
    } catch (err) {
      console.error(
        "Firewall rule delete error:",
        err,
      );

      setRulesError(
        err instanceof Error
          ? err.message
          : "Unable to delete firewall rule",
      );
    } finally {
      setRuleDeleting(false);
    }
  };

  if (loading && !firewall) {
    return (
      <Box
        sx={{
          display: "flex",
          justifyContent: "center",
          py: 10,
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  if (error && !firewall) {
    return (
      <Paper
        elevation={0}
        sx={{
          p: 4,
          border:
            "1px solid rgba(239,83,80,0.35)",
          borderRadius: 2,
          backgroundColor:
            "rgba(239,83,80,0.08)",
        }}
      >
        <Typography
          variant="h6"
          sx={{
            color: "error.main",
            fontWeight: 700,
          }}
        >
          Firewall API unavailable
        </Typography>

        <Typography
          sx={{
            mt: 1,
            color: "text.secondary",
          }}
        >
          Unable to retrieve the current
          firewalld configuration.
        </Typography>
      </Paper>
    );
  }

  if (!firewall) {
    return null;
  }

  const activeZoneNames =
    new Set(
      firewall.active_zones.map(
        (zone) => zone.name,
      ),
    );

  const activeZones =
    firewall.zones.filter((zone) =>
      activeZoneNames.has(zone.name),
    );

  const readableRule = (
    rule: string,
  ) => {
    const actionText =
      rule.includes(" drop")
        ? "BLOCK"
        : rule.includes(" reject")
          ? "REJECT"
          : "PASS";

    const protocolMatch =
      rule.match(/protocol="([^"]+)"/);

    const sourceAddressMatch =
      rule.match(
        /source(?:\s+NOT)?\s+address="([^"]+)"/i,
      );

    const sourceIpSetMatch =
      rule.match(
        /source(?:\s+NOT)?\s+ipset="([^"]+)"/i,
      );

    const sourceNot =
      /source\s+NOT\s+(?:address|ipset)=/i.test(
        rule,
      );

    const destinationMatch =
      rule.match(
        /destination address="([^"]+)"/,
      );

    const portMatch =
      rule.match(
        /port port="([^"]+)"/,
      );

    let source = "Any";

    if (sourceIpSetMatch?.[1]) {
      source = sourceNot
        ? `NOT ${sourceIpSetMatch[1]}`
        : sourceIpSetMatch[1];
    } else if (sourceAddressMatch?.[1]) {
      source = sourceNot
        ? `NOT ${sourceAddressMatch[1]}`
        : sourceAddressMatch[1];
    }

    return {
      action: actionText,
      protocol:
        protocolMatch?.[1]?.toUpperCase() ??
        "ANY",
      source,
      destination:
        destinationMatch?.[1] ?? "Any",
      port:
        portMatch?.[1] ?? "Any",
    };
  };

  return (
    <>
      <Box
        sx={{
          mb: 3,
          display: "flex",
          justifyContent:
            "space-between",
          alignItems: "flex-start",
          flexWrap: "wrap",
          gap: 2,
        }}
      >
        <Box>
          <Typography
            variant="h4"
            sx={{
              fontWeight: 800,
            }}
          >
            Firewall
          </Typography>

          <Typography
            sx={{
              mt: 0.5,
              color: "text.secondary",
            }}
          >
            Manage firewalld rules using a
            structured security policy form.
          </Typography>
        </Box>

        <Button
          variant="contained"
          onClick={openAddRule}
          startIcon={<RuleIcon />}
        >
          Add Rule
        </Button>
      </Box>

      <Paper
        elevation={0}
        sx={{
          p: 2.5,
          mb: 3,
          border:
            "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent:
              "space-between",
            flexWrap: "wrap",
            gap: 2,
          }}
        >
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 2,
            }}
          >
            <SecurityIcon
              color="primary"
              fontSize="large"
            />

            <Box>
              <Typography
                variant="h6"
                sx={{ fontWeight: 700 }}
              >
                firewalld
              </Typography>

              <Typography
                variant="body2"
                sx={{
                  color: "text.secondary",
                }}
              >
                Firewall enforcement service
              </Typography>
            </Box>
          </Box>

          <Chip
            icon={
              firewall.firewalld.running ? (
                <CheckCircleIcon />
              ) : (
                <WarningIcon />
              )
            }
            label={
              firewall.firewalld.running
                ? "RUNNING"
                : "NOT RUNNING"
            }
            color={
              firewall.firewalld.running
                ? "success"
                : "error"
            }
            variant="outlined"
          />
        </Box>
      </Paper>

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        Firewall Rules
      </Typography>

      <Paper
        elevation={0}
        sx={{
          mb: 3,
          border:
            "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            p: 2,
            borderBottom:
              "1px solid rgba(255,255,255,0.08)",
            display: "flex",
            justifyContent:
              "space-between",
            alignItems: "center",
            gap: 2,
            flexWrap: "wrap",
          }}
        >
          <TextField
            select
            size="small"
            label="Zone"
            value={ruleZone}
            onChange={(event) =>
              setRuleZone(event.target.value)
            }
            sx={{ minWidth: 180 }}
          >
            {firewall.zones.map((zone) => (
              <MenuItem
                key={zone.name}
                value={zone.name}
              >
                {zone.name}
              </MenuItem>
            ))}
          </TextField>

          <Button
            variant="outlined"
            onClick={() =>
              fetchFirewallRules(ruleZone)
            }
            disabled={rulesLoading}
          >
            Refresh
          </Button>
        </Box>

        {rulesLoading ? (
          <Box
            sx={{
              display: "flex",
              justifyContent: "center",
              py: 5,
            }}
          >
            <CircularProgress size={28} />
          </Box>
        ) : firewallRules &&
          firewallRules.rules.length > 0 ? (
          <Stack spacing={0}>
            {firewallRules.rules.map(
              (rule, index) => {
                const display =
                  readableRule(rule.rule);

                return (
                  <Box
                    key={rule.id}
                    sx={{
                      p: 2.5,
                      borderBottom:
                        index <
                        firewallRules.rules.length -
                          1
                          ? "1px solid rgba(255,255,255,0.06)"
                          : "none",
                    }}
                  >
                    <Box
                      sx={{
                        display: "flex",
                        alignItems:
                          "center",
                        justifyContent:
                          "space-between",
                        gap: 2,
                        flexWrap: "wrap",
                      }}
                    >
                      <Stack
                        direction="row"
                        spacing={1}
                        sx={{ alignItems: "center" }}
                      >
                        <Chip
                          label={
                            display.action
                          }
                          size="small"
                          color={
                            display.action ===
                            "PASS"
                              ? "success"
                              : "error"
                          }
                          variant="outlined"
                        />

                        <Chip
                          label={
                            display.protocol
                          }
                          size="small"
                          variant="outlined"
                        />
                      </Stack>

                      <Stack
                        direction="row"
                        spacing={1}
                      >
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() =>
                            openEditRule(rule)
                          }
                          disabled={
                            ruleDeleting
                          }
                        >
                          Edit
                        </Button>

                        <Button
                          size="small"
                          color="error"
                          variant="outlined"
                          onClick={() =>
                            deleteRule(rule)
                          }
                          disabled={
                            ruleDeleting
                          }
                        >
                          Delete
                        </Button>
                      </Stack>
                    </Box>

                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: {
                          xs: "1fr",
                          sm: "repeat(4, 1fr)",
                        },
                        gap: 2,
                        mt: 2,
                      }}
                    >
                      <Box>
                        <Typography
                          variant="caption"
                          sx={{
                            color:
                              "text.secondary",
                          }}
                        >
                          Source
                        </Typography>

                        <Typography>
                          {display.source}
                        </Typography>
                      </Box>

                      <Box>
                        <Typography
                          variant="caption"
                          sx={{
                            color:
                              "text.secondary",
                          }}
                        >
                          Destination
                        </Typography>

                        <Typography>
                          {
                            display.destination
                          }
                        </Typography>
                      </Box>

                      <Box>
                        <Typography
                          variant="caption"
                          sx={{
                            color:
                              "text.secondary",
                          }}
                        >
                          Port
                        </Typography>

                        <Typography>
                          {display.port}
                        </Typography>
                      </Box>

                      <Box>
                        <Typography
                          variant="caption"
                          sx={{
                            color:
                              "text.secondary",
                          }}
                        >
                          Zone
                        </Typography>

                        <Typography>
                          {ruleZone}
                        </Typography>
                      </Box>
                    </Box>
                  </Box>
                );
              },
            )}
          </Stack>
        ) : (
          <Box sx={{ p: 3 }}>
            <Typography
              sx={{
                color: "text.secondary",
              }}
            >
              No firewall rules configured
              for this zone.
            </Typography>
          </Box>
        )}
      </Paper>

      {rulesError && (
        <Paper
          elevation={0}
          sx={{
            p: 2,
            mb: 3,
            border:
              "1px solid rgba(239,83,80,0.3)",
            borderRadius: 2,
            backgroundColor:
              "rgba(239,83,80,0.08)",
          }}
        >
          <Typography
            sx={{
              color: "error.main",
            }}
          >
            {rulesError}
          </Typography>
        </Paper>
      )}

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        Active Zones
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            md: "repeat(2, 1fr)",
          },
          gap: 2,
          mb: 3,
        }}
      >
        {activeZones.map((zone) => (
          <Paper
            key={zone.name}
            elevation={0}
            sx={{
              p: 2.5,
              border:
                "1px solid rgba(255,255,255,0.08)",
              borderRadius: 2,
              backgroundColor: "#111827",
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1.5,
                mb: 2,
              }}
            >
              <LanIcon color="primary" />

              <Typography
                variant="h6"
                sx={{ fontWeight: 700 }}
              >
                {zone.name.toUpperCase()}
              </Typography>

              <Chip
                label="ACTIVE"
                size="small"
                color="success"
                variant="outlined"
              />
            </Box>

            <Typography
              variant="body2"
              sx={{
                color: "text.secondary",
                mb: 1,
              }}
            >
              Interfaces
            </Typography>

            <Stack
              direction="row"
              spacing={1}
              sx={{ flexWrap: "wrap" }}
              useFlexGap
            >
              {zone.interfaces.map(
                (iface) => (
                  <Chip
                    key={iface}
                    label={iface}
                    size="small"
                    variant="outlined"
                  />
                ),
              )}
            </Stack>

            <Divider sx={{ my: 2.5 }} />

            <Typography
              variant="subtitle1"
              sx={{
                fontWeight: 700,
                mb: 1,
              }}
            >
              Services
            </Typography>

            {zone.services.length > 0 ? (
              <Stack
                direction="row"
                spacing={1}
                sx={{ flexWrap: "wrap" }}
                useFlexGap
              >
                {zone.services.map(
                  (service) => (
                    <Chip
                      key={service}
                      label={service}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  ),
                )}
              </Stack>
            ) : (
              <Typography
                variant="body2"
                sx={{
                  color:
                    "text.secondary",
                }}
              >
                No services configured.
              </Typography>
            )}

            <Typography
              variant="subtitle1"
              sx={{
                fontWeight: 700,
                mt: 2.5,
                mb: 1,
              }}
            >
              Ports
            </Typography>

            {zone.ports.length > 0 ? (
              <Stack
                direction="row"
                spacing={1}
                sx={{ flexWrap: "wrap" }}
                useFlexGap
              >
                {zone.ports.map((port) => (
                  <Chip
                    key={port}
                    label={port}
                    size="small"
                    variant="outlined"
                  />
                ))}
              </Stack>
            ) : (
              <Typography
                variant="body2"
                sx={{
                  color:
                    "text.secondary",
                }}
              >
                No direct ports configured.
              </Typography>
            )}
          </Paper>
        ))}
      </Box>

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        Port Forwarding
      </Typography>

      <Paper
        elevation={0}
        sx={{
          p: 2.5,
          mb: 3,
          border:
            "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        {activeZones.flatMap((zone) =>
          zone.forward_ports.map(
            (forward, index) => (
              <Box
                key={`${zone.name}-${index}`}
                sx={{
                  display: "flex",
                  alignItems: "center",
                  gap: 2,
                  p: 1.5,
                  borderRadius: 1.5,
                  backgroundColor:
                    "rgba(255,255,255,0.025)",
                  mb: 1,
                }}
              >
                <ForwardIcon color="primary" />

                <Box>
                  <Typography
                    sx={{ fontWeight: 600 }}
                  >
                    {forward}
                  </Typography>

                  <Typography
                    variant="caption"
                    sx={{
                      color:
                        "text.secondary",
                    }}
                  >
                    Zone: {zone.name}
                  </Typography>
                </Box>
              </Box>
            ),
          ),
        )}

        {!activeZones.some(
          (zone) =>
            zone.forward_ports.length > 0,
        ) && (
          <Typography
            variant="body2"
            sx={{
              color: "text.secondary",
            }}
          >
            No port forwarding rules
            configured.
          </Typography>
        )}
      </Paper>

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        Rich Rules
      </Typography>

      <Paper
        elevation={0}
        sx={{
          p: 2,
          mb: 3,
          border:
            "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        <Typography
          variant="body2"
          sx={{
            color: "text.secondary",
          }}
        >
          Existing firewalld rich rules are
          managed through the structured rule
          editor above.
        </Typography>
      </Paper>

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        Available Zones
      </Typography>

      <Paper
        elevation={0}
        sx={{
          p: 2.5,
          border:
            "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        <Stack
          direction="row"
          spacing={1}
          sx={{ flexWrap: "wrap" }}
          useFlexGap
        >
          {firewall.zones.map((zone) => (
            <Chip
              key={zone.name}
              label={zone.name}
              color={
                activeZoneNames.has(zone.name)
                  ? "primary"
                  : "default"
              }
              variant={
                activeZoneNames.has(zone.name)
                  ? "filled"
                  : "outlined"
              }
            />
          ))}
        </Stack>
      </Paper>

      <Dialog
        open={ruleDialogOpen}
        onClose={closeRuleDialog}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle
          sx={{ fontWeight: 800 }}
        >
          {editingRule
            ? "Edit Firewall Rule"
            : "Add Firewall Rule"}
        </DialogTitle>

        <DialogContent dividers>
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: {
                xs: "1fr",
                sm: "repeat(2, 1fr)",
              },
              gap: 2,
              pt: 1,
            }}
          >
            <TextField
              select
              label="Action"
              value={action}
              onChange={(event) =>
                setAction(event.target.value)
              }
              fullWidth
            >
              <MenuItem value="accept">
                Pass / Accept
              </MenuItem>

              <MenuItem value="reject">
                Reject
              </MenuItem>

              <MenuItem value="drop">
                Block / Drop
              </MenuItem>
            </TextField>

            <TextField
              select
              label="Protocol"
              value={protocol}
              onChange={(event) =>
                setProtocol(event.target.value)
              }
              fullWidth
            >
              <MenuItem value="any">
                Any
              </MenuItem>

              <MenuItem value="tcp">
                TCP
              </MenuItem>

              <MenuItem value="udp">
                UDP
              </MenuItem>

              <MenuItem value="sctp">
                SCTP
              </MenuItem>

              <MenuItem value="icmp">
                ICMP
              </MenuItem>

              <MenuItem value="icmpv6">
                ICMPv6
              </MenuItem>
            </TextField>

            <TextField
              select
              label="Address Family"
              value={family}
              onChange={(event) =>
                setFamily(event.target.value)
              }
              fullWidth
            >
              <MenuItem value="ipv4">
                IPv4
              </MenuItem>

              <MenuItem value="ipv6">
                IPv6
              </MenuItem>
            </TextField>

            <TextField
              select
              label="Zone"
              value={ruleZone}
              onChange={(event) =>
                setRuleZone(event.target.value)
              }
              fullWidth
            >
              {(firewall?.zones ?? []).map((zone) => (
                <MenuItem
                  key={zone.name}
                  value={zone.name}
                >
                  {zone.name}
                </MenuItem>
              ))}
            </TextField>

            <Box
              sx={{
                gridColumn: {
                  xs: "auto",
                  sm: "1 / -1",
                },
                mt: 1,
              }}
            >
              <Typography
                variant="subtitle1"
                sx={{
                  fontWeight: 700,
                  mb: 1.5,
                }}
              >
                Source
              </Typography>
            </Box>

            <TextField
              select
              label="Source Type"
              value={sourceType}
              onChange={(event) => {
                const value = event.target.value;
                setSourceType(value);

                if (value === "any") {
                  setSourceAddress("");
                  setSourceIpSet("");
                  setSourceNot(false);
                } else if (value === "address") {
                  setSourceIpSet("");
                } else if (value === "ipset") {
                  setSourceAddress("");
                }
              }}
              fullWidth
            >
              <MenuItem value="any">
                Any
              </MenuItem>

              <MenuItem value="address">
                Address / Network
              </MenuItem>

              <MenuItem value="ipset">
                IP Set
              </MenuItem>
            </TextField>

            {sourceType === "address" && (
              <TextField
                label="Source Address"
                placeholder="10.208.22.0/24"
                value={sourceAddress}
                onChange={(event) =>
                  setSourceAddress(
                    event.target.value,
                  )
                }
                helperText="IPv4/IPv6 address or CIDR."
                fullWidth
              />
            )}

            {sourceType === "ipset" && (
              <TextField
                select
                label="Source IP Set"
                value={sourceIpSet}
                onChange={(event) =>
                  setSourceIpSet(
                    event.target.value,
                  )
                }
                helperText="Select an existing firewalld IP set."
                fullWidth
              >
                <MenuItem value="geoip_india">
                  geoip_india — India
                </MenuItem>
              </TextField>
            )}

            {sourceType !== "any" && (
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  minHeight: 56,
                }}
              >
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={sourceNot}
                      onChange={(event) =>
                        setSourceNot(
                          event.target.checked,
                        )
                      }
                    />
                  }
                  label="Invert source (NOT)"
                />
              </Box>
            )}

            <TextField
              label="Source Port"
              placeholder="Any"
              value={sourcePort}
              onChange={(event) =>
                setSourcePort(
                  event.target.value,
                )
              }
              helperText="Example: 22 or 1000-2000"
              disabled={
                protocol === "icmp" ||
                protocol === "icmpv6"
              }
              fullWidth
            />

            <Box
              sx={{
                gridColumn: {
                  xs: "auto",
                  sm: "1 / -1",
                },
                mt: 1,
              }}
            >
              <Typography
                variant="subtitle1"
                sx={{
                  fontWeight: 700,
                  mb: 1.5,
                }}
              >
                Destination
              </Typography>
            </Box>

            <TextField
              label="Destination Address"
              placeholder="Any"
              value={destinationAddress}
              onChange={(event) =>
                setDestinationAddress(
                  event.target.value,
                )
              }
              helperText="Leave empty for Any."
              fullWidth
            />

            <TextField
              label="Destination Port"
              placeholder="Any"
              value={destinationPort}
              onChange={(event) =>
                setDestinationPort(
                  event.target.value,
                )
              }
              helperText="Example: 80, 443 or 8000-8080"
              disabled={
                protocol === "icmp" ||
                protocol === "icmpv6"
              }
              fullWidth
            />

            <Box
              sx={{
                gridColumn: {
                  xs: "auto",
                  sm: "1 / -1",
                },
                mt: 1,
              }}
            >
              <Typography
                variant="subtitle1"
                sx={{
                  fontWeight: 700,
                  mb: 1.5,
                }}
              >
                Advanced
              </Typography>
            </Box>

            <TextField
              label="Priority"
              placeholder="Default"
              value={priority}
              onChange={(event) =>
                setPriority(
                  event.target.value,
                )
              }
              helperText="Optional. Lower values are evaluated first."
              fullWidth
            />
          </Box>

          {rulesError && (
            <Typography
              sx={{
                mt: 2,
                color: "error.main",
              }}
            >
              {rulesError}
            </Typography>
          )}
        </DialogContent>

        <DialogActions
          sx={{ p: 2 }}
        >
          <Button
            onClick={closeRuleDialog}
            disabled={ruleSaving}
          >
            Cancel
          </Button>

          <Button
            variant="contained"
            onClick={saveRule}
            disabled={ruleSaving}
          >
            {ruleSaving
              ? "Saving..."
              : editingRule
                ? "Save Changes"
                : "Save Rule"}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

function NatPage({
  firewall,
}: {
  firewall: FirewallResponse | null;
}) {
  if (!firewall) {
    return (
      <Paper
        elevation={0}
        sx={{
          p: 4,
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        <Typography
          variant="h6"
          sx={{ color: "warning.main", fontWeight: 700 }}
        >
          NAT configuration unavailable
        </Typography>

        <Typography
          sx={{
            mt: 1,
            color: "text.secondary",
          }}
        >
          Unable to retrieve the current firewalld NAT configuration.
        </Typography>
      </Paper>
    );
  }

  const activeZones = firewall.zones.filter((zone) =>
    firewall.active_zones.some(
      (active) => active.name === zone.name,
    ),
  );

  const forwardRules = activeZones.flatMap((zone) =>
    zone.forward_ports.map((rule) => ({
      zone: zone.name,
      rule,
    })),
  );

  return (
    <>
      <Box sx={{ mb: 3 }}>
        <Typography
          variant="h4"
          sx={{ fontWeight: 800 }}
        >
          NAT
        </Typography>

        <Typography
          sx={{
            mt: 0.5,
            color: "text.secondary",
          }}
        >
          Network Address Translation and port forwarding.
        </Typography>
      </Box>

      <Paper
        elevation={0}
        sx={{
          p: 2.5,
          mb: 3,
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 2,
          }}
        >
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 2,
            }}
          >
            <ForwardIcon
              color="primary"
              fontSize="large"
            />

            <Box>
              <Typography
                variant="h6"
                sx={{ fontWeight: 700 }}
              >
                Port Forwarding
              </Typography>

              <Typography
                variant="body2"
                sx={{ color: "text.secondary" }}
              >
                Current firewalld forward-port configuration
              </Typography>
            </Box>
          </Box>

          <Chip
            label={`${forwardRules.length} rule${
              forwardRules.length === 1 ? "" : "s"
            }`}
            color="primary"
            variant="outlined"
          />
        </Box>
      </Paper>

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        Port Forward Rules
      </Typography>

      {forwardRules.length === 0 ? (
        <Paper
          elevation={0}
          sx={{
            p: 3,
            mb: 3,
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 2,
            backgroundColor: "#111827",
          }}
        >
          <Typography
            sx={{ color: "text.secondary" }}
          >
            No port forwarding rules are configured.
          </Typography>
        </Paper>
      ) : (
        <Stack spacing={1.5} sx={{ mb: 3 }}>
          {forwardRules.map((item, index) => (
            <Paper
              key={`${item.zone}-${index}`}
              elevation={0}
              sx={{
                p: 2.5,
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 2,
                backgroundColor: "#111827",
              }}
            >
              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    sm: "80px 1fr 140px 120px",
                  },
                  gap: 2,
                  alignItems: "center",
                }}
              >
                <Box>
                  <Typography
                    variant="caption"
                    sx={{ color: "text.secondary" }}
                  >
                    #
                  </Typography>

                  <Typography sx={{ fontWeight: 700 }}>
                    {index + 1}
                  </Typography>
                </Box>

                <Box>
                  <Typography
                    variant="caption"
                    sx={{ color: "text.secondary" }}
                  >
                    Forward Rule
                  </Typography>

                  <Typography
                    sx={{
                      mt: 0.5,
                      fontFamily:
                        "ui-monospace, SFMono-Regular, Menlo, monospace",
                    }}
                  >
                    {item.rule}
                  </Typography>
                </Box>

                <Box>
                  <Typography
                    variant="caption"
                    sx={{ color: "text.secondary" }}
                  >
                    Zone
                  </Typography>

                  <Box sx={{ mt: 0.5 }}>
                    <Chip
                      label={item.zone}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  </Box>
                </Box>

                <Box>
                  <Typography
                    variant="caption"
                    sx={{ color: "text.secondary" }}
                  >
                    Status
                  </Typography>

                  <Box sx={{ mt: 0.5 }}>
                    <Chip
                      label="ACTIVE"
                      size="small"
                      color="success"
                      variant="outlined"
                    />
                  </Box>
                </Box>
              </Box>
            </Paper>
          ))}
        </Stack>
      )}

      <Typography
        variant="h6"
        sx={{
          mb: 1.5,
          fontWeight: 700,
        }}
      >
        NAT / Masquerading
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            md: "repeat(2, 1fr)",
          },
          gap: 2,
          mb: 3,
        }}
      >
        {activeZones.map((zone) => (
          <Paper
            key={zone.name}
            elevation={0}
            sx={{
              p: 2.5,
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 2,
              backgroundColor: "#111827",
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <Box>
                <Typography
                  variant="h6"
                  sx={{ fontWeight: 700 }}
                >
                  {zone.name.toUpperCase()}
                </Typography>

                <Typography
                  variant="body2"
                  sx={{
                    mt: 0.5,
                    color: "text.secondary",
                  }}
                >
                  Interface:{" "}
                  {zone.interfaces.join(", ") || "None"}
                </Typography>
              </Box>

              <Chip
                label={
                  zone.masquerade
                    ? "ENABLED"
                    : "DISABLED"
                }
                color={
                  zone.masquerade
                    ? "success"
                    : "default"
                }
                variant="outlined"
              />
            </Box>

            <Divider sx={{ my: 2 }} />

            <Typography
              variant="body2"
              sx={{ color: "text.secondary" }}
            >
              Masquerading allows traffic leaving this zone
              to be source-NATed using the gateway address.
            </Typography>
          </Paper>
        ))}
      </Box>

      <Paper
        elevation={0}
        sx={{
          p: 2.5,
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          backgroundColor: "#111827",
        }}
      >
        <Typography
          variant="subtitle1"
          sx={{ fontWeight: 700 }}
        >
          NAT Safety
        </Typography>

        <Typography
          variant="body2"
          sx={{
            mt: 1,
            color: "text.secondary",
          }}
        >
          This page is currently read-only. No firewall,
          NAT, forwarding, or masquerading changes are made
          from the GUI.
        </Typography>
      </Paper>
    </>
  );
}

function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const [mobileOpen, setMobileOpen] = useState(false);
  const [selected, setSelected] = useState("Dashboard");

  const [reportPeriod, setReportPeriod] = useState("hour");
  const [reportStart, setReportStart] = useState("");
  const [reportEnd, setReportEnd] = useState("");
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");
  const [reportGenerated, setReportGenerated] = useState(false);

  const generateReport = async () => {
    setReportLoading(true);
    setReportError("");

    try {
      const params = new URLSearchParams({
        period: reportPeriod,
      });

      if (reportPeriod === "custom") {
        if (!reportStart || !reportEnd) {
          throw new Error("Please select both start and end date/time.");
        }

        params.set(
          "start",
          new Date(reportStart).toISOString()
        );
        params.set(
          "end",
          new Date(reportEnd).toISOString()
        );
      }

      const response = await fetch(
        `/api/reports/?${params.toString()}`,
        {
          credentials: "same-origin",
        }
      );

      const data: ReportsApiResponse = await response.json();

      if (!response.ok || !data.success || !data.report) {
        throw new Error(
          data.error || "Unable to generate the report."
        );
      }

      setReport(data.report);
      setReportGenerated(true);
    } catch (error) {
      setReport(null);
      setReportGenerated(false);
      setReportError(
        error instanceof Error
          ? error.message
          : "Unable to generate the report."
      );
    } finally {
      setReportLoading(false);
    }
  };

  const downloadReport = (format: "csv" | "pdf") => {
    const params = new URLSearchParams({
      period: reportPeriod,
    });

    if (reportPeriod === "custom") {
      if (!reportStart || !reportEnd) {
        setReportError(
          "Please select both start and end date/time."
        );
        return;
      }

      params.set(
        "start",
        new Date(reportStart).toISOString()
      );
      params.set(
        "end",
        new Date(reportEnd).toISOString()
      );
    }

    window.location.href =
      `/api/reports/download/${format}/?${params.toString()}`;
  };

  const formatReportDate = (value: string | null) => {
    if (!value) return "—";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleString("en-IN", {
      dateStyle: "medium",
      timeStyle: "medium",
    });
  };




  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [firewall, setFirewall] =
    useState<FirewallResponse | null>(null);

  const [suricata, setSuricata] =
    useState<SuricataResponse | null>(null);
  const [suricataRules, setSuricataRules] =
    useState<SuricataRulesInventory | null>(null);

  const [suricataUpdate, setSuricataUpdate] =
    useState<SuricataUpdateStatus | null>(null);

  const [blockedIps, setBlockedIps] =
    useState<BlockedIpsResponse | null>(null);

  const [blockDecisions, setBlockDecisions] =
    useState<BlockDecisionsResponse | null>(null);

  const [customSnortRules, setCustomSnortRules] =
    useState<any>(null);
  const [customSnortRuleValidation, setCustomSnortRuleValidation] =
    useState<string | null>(null);
  const [customSnortRuleValid, setCustomSnortRuleValid] =
    useState(false);
  const [customSnortRuleLoading, setCustomSnortRuleLoading] =
    useState(false);
  const [customSnortAction, setCustomSnortAction] =
    useState("alert");
  const [customSnortProtocol, setCustomSnortProtocol] =
    useState("tcp");
  const [customSnortSource, setCustomSnortSource] =
    useState("$EXTERNAL_NET");
  const [customSnortSourcePort, setCustomSnortSourcePort] =
    useState("any");
  const [customSnortDirection, setCustomSnortDirection] =
    useState("->");
  const [customSnortDestination, setCustomSnortDestination] =
    useState("$HOME_NET");
  const [customSnortDestinationPort, setCustomSnortDestinationPort] =
    useState("any");
  const [customSnortMessage, setCustomSnortMessage] =
    useState("");

  const [customSuricataRules, setCustomSuricataRules] =
    useState<CustomSuricataRulesResponse | null>(null);

  const [customSuricataRuleText, setCustomSuricataRuleText] =
    useState("");

  const [customSuricataRuleValidation, setCustomSuricataRuleValidation] =
    useState<string | null>(null);

  const [customSuricataRuleValid, setCustomSuricataRuleValid] =
    useState<boolean | null>(null);

  const [customSuricataRuleLoading, setCustomSuricataRuleLoading] =
    useState(false);
  const [customSuricataRuleDialogOpen, setCustomSuricataRuleDialogOpen] =
    useState(false);
  const [customSuricataAction, setCustomSuricataAction] =
    useState("drop");
  const [customSuricataProtocol, setCustomSuricataProtocol] =
    useState("tcp");
  const [customSuricataSource, setCustomSuricataSource] =
    useState("$EXTERNAL_NET");
  const [customSuricataSourcePort, setCustomSuricataSourcePort] =
    useState("any");
  const [customSuricataDirection, setCustomSuricataDirection] =
    useState("->");
  const [customSuricataDestination, setCustomSuricataDestination] =
    useState("$HOME_NET");
  const [customSuricataDestinationPort, setCustomSuricataDestinationPort] =
    useState("any");
  const [customSuricataMessage, setCustomSuricataMessage] =
    useState("");

  const [suricataRuleList, setSuricataRuleList] =
    useState<SuricataRule[]>([]);
  const [suricataRuleSearch, setSuricataRuleSearch] =
    useState("");
  const [suricataRuleAction, setSuricataRuleAction] =
    useState("");
  const [suricataRuleProtocol, setSuricataRuleProtocol] =
    useState("");
  const [suricataRulePage, setSuricataRulePage] =
    useState(1);
  const [suricataRuleTotal, setSuricataRuleTotal] =
    useState(0);
  const [suricataRuleLoading, setSuricataRuleLoading] =
    useState(false);
  const [suricataRuleError, setSuricataRuleError] =
    useState("");
  const [snort, setSnort] =
    useState<SnortResponse | null>(null);
  const [fail2ban, setFail2ban] =
    useState<Fail2BanResponse | null>(null);

  const [fail2banCustomJails, setFail2banCustomJails] =
    useState<Fail2BanCustomJailsResponse | null>(null);

  const [fail2banCustomJailName, setFail2banCustomJailName] =
    useState("");
  const [fail2banCustomJailLogpath, setFail2banCustomJailLogpath] =
    useState("");
  const [fail2banCustomJailTrigger, setFail2banCustomJailTrigger] =
    useState("http-400");
  const [fail2banCustomJailMaxretry, setFail2banCustomJailMaxretry] =
    useState("5");
  const [fail2banCustomJailFindtime, setFail2banCustomJailFindtime] =
    useState("10m");
  const [fail2banCustomJailBantime, setFail2banCustomJailBantime] =
    useState("1h");

  const [fail2banCustomJailValidation, setFail2banCustomJailValidation] =
    useState<string | null>(null);
  const [fail2banCustomJailValid, setFail2banCustomJailValid] =
    useState<boolean | null>(null);
  const [fail2banCustomJailLoading, setFail2banCustomJailLoading] =
    useState(false);

  const [logs, setLogs] =
    useState<LogsResponse | null>(null);

  const suricataRulesSynchronized =
    suricata?.stats.rules_loaded !== null &&
    suricata?.stats.rules_loaded !== undefined &&
    suricataRules?.total_rules !== undefined &&
    suricata.stats.rules_loaded ===
      suricataRules.total_rules;

  const suricataEvents =
    logs?.sources.suricata.lines.filter(
      (entry): entry is LogRecord =>
        typeof entry !== "string" &&
        ["medium", "high", "critical"].includes(
          entry.severity.toLowerCase(),
        ),
    ) ?? [];

  const snortEvents =
    logs?.sources.snort.lines.filter(
      (entry): entry is LogRecord =>
        typeof entry !== "string" &&
        ["high", "critical"].includes(
          entry.severity.toLowerCase(),
        ),
    ) ?? [];

  const securityEventCounts = {
    medium:
      suricataEvents.filter(
        (event) => event.severity.toLowerCase() === "medium",
      ).length +
      snortEvents.filter(
        (event) => event.severity.toLowerCase() === "medium",
      ).length,

    high:
      suricataEvents.filter(
        (event) => event.severity.toLowerCase() === "high",
      ).length +
      snortEvents.filter(
        (event) => event.severity.toLowerCase() === "high",
      ).length,

    critical:
      suricataEvents.filter(
        (event) => event.severity.toLowerCase() === "critical",
      ).length +
      snortEvents.filter(
        (event) => event.severity.toLowerCase() === "critical",
      ).length,
  };

  const totalSecurityEvents =
    securityEventCounts.medium +
    securityEventCounts.high +
    securityEventCounts.critical;

  const [loading, setLoading] = useState(true);
  const [firewallLoading, setFirewallLoading] = useState(true);
  const [apiError, setApiError] = useState(false);
  const [firewallError, setFirewallError] = useState(false);

  const getCsrfToken = async (): Promise<string> => {
    const response = await fetch("/api/auth/csrf/", {
      credentials: "include",
    });

    if (!response.ok) {
      throw new Error("Unable to initialize secure login.");
    }

    const match = document.cookie.match(
      /(?:^|; )csrftoken=([^;]+)/
    );

    if (!match) {
      throw new Error("CSRF token was not provided.");
    }

    return decodeURIComponent(match[1]);
  };

  const checkAuthentication = async () => {
    try {
      const response = await fetch("/api/auth/me/", {
        credentials: "include",
      });

      if (!response.ok) {
        throw new Error("Authentication check failed.");
      }

      const data: AuthResponse = await response.json();

      setAuthenticated(data.authenticated);
      setAuthUser(data.user);
    } catch (error) {
      console.error("Authentication check failed:", error);
      setAuthenticated(false);
      setAuthUser(null);
    }
  };

  const handleLogin = async () => {
    setLoginError("");

    if (!username.trim() || !password) {
      setLoginError("Username and password are required.");
      return;
    }

    setLoginLoading(true);

    try {
      const csrfToken = await getCsrfToken();

      const response = await fetch("/api/auth/login/", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({
          username: username.trim(),
          password,
        }),
      });

      const data: AuthResponse = await response.json();

      if (!response.ok || !data.authenticated) {
        throw new Error("Invalid username or password.");
      }

      setAuthenticated(true);
      setAuthUser(data.user);
      setPassword("");
      setLoginError("");
    } catch (error) {
      console.error("Login failed:", error);
      setAuthenticated(false);
      setAuthUser(null);
      setLoginError(
        error instanceof Error
          ? error.message
          : "Login failed."
      );
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const csrfToken = await getCsrfToken();

      await fetch("/api/auth/logout/", {
        method: "POST",
        credentials: "include",
        headers: {
          "X-CSRFToken": csrfToken,
        },
      });
    } catch (error) {
      console.error("Logout failed:", error);
    } finally {
      setAuthenticated(false);
      setAuthUser(null);
      setPassword("");
      setUsername("");
      setSelected("Dashboard");
    }
  };

  useEffect(() => {
    checkAuthentication();
  }, []);

  const fetchSecurityStatus = async () => {
    try {
      setApiError(false);

      const [servicesResponse, systemResponse] =
        await Promise.all([
          fetch("/api/services/"),
          fetch("/api/system/"),
        ]);

      if (
        !servicesResponse.ok ||
        !systemResponse.ok
      ) {
        throw new Error("API request failed");
      }

      const servicesData: ServicesResponse =
        await servicesResponse.json();

      const systemData: SystemInfo =
        await systemResponse.json();

      setServices(servicesData.services);
      setSystem(systemData);
    } catch (error) {
      console.error("Security API error:", error);
      setApiError(true);
    } finally {
      setLoading(false);
    }
  };

  const fetchFirewall = async () => {
    try {
      setFirewallError(false);

      const response = await fetch("/api/firewall/");

      if (!response.ok) {
        throw new Error("Firewall API request failed");
      }

      const data: FirewallResponse =
        await response.json();

      setFirewall(data);
    } catch (error) {
      console.error("Firewall API error:", error);
      setFirewallError(true);
    } finally {
      setFirewallLoading(false);
    }
  };

  const fetchSuricata = async () => {
    try {
      const response = await fetch("/api/suricata/");

      if (!response.ok) {
        throw new Error("Suricata API request failed");
      }

      const data: SuricataResponse =
        await response.json();

      setSuricata(data);
    } catch (error) {
      console.error("Suricata API error:", error);
    }
  };

  const fetchSuricataRules = async () => {
    try {
      const response = await fetch("/api/suricata/rules/");

      if (!response.ok) {
        throw new Error("Suricata rules API request failed");
      }

      const data: SuricataRulesResponse =
        await response.json();

      setSuricataRules(data.rules);
      setSuricataUpdate(data.update);
    } catch (error) {
      console.error(
        "Suricata rules API error:",
        error,
      );
    }
  };

  const fetchBlockedIps = async () => {
    try {
      const response = await fetch(
        "/api/suricata/blocked-ips/",
      );

      if (!response.ok) {
        throw new Error(
          "Blocked IP API request failed",
        );
      }

      const data: BlockedIpsResponse =
        await response.json();

      setBlockedIps(data);
    } catch (error) {
      console.error(
        "Blocked IP API error:",
        error,
      );

      setBlockedIps(null);
    }
  };

  const fetchBlockDecisions = async () => {
    try {
      const response = await fetch(
        "/api/suricata/block-decisions/",
      );

      if (!response.ok) {
        throw new Error(
          "Block decisions API request failed",
        );
      }

      const data: BlockDecisionsResponse =
        await response.json();

      setBlockDecisions(data);
    } catch (error) {
      console.error(
        "Block decisions API error:",
        error,
      );

      setBlockDecisions(null);
    }
  };

  const unblockIp = async (ip: string) => {
    const confirmed =
      window.confirm(
        `Unblock this IP from the administrator-managed firewall blocklist?\n\n${ip}`,
      );

    if (!confirmed) {
      return;
    }

    try {
      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        `/api/suricata/blocked-ips/${encodeURIComponent(ip)}/`,
        {
          method: "DELETE",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": csrfToken,
          },
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to unblock IP",
        );
      }

      await fetchBlockedIps();
    } catch (err) {
      console.error(
        "Blocked IP unblock error:",
        err,
      );

      window.alert(
        err instanceof Error
          ? err.message
          : "Unable to unblock IP",
      );
    }
  };

  const approveBlockDecision = async (ip: string) => {
    const confirmed =
      window.confirm(
        `Approve blocking this IP?

${ip}

The IP will be added to the administrator-managed firewall blocklist.`,
      );

    if (!confirmed) {
      return;
    }

    try {
      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        `/api/suricata/block-decisions/${encodeURIComponent(ip)}/approve/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": csrfToken,
          },
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to approve block decision",
        );
      }

      await Promise.all([
        fetchBlockedIps(),
        fetchBlockDecisions(),
      ]);
    } catch (err) {
      console.error(
        "Block decision approval error:",
        err,
      );

      window.alert(
        err instanceof Error
          ? err.message
          : "Unable to approve block decision",
      );
    }
  };

  const denyBlockDecision = async (ip: string) => {
    const confirmed =
      window.confirm(
        `Deny blocking this IP?

${ip}

The IP will remain unblocked.`,
      );

    if (!confirmed) {
      return;
    }

    try {
      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        `/api/suricata/block-decisions/${encodeURIComponent(ip)}/deny/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": csrfToken,
          },
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to deny block decision",
        );
      }

      await fetchBlockDecisions();
    } catch (err) {
      console.error(
        "Block decision denial error:",
        err,
      );

      window.alert(
        err instanceof Error
          ? err.message
          : "Unable to deny block decision",
      );
    }
  };


  const loadCustomSnortRules = async () => {
    try {
      const response = await fetch("/api/snort/custom-rules/", {
        credentials: "include",
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      setCustomSnortRules(data);
    } catch (error) {
      console.error("Failed to load Snort custom rules:", error);
    }
  };

  const validateCustomSnortRule = async () => {
    const rule = generatedCustomSnortRule;

    if (!rule) {
      setCustomSnortRuleValidation("Unable to generate a Snort rule.");
      setCustomSnortRuleValid(false);
      return;
    }

    setCustomSnortRuleLoading(true);
    setCustomSnortRuleValidation(null);
    setCustomSnortRuleValid(false);

    try {
      const response = await fetch(
        "/api/snort/custom-rules/validate/",
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken":
              document.cookie
                .split("; ")
                .find((row) => row.startsWith("csrftoken="))
                ?.split("=")[1] || "",
          },
          body: JSON.stringify({ rule }),
        }
      );

      const data = await response.json();

      if (!response.ok || !data.valid) {
        throw new Error(
          data.error ||
            data.message ||
            "Snort rule validation failed."
        );
      }

      setCustomSnortRuleValid(true);
      setCustomSnortRuleValidation(
        data.message || "Snort rule is valid."
      );
    } catch (error: any) {
      setCustomSnortRuleValid(false);
      setCustomSnortRuleValidation(
        error?.message || "Snort rule validation failed."
      );
    } finally {
      setCustomSnortRuleLoading(false);
    }
  };

  const addCustomSnortRule = async () => {
    const rule = generatedCustomSnortRule;

    if (!rule) {
      setCustomSnortRuleValidation("Unable to generate a Snort rule.");
      return;
    }

    setCustomSnortRuleLoading(true);
    setCustomSnortRuleValidation(null);

    try {
      const response = await fetch(
        "/api/snort/custom-rules/",
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken":
              document.cookie
                .split("; ")
                .find((row) => row.startsWith("csrftoken="))
                ?.split("=")[1] || "",
          },
          body: JSON.stringify({ rule }),
        }
      );

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(
          data.error ||
            data.message ||
            "Failed to add Snort rule."
        );
      }

      setCustomSnortRuleValid(false);
      setCustomSnortRuleValidation(
        data.message || "Snort rule added successfully."
      );

      await loadCustomSnortRules();
    } catch (error: any) {
      setCustomSnortRuleValidation(
        error?.message || "Failed to add Snort rule."
      );
    } finally {
      setCustomSnortRuleLoading(false);
    }
  };

  const generateCustomSnortRule = () => {
    const action = customSnortAction.toLowerCase();
    const protocol = customSnortProtocol.toLowerCase();

    const source = customSnortSource.trim() || "any";
    const destination = customSnortDestination.trim() || "any";
    const direction = customSnortDirection;

    const message =
      customSnortMessage.trim() ||
      "Administrator managed Snort rule";

    const existingSids =
      customSnortRules?.rules
        ?.map((item: any) => item.sid)
        .filter(
          (sid: any) =>
            Number.isInteger(sid) &&
            sid >= 1000000 &&
            sid <= 1999999
        ) || [];

    let sid = 1000000;

    while (existingSids.includes(sid) && sid <= 1999999) {
      sid += 1;
    }

    if (sid > 1999999) {
      return "";
    }

    const escapedMessage = message.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

    const options =
      `msg:"${escapedMessage}"; sid:${sid}; rev:1;`;

    if (protocol === "tcp" || protocol === "udp") {
      const sourcePort =
        customSnortSourcePort.trim() || "any";

      const destinationPort =
        customSnortDestinationPort.trim() || "any";

      return `${action} ${protocol} ${source} ${sourcePort} ${direction} ${destination} ${destinationPort} (${options})`;
    }

    return `${action} ${protocol} ${source} any ${direction} ${destination} any (${options})`;
  };

  const generatedCustomSnortRule =
    generateCustomSnortRule();

  const generateCustomSuricataRule = () => {
    const protocol = customSuricataProtocol.toLowerCase();
    const action = customSuricataAction.toLowerCase();

    const source =
      customSuricataSource.trim() || "any";
    const destination =
      customSuricataDestination.trim() || "any";
    const direction = customSuricataDirection;

    const message =
      customSuricataMessage.trim() ||
      "Administrator managed Suricata rule";

    const existingSids =
      customSuricataRules?.rules
        ?.map((item) => item.sid)
        .filter(
          (sid) =>
            Number.isInteger(sid) &&
            sid >= 1000000 &&
            sid <= 1999999,
        ) || [];

    let sid = 1000000;

    while (
      existingSids.includes(sid) &&
      sid <= 1999999
    ) {
      sid += 1;
    }

    if (sid > 1999999) {
      return "";
    }

    const escapedMessage = message.replace(
      /"/g,
      '\\"',
    );

    const options =
      `msg:"${escapedMessage}"; ` +
      `sid:${sid}; rev:1;`;

    if (
      protocol === "tcp" ||
      protocol === "udp"
    ) {
      const sourcePort =
        customSuricataSourcePort.trim() || "any";

      const destinationPort =
        customSuricataDestinationPort.trim() || "any";

      return (
        `${action} ${protocol} ` +
        `${source} ${sourcePort} ` +
        `${direction} ` +
        `${destination} ${destinationPort} ` +
        `(${options})`
      );
    }

    return (
      `${action} ${protocol} ` +
      `${source} ${direction} ` +
      `${destination} ` +
      `(${options})`
    );
  };

  const generatedCustomSuricataRule =
    generateCustomSuricataRule();

  const fetchCustomSuricataRules = async () => {
    try {
      const response = await fetch(
        "/api/suricata/custom-rules/",
        {
          credentials: "same-origin",
        },
      );

      if (!response.ok) {
        throw new Error(
          "Custom Suricata rules API request failed",
        );
      }

      const data: CustomSuricataRulesResponse =
        await response.json();

      setCustomSuricataRules(data);
    } catch (error) {
      console.error(
        "Custom Suricata rules API error:",
        error,
      );

      setCustomSuricataRules(null);
    }
  };

  const validateCustomSuricataRule = async () => {
    const rule = customSuricataRuleText.trim();

    if (!rule) {
      setCustomSuricataRuleValid(false);
      setCustomSuricataRuleValidation(
        "Enter a Suricata rule before validating.",
      );
      return false;
    }

    setCustomSuricataRuleLoading(true);
    setCustomSuricataRuleValidation(null);
    setCustomSuricataRuleValid(null);

    try {
      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        "/api/suricata/custom-rules/validate/",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
          },
          body: JSON.stringify({
            rule,
          }),
        },
      );

      const data = await response.json();

      if (!response.ok) {
        setCustomSuricataRuleValid(false);
        setCustomSuricataRuleValidation(
          data.error ||
            "Suricata rule validation failed.",
        );
        return false;
      }

      setCustomSuricataRuleValid(true);
      setCustomSuricataRuleValidation(
        data.message ||
          "Rule is valid.",
      );

      return true;
    } catch (err) {
      console.error(
        "Custom Suricata rule validation error:",
        err,
      );

      setCustomSuricataRuleValid(false);
      setCustomSuricataRuleValidation(
        err instanceof Error
          ? err.message
          : "Unable to validate Suricata rule.",
      );

      return false;
    } finally {
      setCustomSuricataRuleLoading(false);
    }
  };

  const addCustomSuricataRule = async () => {
    const rule = customSuricataRuleText.trim();

    if (!rule) {
      setCustomSuricataRuleValid(false);
      setCustomSuricataRuleValidation(
        "Enter a Suricata rule before adding it.",
      );
      return;
    }

    const confirmed = window.confirm(
      "Add this custom Suricata rule and reload the IPS?\n\n" +
        rule,
    );

    if (!confirmed) {
      return;
    }

    setCustomSuricataRuleLoading(true);
    setCustomSuricataRuleValidation(null);

    try {
      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        "/api/suricata/custom-rules/",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
          },
          body: JSON.stringify({
            rule,
          }),
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to add custom Suricata rule.",
        );
      }

      setCustomSuricataRuleText("");
      setCustomSuricataRuleValid(null);
      setCustomSuricataRuleValidation(
        data.message ||
          "Custom Suricata rule added successfully.",
      );

      await fetchCustomSuricataRules();
    } catch (err) {
      console.error(
        "Custom Suricata rule add error:",
        err,
      );

      setCustomSuricataRuleValid(false);
      setCustomSuricataRuleValidation(
        err instanceof Error
          ? err.message
          : "Unable to add custom Suricata rule.",
      );
    } finally {
      setCustomSuricataRuleLoading(false);
    }
  };

  const deleteCustomSuricataRule = async (sid: number) => {
    const confirmed = window.confirm(
      `Delete custom Suricata rule SID ${sid}?\n\n` +
        "Suricata will be validated and reloaded after deletion.",
    );

    if (!confirmed) {
      return;
    }

    setCustomSuricataRuleLoading(true);
    setCustomSuricataRuleValidation(null);

    try {
      const csrfToken =
        await getCsrfToken();

      const response = await fetch(
        `/api/suricata/custom-rules/${encodeURIComponent(sid)}/`,
        {
          method: "DELETE",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": csrfToken,
          },
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Unable to delete custom Suricata rule.",
        );
      }

      setCustomSuricataRuleValidation(
        data.message ||
          "Custom Suricata rule deleted successfully.",
      );

      await fetchCustomSuricataRules();
    } catch (err) {
      console.error(
        "Custom Suricata rule delete error:",
        err,
      );

      setCustomSuricataRuleValid(false);
      setCustomSuricataRuleValidation(
        err instanceof Error
          ? err.message
          : "Unable to delete custom Suricata rule.",
      );
    } finally {
      setCustomSuricataRuleLoading(false);
    }
  };

  const fetchSuricataRuleList = async () => {
    setSuricataRuleLoading(true);
    setSuricataRuleError("");

    try {
      const params = new URLSearchParams();

      if (suricataRuleSearch.trim()) {
        params.set(
          "search",
          suricataRuleSearch.trim(),
        );
      }

      if (suricataRuleAction) {
        params.set(
          "action",
          suricataRuleAction,
        );
      }

      if (suricataRuleProtocol) {
        params.set(
          "protocol",
          suricataRuleProtocol,
        );
      }

      params.set(
        "page",
        String(suricataRulePage),
      );

      params.set("limit", "50");

      const response = await fetch(
        `/api/suricata/rules/list/?${params.toString()}`,
      );

      if (!response.ok) {
        throw new Error(
          "Suricata rule-list API request failed",
        );
      }

      const data: SuricataRuleListResponse =
        await response.json();

      if (!data.rules.available) {
        throw new Error(
          data.rules.error ||
            "Suricata rules are unavailable",
        );
      }

      setSuricataRuleList(data.rules.rules);
      setSuricataRuleTotal(
        data.rules.total_matches,
      );
    } catch (error) {
      console.error(
        "Suricata rule-list API error:",
        error,
      );

      setSuricataRuleList([]);
      setSuricataRuleTotal(0);
      setSuricataRuleError(
        error instanceof Error
          ? error.message
          : "Failed to load Suricata rules",
      );
    } finally {
      setSuricataRuleLoading(false);
    }
  };

  const fetchSnort = async () => {
    try {
      const response = await fetch("/api/snort/");

      if (!response.ok) {
        throw new Error("Snort API request failed");
      }

      const data: SnortResponse =
        await response.json();

      setSnort(data);
    } catch (error) {
      console.error("Snort API error:", error);
    }
  };

  const fetchFail2Ban = async () => {
    try {
      const response = await fetch("/api/fail2ban/");

      if (!response.ok) {
        throw new Error("Fail2Ban API request failed");
      }

      const data: Fail2BanResponse =
        await response.json();

      setFail2ban(data);
    } catch (error) {
      console.error("Fail2Ban API error:", error);
    }
  };

  const fail2banTriggerOptions = [
    {
      value: "http-400",
      label: "Bad HTTP requests (400)",
      description:
        "Repeated malformed or invalid HTTP requests.",
      regex: '^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 400',
    },
    {
      value: "http-401",
      label: "Unauthorized requests (401)",
      description:
        "Repeated HTTP requests that require authentication.",
      regex: '^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 401',
    },
    {
      value: "http-403",
      label: "Forbidden requests (403)",
      description:
        "Repeated HTTP requests rejected by access controls.",
      regex: '^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 403',
    },
    {
      value: "http-404",
      label: "Missing page requests (404)",
      description:
        "Repeated requests for resources that do not exist.",
      regex: '^<HOST> - \\S+ \\[[^\\]]*\\] "[^"]*" 404',
    },
  ];

  const fetchFail2BanCustomJails = async () => {
    try {
      const response = await fetch(
        "/api/fail2ban/custom-jails/",
        {
          credentials: "same-origin",
        },
      );

      if (!response.ok) {
        throw new Error(
          "Custom Fail2Ban jails API request failed",
        );
      }

      const data: Fail2BanCustomJailsResponse =
        await response.json();

      setFail2banCustomJails(data);
    } catch (error) {
      console.error(
        "Custom Fail2Ban jails API error:",
        error,
      );
      setFail2banCustomJails(null);
    }
  };

  const validateFail2BanCustomJail = async () => {
    const payload = {
      name: fail2banCustomJailName.trim(),
      logpath: fail2banCustomJailLogpath.trim(),
      trigger: fail2banCustomJailTrigger,
      maxretry:
        fail2banCustomJailMaxretry.trim(),
      findtime:
        fail2banCustomJailFindtime.trim(),
      bantime:
        fail2banCustomJailBantime.trim(),
    };

    if (!payload.name) {
      setFail2banCustomJailValid(false);
      setFail2banCustomJailValidation(
        "Jail name is required.",
      );
      return false;
    }

    setFail2banCustomJailLoading(true);
    setFail2banCustomJailValidation(null);

    try {
      const csrfToken = await getCsrfToken();

      const response = await fetch(
        "/api/fail2ban/custom-jails/validate/",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
          },
          body: JSON.stringify(payload),
        },
      );

      const data = await response.json();

      if (!response.ok) {
        setFail2banCustomJailValid(false);
        setFail2banCustomJailValidation(
          data.error ||
            "Fail2Ban custom jail validation failed.",
        );
        return false;
      }

      setFail2banCustomJailValid(
        data.valid === true,
      );
      setFail2banCustomJailValidation(
        data.valid
          ? data.message ||
              "Custom Fail2Ban jail configuration is valid."
          : data.error ||
              "Custom Fail2Ban jail configuration is invalid.",
      );

      return data.valid === true;
    } catch (error) {
      setFail2banCustomJailValid(false);
      setFail2banCustomJailValidation(
        error instanceof Error
          ? error.message
          : "Fail2Ban validation request failed.",
      );
      return false;
    } finally {
      setFail2banCustomJailLoading(false);
    }
  };

  const addFail2BanCustomJail = async () => {
    const payload = {
      name: fail2banCustomJailName.trim(),
      logpath: fail2banCustomJailLogpath.trim(),
      trigger: fail2banCustomJailTrigger,
      maxretry:
        fail2banCustomJailMaxretry.trim(),
      findtime:
        fail2banCustomJailFindtime.trim(),
      bantime:
        fail2banCustomJailBantime.trim(),
    };

    if (
      !payload.name ||
      !payload.logpath ||
      !payload.trigger
    ) {
      setFail2banCustomJailValid(false);
      setFail2banCustomJailValidation(
        "Jail name, log path, and trigger are required.",
      );
      return;
    }

    const confirmed = window.confirm(
      "Add this custom Fail2Ban jail and reload Fail2Ban?\n\n" +
        `[${payload.name}]`,
    );

    if (!confirmed) {
      return;
    }

    setFail2banCustomJailLoading(true);
    setFail2banCustomJailValidation(null);

    try {
      const csrfToken = await getCsrfToken();

      const response = await fetch(
        "/api/fail2ban/custom-jails/",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
          },
          body: JSON.stringify(payload),
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Failed to add custom Fail2Ban jail.",
        );
      }

      setFail2banCustomJailName("");
      setFail2banCustomJailLogpath("");
      setFail2banCustomJailValid(null);
      setFail2banCustomJailValidation(
        data.message ||
          "Custom Fail2Ban jail added successfully.",
      );

      await fetchFail2BanCustomJails();
      await fetchFail2Ban();
    } catch (error) {
      setFail2banCustomJailValid(false);
      setFail2banCustomJailValidation(
        error instanceof Error
          ? error.message
          : "Failed to add custom Fail2Ban jail.",
      );
    } finally {
      setFail2banCustomJailLoading(false);
    }
  };

  const deleteFail2BanCustomJail = async (
    name: string,
  ) => {
    const confirmed = window.confirm(
      `Delete custom Fail2Ban jail "${name}"?`,
    );

    if (!confirmed) {
      return;
    }

    setFail2banCustomJailLoading(true);
    setFail2banCustomJailValidation(null);

    try {
      const csrfToken = await getCsrfToken();

      const response = await fetch(
        `/api/fail2ban/custom-jails/${encodeURIComponent(name)}/`,
        {
          method: "DELETE",
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": csrfToken,
          },
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            "Failed to delete custom Fail2Ban jail.",
        );
      }

      setFail2banCustomJailValid(true);
      setFail2banCustomJailValidation(
        data.message ||
          "Custom Fail2Ban jail deleted successfully.",
      );

      await fetchFail2BanCustomJails();
      await fetchFail2Ban();
    } catch (error) {
      setFail2banCustomJailValid(false);
      setFail2banCustomJailValidation(
        error instanceof Error
          ? error.message
          : "Failed to delete custom Fail2Ban jail.",
      );
    } finally {
      setFail2banCustomJailLoading(false);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch("/api/logs/?limit=50");

      if (!response.ok) {
        throw new Error("Logs API request failed");
      }

      const data: LogsResponse =
        await response.json();

      setLogs(data);
    } catch (error) {
      console.error("Logs API error:", error);
    }
  };

  useEffect(() => {
    if (authenticated !== true) {
      return;
    }

    fetchSecurityStatus();
    fetchFirewall();
    fetchSuricata();
    fetchSuricataRules();
    fetchBlockedIps();
    fetchBlockDecisions();
    fetchCustomSuricataRules();
    loadCustomSnortRules();
    fetchSnort();
    fetchFail2Ban();
    fetchFail2BanCustomJails();
    fetchLogs();

    const interval = window.setInterval(() => {
      fetchSecurityStatus();
      fetchFirewall();
      fetchSuricata();
      fetchBlockedIps();
      fetchBlockDecisions();
      fetchCustomSuricataRules();
      loadCustomSnortRules();
      fetchSnort();
      fetchFail2Ban();
      fetchFail2BanCustomJails();
      fetchLogs();
    }, 10000);

    return () => window.clearInterval(interval);
  }, [authenticated]);

  useEffect(() => {
    if (authenticated !== true) {
      return;
    }

    fetchSuricataRuleList();
  }, [
    authenticated,
    suricataRuleSearch,
    suricataRuleAction,
    suricataRuleProtocol,
    suricataRulePage,
  ]);

  const getService = (name: string): ServiceStatus => {
    return (
      services.find(
        (service) => service.service === name,
      ) ?? {
        service: name,
        active: false,
        status: "unknown",
      }
    );
  };

  const allServicesActive =
    services.length > 0 &&
    services.every((service) => service.active);

  const drawerContent = (
    <Box>
      <Toolbar
        sx={{
          minHeight: "72px !important",
          px: 2,
        }}
      >
        <RouterIcon
          sx={{
            mr: 1.5,
            color: "primary.main",
          }}
        />

        <Box>
          <Typography
            sx={{
              fontWeight: 800,
              fontSize: 15,
            }}
          >
            HPC SECURITY
          </Typography>

          <Typography
            variant="caption"
            sx={{ color: "text.secondary" }}
          >
            GATEWAY
          </Typography>
        </Box>
      </Toolbar>

      <Divider />

      <List sx={{ px: 1, py: 1 }}>
        {menuItems.map((item) => {
          const isSelected = selected === item.label;

          return (
            <ListItemButton
              key={item.label}
              selected={isSelected}
              onClick={() => {
                setSelected(item.label);
                setMobileOpen(false);
              }}
              sx={{
                borderRadius: 1.5,
                mb: 0.5,

                "&.Mui-selected": {
                  backgroundColor:
                    "rgba(66,165,245,0.14)",
                  color: "primary.main",
                },

                "&.Mui-selected:hover": {
                  backgroundColor:
                    "rgba(66,165,245,0.20)",
                },
              }}
            >
              <ListItemIcon
                sx={{
                  minWidth: 40,
                  color: isSelected
                    ? "primary.main"
                    : "text.secondary",
                }}
              >
                {item.icon}
              </ListItemIcon>

              <ListItemText
                primary={item.label}
                slotProps={{
                  primary: {
                    sx: {
                      fontSize: 14,
                      fontWeight: isSelected
                        ? 600
                        : 400,
                    },
                  },
                }}
              />
            </ListItemButton>
          );
        })}
      </List>
    </Box>
  );

  if (authenticated === null) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box
          sx={{
            minHeight: "100vh",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            backgroundColor: "#0b1220",
          }}
        >
          <CircularProgress />
        </Box>
      </ThemeProvider>
    );
  }

  if (!authenticated) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />

        <Box
          sx={{
            minHeight: "100vh",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            backgroundColor: "#0b1220",
            px: 2,
          }}
        >
          <Paper
            elevation={0}
            sx={{
              width: "100%",
              maxWidth: 430,
              p: 4,
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 3,
              backgroundColor: "#111827",
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                mb: 2,
              }}
            >
              <RouterIcon
                sx={{
                  fontSize: 48,
                  color: "primary.main",
                }}
              />
            </Box>

            <Typography
              variant="h4"
              sx={{
                textAlign: "center",
                fontWeight: 800,
              }}
            >
              HPC SECURITY
            </Typography>

            <Typography
              sx={{
                mt: 0.5,
                mb: 4,
                textAlign: "center",
                color: "text.secondary",
              }}
            >
              Security Gateway
            </Typography>

            <Typography
              variant="h6"
              sx={{
                mb: 2.5,
                fontWeight: 700,
              }}
            >
              Sign in
            </Typography>

            <Stack spacing={2}>
              <TextField
                fullWidth
                label="Username"
                value={username}
                onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
                  setUsername(event.target.value)
                }
                autoComplete="username"
                disabled={loginLoading}
              />

              <TextField
                fullWidth
                label="Password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
                  setPassword(event.target.value)
                }
                onKeyDown={(event: React.KeyboardEvent<HTMLInputElement>) => {
                  if (event.key === "Enter") {
                    handleLogin();
                  }
                }}
                autoComplete="current-password"
                disabled={loginLoading}
                slotProps={{
                  input: {
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() =>
                            setShowPassword(
                              (value) => !value,
                            )
                          }
                          edge="end"
                          disabled={loginLoading}
                          aria-label={
                            showPassword
                              ? "Hide password"
                              : "Show password"
                          }
                        >
                          {showPassword ? (
                            <VisibilityOffIcon />
                          ) : (
                            <VisibilityIcon />
                          )}
                        </IconButton>
                      </InputAdornment>
                    ),
                  },
                }}
              />

              {loginError && (
                <Typography
                  sx={{
                    color: "error.main",
                    fontSize: 14,
                  }}
                >
                  {loginError}
                </Typography>
              )}

              <Box
                component="button"
                type="button"
                onClick={handleLogin}
                disabled={loginLoading}
                sx={{
                  width: "100%",
                  border: 0,
                  borderRadius: 1.5,
                  py: 1.4,
                  backgroundColor: "primary.main",
                  color: "#fff",
                  fontSize: 15,
                  fontWeight: 700,
                  cursor: loginLoading
                    ? "default"
                    : "pointer",
                  opacity: loginLoading ? 0.7 : 1,
                  "&:hover": {
                    backgroundColor: "primary.dark",
                  },
                }}
              >
                {loginLoading
                  ? "Signing in..."
                  : "Sign in"}
              </Box>
            </Stack>

            <Typography
              variant="caption"
              sx={{
                display: "block",
                mt: 3,
                textAlign: "center",
                color: "text.secondary",
              }}
            >
              Authorized access only
            </Typography>
          </Paper>
        </Box>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <Box
        sx={{ display: "none" }}
        aria-hidden="true"
      >
        {authUser?.username}
      </Box>
      <CssBaseline />

      <Box
        sx={{
          display: "flex",
          minHeight: "100vh",
          backgroundColor: "background.default",
        }}
      >
        <AppBar
          position="fixed"
          elevation={0}
          sx={{
            minWidth: 0,
            ml: {
              sm: `${drawerWidth}px`,
            },
            backgroundColor: "#0b1220",
            borderBottom:
              "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <Toolbar
            sx={{
              minHeight: "72px !important",
            }}
          >
            <IconButton
              color="inherit"
              edge="start"
              onClick={() =>
                setMobileOpen(!mobileOpen)
              }
              sx={{
                mr: 2,
                display: {
                  sm: "none",
                },
              }}
            >
              <MenuIcon />
            </IconButton>

            <Box sx={{ flexGrow: 1 }}>
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 700,
                }}
              >
                {selected}
              </Typography>

              <Typography
                variant="caption"
                sx={{
                  color: "text.secondary",
                }}
              >
                Rocky Linux Security Gateway
              </Typography>
            </Box>

            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
              }}
            >
              {authUser && (
                <Typography
                  variant="body2"
                  sx={{
                    color: "text.secondary",
                    display: {
                      xs: "none",
                      md: "block",
                    },
                  }}
                >
                  {authUser.username}
                </Typography>
              )}

              <Box
                component="button"
                type="button"
                onClick={handleLogout}
                sx={{
                  border: "1px solid rgba(255,255,255,0.15)",
                  borderRadius: 1.5,
                  px: 2,
                  py: 0.8,
                  backgroundColor: "transparent",
                  color: "text.primary",
                  fontSize: 13,
                  fontWeight: 700,
                  cursor: "pointer",
                  "&:hover": {
                    backgroundColor:
                      "rgba(255,255,255,0.06)",
                  },
                }}
              >
                Logout
              </Box>
            </Box>

            {loading ? (
              <Chip
                icon={
                  <CircularProgress size={15} />
                }
                label="CHECKING"
                variant="outlined"
                size="small"
              />
            ) : apiError ? (
              <Chip
                icon={<WarningIcon />}
                label="API OFFLINE"
                color="error"
                variant="outlined"
                size="small"
              />
            ) : (
              <Chip
                icon={<CheckCircleIcon />}
                label={
                  allServicesActive
                    ? "SYSTEM READY"
                    : "ATTENTION REQUIRED"
                }
                color={
                  allServicesActive
                    ? "success"
                    : "warning"
                }
                variant="outlined"
                size="small"
              />
            )}
          </Toolbar>
        </AppBar>

        <Box
          component="nav"
          sx={{
            width: {
              sm: drawerWidth,
            },
            flexShrink: {
              sm: 0,
            },
          }}
        >
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={() => setMobileOpen(false)}
            ModalProps={{
              keepMounted: true,
            }}
            sx={{
              display: {
                xs: "block",
                sm: "none",
              },
              "& .MuiDrawer-paper": {
                width: drawerWidth,
                boxSizing: "border-box",
                backgroundColor: "#111827",
              },
            }}
          >
            {drawerContent}
          </Drawer>

          <Drawer
            variant="permanent"
            open
            sx={{
              display: {
                xs: "none",
                sm: "block",
              },
              "& .MuiDrawer-paper": {
                width: drawerWidth,
                boxSizing: "border-box",
                backgroundColor: "#111827",
                borderRight:
                  "1px solid rgba(255,255,255,0.08)",
              },
            }}
          >
            {drawerContent}
          </Drawer>
        </Box>

        <Box
          component="main"
          sx={{
            flexGrow: 1,
            width: {
              sm: `calc(100% - ${drawerWidth}px)`,
            },
            p: {
              xs: 2,
              md: 3,
            },
          }}
        >
          <Toolbar
            sx={{
              minHeight: "72px !important",
            }}
          />

          {selected === "Dashboard" ? (
            <>
              <Box sx={{ mb: 3 }}>
                <Typography
                  variant="h4"
                  sx={{
                    fontWeight: 800,
                  }}
                >
                  Security Overview
                </Typography>

                <Typography
                  sx={{
                    mt: 0.5,
                    color: "text.secondary",
                  }}
                >
                  Live status of the HPC security gateway.
                </Typography>
              </Box>

              {apiError && (
                <Paper
                  elevation={0}
                  sx={{
                    p: 2,
                    mb: 3,
                    border:
                      "1px solid rgba(239,83,80,0.35)",
                    borderRadius: 2,
                    backgroundColor:
                      "rgba(239,83,80,0.08)",
                  }}
                >
                  <Typography
                    sx={{
                      color: "error.main",
                      fontWeight: 600,
                    }}
                  >
                    Security API unavailable
                  </Typography>

                  <Typography
                    variant="body2"
                    sx={{
                      mt: 0.5,
                      color: "text.secondary",
                    }}
                  >
                    The dashboard cannot retrieve live
                    security-control status from Django.
                  </Typography>
                </Paper>
              )}

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    sm: "repeat(2, 1fr)",
                    lg: "repeat(5, 1fr)",
                  },
                  gap: 2,
                  mb: 3,
                }}
              >
                {[
                  [
                    "Firewall",
                    "firewalld",
                    "firewalld / nftables",
                  ],
                  [
                    "Suricata",
                    "suricata",
                    "IPS engine / NFQUEUE",
                  ],
                  [
                    "Snort",
                    "snort",
                    "IDS engine",
                  ],
                  [
                    "Fail2Ban",
                    "fail2ban",
                    "Host-based banning",
                  ],
                  [
                    "Nginx",
                    "nginx",
                    "HTTP / HTTPS service",
                  ],
                ].map(
                  ([title, service, detail]) => {
                    const item = getService(service);

                    return (
                      <StatusCard
                        key={service}
                        title={title}
                        status={
                          loading
                            ? "CHECKING"
                            : item.active
                              ? "ACTIVE"
                              : "DOWN"
                        }
                        detail={detail}
                        active={item.active}
                        icon={
                          item.active ? (
                            <CheckCircleIcon fontSize="large" />
                          ) : (
                            <WarningIcon fontSize="large" />
                          )
                        }
                      />
                    );
                  },
                )}
              </Box>

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    lg: "2fr 1fr",
                  },
                  gap: 2,
                }}
              >
                <Paper
                  elevation={0}
                  sx={{
                    p: 2.5,
                    border:
                      "1px solid rgba(255,255,255,0.08)",
                    borderRadius: 2,
                    backgroundColor: "#111827",
                  }}
                >
                  <Typography
                    variant="h6"
                    sx={{
                      fontWeight: 700,
                    }}
                  >
                    Security Controls
                  </Typography>

                  <Typography
                    variant="body2"
                    sx={{
                      mb: 2,
                      color: "text.secondary",
                    }}
                  >
                    Current enforcement and monitoring
                    components.
                  </Typography>

                  <Stack spacing={1.5}>
                    {[
                      [
                        "firewalld",
                        "Firewall enforcement",
                      ],
                      [
                        "suricata",
                        "Suricata IPS engine",
                      ],
                      [
                        "snort",
                        "Snort IDS engine",
                      ],
                      [
                        "fail2ban",
                        "Host-based banning",
                      ],
                      [
                        "nginx",
                        "HTTP / HTTPS service",
                      ],
                      [
                        "sshd",
                        "Secure administration",
                      ],
                    ].map(
                      ([service, description]) => {
                        const item =
                          getService(service);

                        return (
                          <Box
                            key={service}
                            sx={{
                              display: "flex",
                              alignItems:
                                "center",
                              justifyContent:
                                "space-between",
                              p: 1.5,
                              borderRadius: 1.5,
                              backgroundColor:
                                "rgba(255,255,255,0.025)",
                            }}
                          >
                            <Box>
                              <Typography
                                sx={{
                                  fontWeight: 600,
                                }}
                              >
                                {service}
                              </Typography>

                              <Typography
                                variant="caption"
                                sx={{
                                  color:
                                    "text.secondary",
                                }}
                              >
                                {description}
                              </Typography>
                            </Box>

                            <Chip
                              label={
                                loading
                                  ? "CHECKING"
                                  : item.active
                                    ? "ACTIVE"
                                    : "DOWN"
                              }
                              color={
                                item.active
                                  ? "success"
                                  : "error"
                              }
                              size="small"
                              variant="outlined"
                            />
                          </Box>
                        );
                      },
                    )}
                  </Stack>
                </Paper>

                <Stack spacing={2}>
                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#111827",
                    }}
                  >
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        gap: 2,
                      }}
                    >
                      <MemoryIcon color="primary" />

                      <Box>
                        <Typography
                          variant="body2"
                          sx={{
                            color: "text.secondary",
                          }}
                        >
                          System Resources
                        </Typography>

                        <Typography
                          variant="h6"
                          sx={{
                            fontWeight: 700,
                          }}
                        >
                          {system?.hostname ??
                            "Loading..."}
                        </Typography>
                      </Box>
                    </Box>

                    <Divider sx={{ my: 2 }} />

                    <Typography variant="body2">
                      CPU:{" "}
                      <strong>
                        {system
                          ? `${system.cpu.usage_percent.toFixed(1)}%`
                          : "Checking..."}
                      </strong>
                    </Typography>

                    <Typography
                      variant="body2"
                      sx={{ mt: 1 }}
                    >
                      Memory:{" "}
                      <strong>
                        {system
                          ? `${system.memory.usage_percent.toFixed(1)}%`
                          : "Checking..."}
                      </strong>
                    </Typography>

                    <Typography
                      variant="body2"
                      sx={{ mt: 1 }}
                    >
                      RAM:{" "}
                      <strong>
                        {system
                          ? `${formatBytes(system.memory.used_bytes)} / ${formatBytes(system.memory.total_bytes)}`
                          : "Checking..."}
                      </strong>
                    </Typography>

                    <Typography
                      variant="body2"
                      sx={{ mt: 1 }}
                    >
                      Uptime:{" "}
                      <strong>
                        {system
                          ? formatUptime(
                              system.uptime_seconds,
                            )
                          : "Checking..."}
                      </strong>
                    </Typography>
                  </Paper>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#111827",
                    }}
                  >
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        mb: 2,
                      }}
                    >
                      <Box>
                        <Typography
                          variant="body2"
                          sx={{
                            color: "text.secondary",
                          }}
                        >
                          Security Events
                        </Typography>

                        <Typography
                          variant="h5"
                          sx={{
                            mt: 0.5,
                            fontWeight: 800,
                          }}
                        >
                          {totalSecurityEvents}
                        </Typography>
                      </Box>

                      <Chip
                        label="MEDIUM+"
                        size="small"
                        color="warning"
                        variant="outlined"
                      />
                    </Box>

                    <Stack spacing={1}>
                      <Box
                        sx={{
                          display: "flex",
                          justifyContent: "space-between",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ color: "text.secondary" }}
                        >
                          Medium
                        </Typography>

                        <Typography
                          variant="body2"
                          sx={{ fontWeight: 700 }}
                        >
                          {securityEventCounts.medium}
                        </Typography>
                      </Box>

                      <Box
                        sx={{
                          display: "flex",
                          justifyContent: "space-between",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ color: "text.secondary" }}
                        >
                          High
                        </Typography>

                        <Typography
                          variant="body2"
                          sx={{ fontWeight: 700 }}
                        >
                          {securityEventCounts.high}
                        </Typography>
                      </Box>

                      <Box
                        sx={{
                          display: "flex",
                          justifyContent: "space-between",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ color: "text.secondary" }}
                        >
                          Critical
                        </Typography>

                        <Typography
                          variant="body2"
                          sx={{ fontWeight: 700 }}
                        >
                          {securityEventCounts.critical}
                        </Typography>
                      </Box>
                    </Stack>

                    <Typography
                      variant="caption"
                      sx={{
                        display: "block",
                        mt: 2,
                        color: "text.secondary",
                      }}
                    >
                      Suricata + Snort • High and Critical only
                    </Typography>
                  </Paper>
                </Stack>
              </Box>

              <Paper
                elevation={0}
                sx={{
                  mt: 2,
                  p: 2.5,
                  border:
                    "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 2,
                  backgroundColor: "#111827",
                }}
              >
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    mb: 2,
                  }}
                >
                  <Box>
                    <Typography
                      variant="h6"
                      sx={{ fontWeight: 700 }}
                    >
                      Blocked IPs
                    </Typography>

                    <Typography
                      variant="body2"
                      sx={{
                        mt: 0.5,
                        color: "text.secondary",
                      }}
                    >
                      Administrator-managed firewalld blocklist.
                    </Typography>
                  </Box>

                  <Chip
                    label={
                      blockedIps?.available
                        ? `${blockedIps.count} BLOCKED`
                        : "UNAVAILABLE"
                    }
                    color={
                      blockedIps?.available
                        ? blockedIps.count > 0
                          ? "error"
                          : "success"
                        : "warning"
                    }
                    size="small"
                    variant="outlined"
                  />
                </Box>

                {blockedIps?.available ? (
                  blockedIps.count > 0 ? (
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>IP ADDRESS</TableCell>
                            <TableCell>SOURCE</TableCell>
                            <TableCell>STATUS</TableCell>
                            <TableCell>ACTION</TableCell>
                          </TableRow>
                        </TableHead>

                        <TableBody>
                          {blockedIps.blocked_ips.map((ip) => (
                            <TableRow key={ip}>
                              <TableCell>
                                <Typography
                                  variant="body2"
                                  sx={{
                                    fontFamily:
                                      "monospace",
                                    fontWeight: 600,
                                  }}
                                >
                                  {ip}
                                </Typography>
                              </TableCell>

                              <TableCell>
                                <Chip
                                  label="FIREWALL"
                                  size="small"
                                  variant="outlined"
                                />
                              </TableCell>

                              <TableCell>
                                <Chip
                                  label="BLOCKED"
                                  size="small"
                                  color="error"
                                  variant="outlined"
                                />
                              </TableCell>

                              <TableCell>
                                <Button
                                  size="small"
                                  variant="outlined"
                                  color="warning"
                                  onClick={() => unblockIp(ip)}
                                >
                                  UNBLOCK
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  ) : (
                    <Box
                      sx={{
                        py: 2,
                        textAlign: "center",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        No administrator-managed IPs are
                        currently blocked.
                      </Typography>
                    </Box>
                  )
                ) : (
                  <Typography
                    variant="body2"
                    sx={{ color: "text.secondary" }}
                  >
                    Unable to retrieve the firewalld blocklist.
                  </Typography>
                )}

                <Typography
                  variant="caption"
                  sx={{
                    display: "block",
                    mt: 2,
                    color: "text.secondary",
                  }}
                >
                  firewalld ipset: hpc_blocked_ips
                </Typography>
              </Paper>

              

              <Paper
                elevation={0}
                sx={{
                  mt: 2,
                  p: 2.5,
                  border:
                    "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 2,
                  backgroundColor: "#111827",
                }}
              >
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    mb: 2,
                  }}
                >
                  <Box>
                    <Typography
                      variant="h6"
                      sx={{ fontWeight: 700 }}
                    >
                      Pending Block Decisions
                    </Typography>

                    <Typography
                      variant="body2"
                      sx={{
                        mt: 0.5,
                        color: "text.secondary",
                      }}
                    >
                      Administrator approval is required before
                      a previously unblocked IP can be blocked again.
                    </Typography>
                  </Box>

                  <Chip
                    label={
                      blockDecisions?.available
                        ? `${blockDecisions.count} PENDING`
                        : "UNAVAILABLE"
                    }
                    color={
                      blockDecisions?.available
                        ? blockDecisions.count > 0
                          ? "warning"
                          : "success"
                        : "warning"
                    }
                    size="small"
                    variant="outlined"
                  />
                </Box>

                {blockDecisions?.available ? (
                  blockDecisions.count > 0 ? (
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>IP ADDRESS</TableCell>
                            <TableCell>SOURCE</TableCell>
                            <TableCell>REASON</TableCell>
                            <TableCell>STATUS</TableCell>
                            <TableCell>ACTION</TableCell>
                          </TableRow>
                        </TableHead>

                        <TableBody>
                          {blockDecisions.decisions.map((decision) => (
                            <TableRow key={decision.ip}>
                              <TableCell>
                                <Typography
                                  variant="body2"
                                  sx={{
                                    fontFamily:
                                      "monospace",
                                    fontWeight: 600,
                                  }}
                                >
                                  {decision.ip}
                                </Typography>
                              </TableCell>

                              <TableCell>
                                <Chip
                                  label={decision.source}
                                  size="small"
                                  variant="outlined"
                                />
                              </TableCell>

                              <TableCell>
                                <Typography
                                  variant="body2"
                                  sx={{
                                    maxWidth: 320,
                                    color: "text.secondary",
                                  }}
                                >
                                  {decision.reason || "No reason provided"}
                                </Typography>
                              </TableCell>

                              <TableCell>
                                <Chip
                                  label={decision.decision.toUpperCase()}
                                  size="small"
                                  color="warning"
                                  variant="outlined"
                                />
                              </TableCell>

                              <TableCell>
                                <Stack
                                  direction="row"
                                  spacing={1}
                                >
                                  <Button
                                    size="small"
                                    variant="outlined"
                                    color="error"
                                    onClick={() =>
                                      approveBlockDecision(
                                        decision.ip,
                                      )
                                    }
                                  >
                                    APPROVE
                                  </Button>

                                  <Button
                                    size="small"
                                    variant="outlined"
                                    color="inherit"
                                    onClick={() =>
                                      denyBlockDecision(
                                        decision.ip,
                                      )
                                    }
                                  >
                                    DENY
                                  </Button>
                                </Stack>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  ) : (
                    <Box
                      sx={{
                        py: 2,
                        textAlign: "center",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        No pending administrator decisions.
                      </Typography>
                    </Box>
                  )
                ) : (
                  <Typography
                    variant="body2"
                    sx={{ color: "text.secondary" }}
                  >
                    Unable to retrieve pending block decisions.
                  </Typography>
                )}

                <Typography
                  variant="caption"
                  sx={{
                    display: "block",
                    mt: 2,
                    color: "text.secondary",
                  }}
                >
                  Decisions are persisted in the security database.
                </Typography>
              </Paper>
            </>
          ) : selected === "Firewall" ? (
            <FirewallPage
              firewall={firewall}
              loading={firewallLoading}
              error={firewallError}
            />
          ) : selected === "NAT" ? (
            <NatPage firewall={firewall} />
          ) : selected === "Logs" ? (
            <Paper
              elevation={0}
              sx={{
                p: 4,
                border:
                  "1px solid rgba(255,255,255,0.08)",
                borderRadius: 2,
                backgroundColor: "#111827",
              }}
            >
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  mb: 3,
                }}
              >
                <Box>
                  <Typography
                    variant="h4"
                    sx={{ fontWeight: 800 }}
                  >
                    Security Logs
                  </Typography>

                  <Typography
                    variant="body2"
                    sx={{
                      mt: 0.5,
                      color: "text.secondary",
                    }}
                  >
                    Live security and system events
                  </Typography>
                </Box>

                <Chip
                  label={
                    logs
                      ? "LIVE"
                      : "LOADING"
                  }
                  color={
                    logs
                      ? "success"
                      : "default"
                  }
                  size="small"
                />
              </Box>

              {!logs ? (
                <Typography
                  sx={{ color: "text.secondary" }}
                >
                  Loading security logs...
                </Typography>
              ) : (
                <Stack spacing={3}>
                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    <Typography
                      variant="h6"
                      sx={{
                        fontWeight: 700,
                        mb: 2,
                      }}
                    >
                      Suricata
                    </Typography>

                    {logs.sources.suricata.available &&
                    suricataEvents.length > 0 ? (
                      <Stack spacing={1.5}>
                        {suricataEvents.map(
                          (entry, index) => {
                            if (
                              typeof entry ===
                              "string"
                            ) {
                              return (
                                <Typography
                                  key={index}
                                  variant="body2"
                                >
                                  {entry}
                                </Typography>
                              );
                            }

                            return (
                              <Box
                                key={index}
                                sx={{
                                  p: 1.5,
                                  border:
                                    "1px solid rgba(255,255,255,0.06)",
                                  borderRadius: 1.5,
                                }}
                              >
                                <Stack
                                  direction="row"
                                  spacing={1}
                                  sx={{
                                    mb: 0.5,
                                    flexWrap: "wrap",
                                  }}
                                >
                                  <Chip
                                    label={
                                      entry.severity.toUpperCase()
                                    }
                                    color={
                                      entry.severity ===
                                      "drop"
                                        ? "error"
                                        : "warning"
                                    }
                                    size="small"
                                  />

                                  {entry.protocol && (
                                    <Chip
                                      label={
                                        entry.protocol
                                      }
                                      size="small"
                                      variant="outlined"
                                    />
                                  )}
                                </Stack>

                                <Typography
                                  sx={{
                                    fontWeight: 700,
                                  }}
                                >
                                  {entry.message}
                                </Typography>

                                <Typography
                                  variant="body2"
                                  sx={{
                                    mt: 0.5,
                                    color:
                                      "text.secondary",
                                  }}
                                >
                                  {entry.src_ip ?? "Unknown"}
                                  {entry.src_port
                                    ? `:${entry.src_port}`
                                    : ""}
                                  {" → "}
                                  {entry.dest_ip ??
                                    "Unknown"}
                                  {entry.dest_port
                                    ? `:${entry.dest_port}`
                                    : ""}
                                </Typography>

                                {entry.timestamp && (
                                  <Typography
                                    variant="caption"
                                    sx={{
                                      color:
                                        "text.secondary",
                                    }}
                                  >
                                    {entry.timestamp}
                                  </Typography>
                                )}
                              </Box>
                            );
                          },
                        )}
                      </Stack>
                    ) : (
                      <Typography
                        variant="body2"
                        sx={{
                          color: "text.secondary",
                        }}
                      >
                        No Suricata events available.
                      </Typography>
                    )}
                  </Paper>

                  {[
                    ["SSH", "ssh"],
                    ["Fail2Ban", "fail2ban"],
                    ["firewalld", "firewalld"],
                    ["System", "system"],
                    ["Nginx Access", "nginx_access"],
                    ["Nginx Error", "nginx_error"],
                  ].map(([title, key]) => {
                    const source =
                      logs.sources[
                        key as keyof LogsResponse["sources"]
                      ];

                    return (
                      <Paper
                        key={key}
                        elevation={0}
                        sx={{
                          p: 2.5,
                          border:
                            "1px solid rgba(255,255,255,0.08)",
                          borderRadius: 2,
                          backgroundColor: "#0b1220",
                        }}
                      >
                        <Typography
                          variant="h6"
                          sx={{
                            fontWeight: 700,
                            mb: 2,
                          }}
                        >
                          {title}
                        </Typography>

                        {!source.available ? (
                          <Typography
                            variant="body2"
                            sx={{
                              color: "error.main",
                            }}
                          >
                            Log source unavailable.
                          </Typography>
                        ) : source.lines.length ===
                          0 ? (
                          <Typography
                            variant="body2"
                            sx={{
                              color: "text.secondary",
                            }}
                          >
                            No recent events.
                          </Typography>
                        ) : (
                          <Stack spacing={1}>
                            {source.lines.map(
                              (line, index) => (
                                <Typography
                                  key={index}
                                  variant="body2"
                                  sx={{
                                    fontFamily:
                                      "monospace",
                                    whiteSpace:
                                      "pre-wrap",
                                    wordBreak:
                                      "break-word",
                                  }}
                                >
                                  {typeof line ===
                                  "string"
                                    ? line
                                    : line.message}
                                </Typography>
                              ),
                            )}
                          </Stack>
                        )}
                      </Paper>
                    );
                  })}
                </Stack>
              )}
            </Paper>
          ) : selected === "Suricata IPS" ? (
            <>
            <Paper
              elevation={0}
              sx={{
                p: 4,
                border:
                  "1px solid rgba(255,255,255,0.08)",
                borderRadius: 2,
                backgroundColor: "#111827",
              }}
            >
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: 2,
                }}
              >
                <Box>
                  <Typography
                    variant="h4"
                    sx={{ fontWeight: 800 }}
                  >
                    Suricata IPS
                  </Typography>

                  <Typography
                    sx={{
                      mt: 0.5,
                      color: "text.secondary",
                    }}
                  >
                    Intrusion prevention engine protecting the HPC network boundary
                  </Typography>
                </Box>

                <Chip
                  label={
                    suricata?.service.active
                      ? "ACTIVE"
                      : "INACTIVE"
                  }
                  color={
                    suricata?.service.active
                      ? "success"
                      : "error"
                  }
                  icon={
                    suricata?.service.active
                      ? <CheckCircleIcon />
                      : <WarningIcon />
                  }
                />
              </Box>

              {!suricata ? (
                <Box
                  sx={{
                    mt: 5,
                    textAlign: "center",
                  }}
                >
                  <CircularProgress size={30} />

                  <Typography
                    sx={{
                      mt: 2,
                      color: "text.secondary",
                    }}
                  >
                    Loading Suricata status...
                  </Typography>
                </Box>
              ) : (
                <>
                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(3, 1fr)",
                      },
                      gap: 2,
                      mt: 4,
                    }}
                  >
                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Version
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {suricata.build.version ?? "Unknown"}
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Packets
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {suricata.stats.packets ?? 0}
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Rules Loaded
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {suricata.stats.rules_loaded ?? 0}
                      </Typography>
                    </Paper>
                  </Box>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Engine Capabilities
                  </Typography>

                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{
                      flexWrap: "wrap",
                      gap: 1,
                    }}
                  >
                    <Chip
                      label="AF_PACKET"
                      color={
                        suricata.build.af_packet
                          ? "success"
                          : "error"
                      }
                      variant="outlined"
                    />

                    <Chip
                      label="NFQUEUE"
                      color={
                        suricata.build.nfqueue
                          ? "success"
                          : "error"
                      }
                      variant="outlined"
                    />

                    <Chip
                      label="Unix Socket"
                      color={
                        suricata.build.unix_socket
                          ? "success"
                          : "error"
                      }
                      variant="outlined"
                    />

                    <Chip
                      label={
                        suricata.build.detection
                          ? "Detection Enabled"
                          : "Detection Disabled"
                      }
                      color={
                        suricata.build.detection
                          ? "success"
                          : "error"
                      }
                      variant="outlined"
                    />
                  </Stack>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    IPS Enforcement
                  </Typography>

                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(3, 1fr)",
                      },
                      gap: 2,
                    }}
                  >
                    {[
                      ["Outside Interface", "enp1s0"],
                      ["Protected Interface", "enp2s0"],
                      ["NFQUEUE", "Queue 100"],
                    ].map(([label, value]) => (
                      <Paper
                        key={label}
                        elevation={0}
                        sx={{
                          p: 2.5,
                          border:
                            "1px solid rgba(255,255,255,0.08)",
                          borderRadius: 2,
                          backgroundColor: "#0b1220",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ color: "text.secondary" }}
                        >
                          {label}
                        </Typography>

                        <Typography
                          variant="h6"
                          sx={{
                            mt: 0.5,
                            fontWeight: 800,
                          }}
                        >
                          {value}
                        </Typography>
                      </Paper>
                    ))}
                  </Box>

                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{
                      mt: 2,
                      flexWrap: "wrap",
                      gap: 1,
                    }}
                  >
                    <Chip
                      label="Outside → Protected: IPS Enforced"
                      color="success"
                      variant="outlined"
                    />

                    <Chip
                      label="Protected → Outside: Observation / Normal Forwarding"
                      color="info"
                      variant="outlined"
                    />
                  </Stack>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Traffic Statistics
                  </Typography>

                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: {
                        xs: "1fr 1fr",
                        sm: "repeat(4, 1fr)",
                      },
                      gap: 2,
                    }}
                  >
                    {[
                      ["Accepted", suricata.stats.accepted],
                      ["IPS Blocks", suricata.stats.signature_drops],
                      ["Flow Drops", suricata.stats.flow_drops],
                      ["Rejected", suricata.stats.rejected],
                      ["NFQUEUE Errors", suricata.stats.nfq_errors],
                      ["Midstream", suricata.stats.stream_midstream],
                      ["Bytes", suricata.stats.bytes],
                    ].map(([label, value]) => (
                      <Paper
                        key={label}
                        elevation={0}
                        sx={{
                          p: 2,
                          border:
                            "1px solid rgba(255,255,255,0.08)",
                          borderRadius: 2,
                          backgroundColor: "#0b1220",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ color: "text.secondary" }}
                        >
                          {label}
                        </Typography>

                        <Typography
                          variant="h6"
                          sx={{
                            mt: 0.5,
                            fontWeight: 800,
                          }}
                        >
                          {value ?? 0}
                        </Typography>
                      </Paper>
                    ))}
                  </Box>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Ruleset Inventory
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    {!suricataRules ? (
                      <Typography
                        sx={{
                          color: "text.secondary",
                        }}
                      >
                        Loading ruleset inventory...
                      </Typography>
                    ) : suricataRules.error ? (
                      <Typography color="error">
                        {suricataRules.error}
                      </Typography>
                    ) : (
                      <>
                        <Box
                          sx={{
                            display: "grid",
                            gridTemplateColumns: {
                              xs: "1fr 1fr",
                              sm: "repeat(4, 1fr)",
                            },
                            gap: 2,
                          }}
                        >
                          {[
                            [
                              "Total Active",
                              suricataRules.total_rules,
                            ],
                            [
                              "Alert",
                              suricataRules.alert_rules,
                            ],
                            [
                              "Drop",
                              suricataRules.drop_rules,
                            ],
                            [
                              "Reject",
                              suricataRules.reject_rules,
                            ],
                          ].map(([label, value]) => (
                            <Box key={label}>
                              <Typography
                                variant="body2"
                                sx={{
                                  color: "text.secondary",
                                }}
                              >
                                {label}
                              </Typography>

                              <Typography
                                variant="h6"
                                sx={{
                                  mt: 0.5,
                                  fontWeight: 800,
                                }}
                              >
                                {value}
                              </Typography>
                            </Box>
                          ))}
                        </Box>

                        <Divider sx={{ my: 2.5 }} />

                        <Box
                          sx={{
                            display: "grid",
                            gridTemplateColumns: {
                              xs: "1fr",
                              sm: "repeat(3, 1fr)",
                            },
                            gap: 2,
                          }}
                        >
                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Disabled / Commented
                            </Typography>

                            <Typography
                              sx={{
                                mt: 0.5,
                                fontWeight: 700,
                              }}
                            >
                              {suricataRules.disabled_rules}
                            </Typography>
                          </Box>

                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Ruleset Size
                            </Typography>

                            <Typography
                              sx={{
                                mt: 0.5,
                                fontWeight: 700,
                              }}
                            >
                              {suricataRules.file_size !== null
                                ? `${(
                                    suricataRules.file_size /
                                    (1024 * 1024)
                                  ).toFixed(1)} MiB`
                                : "Unknown"}
                            </Typography>
                          </Box>

                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Last Modified
                            </Typography>

                            <Typography
                              sx={{
                                mt: 0.5,
                                fontWeight: 700,
                                wordBreak: "break-word",
                              }}
                            >
                              {suricataRules.modified ??
                                "Unknown"}
                            </Typography>
                          </Box>
                        </Box>

                        <Typography
                          variant="caption"
                          sx={{
                            display: "block",
                            mt: 2,
                            color: "text.secondary",
                            wordBreak: "break-all",
                          }}
                        >
                          {suricataRules.path}
                        </Typography>
                      </>
                    )}
                  </Paper>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Ruleset Update & Policy
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    {!suricataUpdate ? (
                      <Typography
                        sx={{
                          color: "text.secondary",
                        }}
                      >
                        Loading update status...
                      </Typography>
                    ) : (
                      <>
                        <Box
                          sx={{
                            display: "grid",
                            gridTemplateColumns: {
                              xs: "1fr",
                              sm: "repeat(3, 1fr)",
                            },
                            gap: 2,
                          }}
                        >
                          {[
                            [
                              "Rule Source",
                              suricataUpdate.source,
                            ],
                            [
                              "Managed DROP Rules",
                              suricataUpdate.managed_drop_rules,
                            ],
                            [
                              "Total DROP Rules",
                              suricataUpdate.total_drop_rules,
                            ],
                            [
                              "Automatic Updates",
                              suricataUpdate.automatic_update.toUpperCase(),
                            ],
                            [
                              "Last Successful Update",
                              suricataUpdate.last_update ?? "Unknown",
                            ],
                            [
                              "Validation",
                              suricataUpdate.validation.toUpperCase(),
                            ],
                          ].map(([label, value]) => (
                            <Box key={label}>
                              <Typography
                                variant="body2"
                                sx={{
                                  color: "text.secondary",
                                }}
                              >
                                {label}
                              </Typography>

                              <Typography
                                sx={{
                                  mt: 0.5,
                                  fontWeight: 700,
                                }}
                              >
                                {value}
                              </Typography>
                            </Box>
                          ))}
                        </Box>

                        <Divider sx={{ my: 2.5 }} />

                        <Stack
                          direction="row"
                          spacing={1}
                          sx={{
                            flexWrap: "wrap",
                            gap: 1,
                          }}
                        >
                          <Chip
                            label="ET Open"
                            color="success"
                            variant="outlined"
                          />

                          <Chip
                            label={`Managed DROP: ${suricataUpdate.managed_drop_rules}`}
                            color="warning"
                            variant="outlined"
                          />

                          <Chip
                            label={`Total DROP: ${suricataUpdate.total_drop_rules}`}
                            color="warning"
                            variant="outlined"
                          />

                          <Chip
                            label={
                              suricataUpdate.reload === "successful"
                                ? "Reload Successful"
                                : `Reload: ${suricataUpdate.reload}`
                            }
                            color={
                              suricataUpdate.reload === "successful"
                                ? "success"
                                : "error"
                            }
                            variant="outlined"
                          />
                        </Stack>

                        {suricataUpdate.error && (
                          <Typography
                            sx={{
                              mt: 2,
                              color: "error.main",
                            }}
                          >
                            {suricataUpdate.error}
                          </Typography>
                        )}
                      </>
                    )}
                  </Paper>

                  <Paper
                    elevation={0}
                    sx={{
                      mt: 2,
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: 2,
                      }}
                    >
                      <Box>
                        <Typography
                          variant="subtitle1"
                          sx={{ fontWeight: 700 }}
                        >
                          Ruleset Synchronization
                        </Typography>

                        <Typography
                          variant="body2"
                          sx={{
                            mt: 0.5,
                            color: "text.secondary",
                          }}
                        >
                          Runtime loaded rules compared with
                          the active rules file.
                        </Typography>
                      </Box>

                      <Chip
                        icon={
                          suricataRulesSynchronized ? (
                            <CheckCircleIcon />
                          ) : (
                            <WarningIcon />
                          )
                        }
                        label={
                          suricataRulesSynchronized
                            ? "SYNCHRONIZED"
                            : "MISMATCH"
                        }
                        color={
                          suricataRulesSynchronized
                            ? "success"
                            : "warning"
                        }
                        variant="outlined"
                      />
                    </Box>

                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: {
                          xs: "1fr",
                          sm: "1fr 1fr",
                        },
                        gap: 2,
                        mt: 2,
                      }}
                    >
                      <Box>
                        <Typography
                          variant="body2"
                          sx={{
                            color: "text.secondary",
                          }}
                        >
                          Suricata Runtime
                        </Typography>

                        <Typography
                          variant="h6"
                          sx={{
                            mt: 0.5,
                            fontWeight: 800,
                          }}
                        >
                          {suricata?.stats.rules_loaded ?? "Unknown"}
                        </Typography>
                      </Box>

                      <Box>
                        <Typography
                          variant="body2"
                          sx={{
                            color: "text.secondary",
                          }}
                        >
                          Rules File
                        </Typography>

                        <Typography
                          variant="h6"
                          sx={{
                            mt: 0.5,
                            fontWeight: 800,
                          }}
                        >
                          {suricataRules?.total_rules ?? "Unknown"}
                        </Typography>
                      </Box>
                    </Box>
                  </Paper>

                  <Paper
                    elevation={0}
                    sx={{
                      mt: 2,
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: 2,
                        mb: 2,
                      }}
                    >
                      <Box>
                        <Typography
                          variant="subtitle1"
                          sx={{ fontWeight: 700 }}
                        >
                          Suricata Rules
                        </Typography>

                        <Typography
                          variant="body2"
                          sx={{
                            mt: 0.5,
                            color: "text.secondary",
                          }}
                        >
                          Active rules loaded from the configured
                          Suricata ruleset.
                        </Typography>

                        <Box
                          sx={{
                            mt: 2,
                            display: "flex",
                            alignItems: "center",
                            gap: 1,
                            flexWrap: "wrap",
                          }}
                        >
                          <Button
                            variant="contained"
                            size="small"
                            onClick={() =>
                              setCustomSuricataRuleDialogOpen(true)
                            }
                          >
                            Add Custom Rule
                          </Button>

                          <Chip
                            label={`Custom rules: ${
                              customSuricataRules?.count ?? 0
                            }`}
                            size="small"
                            variant="outlined"
                          />
                        </Box>
                      </Box>

                      {customSuricataRules?.rules &&
                        customSuricataRules.rules.length > 0 && (
                          <Box
                            sx={{
                              mb: 2.5,
                              p: 2,
                              border:
                                "1px solid rgba(255,255,255,0.08)",
                              borderRadius: 2,
                              backgroundColor: "#111827",
                            }}
                          >
                            <Typography
                              variant="subtitle2"
                              sx={{
                                mb: 1.5,
                                fontWeight: 700,
                              }}
                            >
                              Installed Custom Rules
                            </Typography>

                            <Stack spacing={1}>
                              {customSuricataRules.rules.map(
                                (customRule) => (
                                  <Box
                                    key={customRule.sid}
                                    sx={{
                                      display: "flex",
                                      alignItems: "center",
                                      gap: 1.5,
                                      justifyContent:
                                        "space-between",
                                      flexWrap: "wrap",
                                    }}
                                  >
                                    <Box
                                      sx={{
                                        minWidth: 0,
                                        flex: 1,
                                      }}
                                    >
                                      <Typography
                                        variant="caption"
                                        sx={{
                                          color: "text.secondary",
                                          fontWeight: 700,
                                        }}
                                      >
                                        SID {customRule.sid}
                                      </Typography>

                                      <Typography
                                        variant="body2"
                                        sx={{
                                          mt: 0.25,
                                          fontFamily:
                                            "monospace",
                                          wordBreak:
                                            "break-word",
                                        }}
                                      >
                                        {customRule.rule}
                                      </Typography>
                                    </Box>

                                    <Button
                                      size="small"
                                      color="error"
                                      variant="outlined"
                                      disabled={
                                        customSuricataRuleLoading
                                      }
                                      onClick={() =>
                                        deleteCustomSuricataRule(
                                          customRule.sid,
                                        )
                                      }
                                    >
                                      Delete
                                    </Button>
                                  </Box>
                                ),
                              )}
                            </Stack>
                          </Box>
                        )}

                      <Chip
                        label={`${suricataRuleTotal.toLocaleString()} matches`}
                        variant="outlined"
                      />
                    </Box>

                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: {
                          xs: "1fr",
                          sm: "2fr 1fr 1fr auto",
                        },
                        gap: 2,
                        mb: 2.5,
                      }}
                    >
                      <TextField
                        label="Search rules"
                        placeholder="Message, SID, source, destination..."
                        size="small"
                        value={suricataRuleSearch}
                        onChange={(event) => {
                          setSuricataRuleSearch(
                            event.target.value,
                          );
                          setSuricataRulePage(1);
                        }}
                        fullWidth
                      />

                      <TextField
                        select
                        label="Action"
                        size="small"
                        value={suricataRuleAction}
                        onChange={(event) => {
                          setSuricataRuleAction(
                            event.target.value,
                          );
                          setSuricataRulePage(1);
                        }}
                        fullWidth
                      >
                        <MenuItem value="">
                          All actions
                        </MenuItem>

                        <MenuItem value="alert">
                          Alert
                        </MenuItem>

                        <MenuItem value="drop">
                          Drop
                        </MenuItem>

                        <MenuItem value="reject">
                          Reject
                        </MenuItem>
                      </TextField>

                      <TextField
                        select
                        label="Protocol"
                        size="small"
                        value={suricataRuleProtocol}
                        onChange={(event) => {
                          setSuricataRuleProtocol(
                            event.target.value,
                          );
                          setSuricataRulePage(1);
                        }}
                        fullWidth
                      >
                        <MenuItem value="">
                          All protocols
                        </MenuItem>

                        <MenuItem value="ip">
                          IP
                        </MenuItem>

                        <MenuItem value="tcp">
                          TCP
                        </MenuItem>

                        <MenuItem value="udp">
                          UDP
                        </MenuItem>

                        <MenuItem value="icmp">
                          ICMP
                        </MenuItem>

                        <MenuItem value="icmpv6">
                          ICMPv6
                        </MenuItem>

                        <MenuItem value="http">
                          HTTP
                        </MenuItem>

                        <MenuItem value="tls">
                          TLS
                        </MenuItem>

                        <MenuItem value="dns">
                          DNS
                        </MenuItem>
                      </TextField>

                      <Button
                        variant="outlined"
                        onClick={() => {
                          setSuricataRuleSearch("");
                          setSuricataRuleAction("");
                          setSuricataRuleProtocol("");
                          setSuricataRulePage(1);
                        }}
                        sx={{
                          minWidth: 110,
                          height: 40,
                          alignSelf: "center",
                        }}
                      >
                        Reset
                      </Button>
                    </Box>

                    {suricataRuleLoading ? (
                      <Box
                        sx={{
                          minHeight: 240,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexDirection: "column",
                          gap: 2,
                        }}
                      >
                        <CircularProgress size={30} />

                        <Typography
                          variant="body2"
                          sx={{
                            color: "text.secondary",
                          }}
                        >
                          Loading Suricata rules...
                        </Typography>
                      </Box>
                    ) : suricataRuleError ? (
                      <Box
                        sx={{
                          p: 3,
                          textAlign: "center",
                        }}
                      >
                        <Typography
                          color="error"
                          variant="body2"
                        >
                          {suricataRuleError}
                        </Typography>
                      </Box>
                    ) : suricataRuleList.length === 0 ? (
                      <Box
                        sx={{
                          p: 4,
                          textAlign: "center",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{
                            color: "text.secondary",
                          }}
                        >
                          No matching Suricata rules found.
                        </Typography>
                      </Box>
                    ) : (
                      <>
                        <TableContainer
                          sx={{
                            maxHeight: 620,
                            border:
                              "1px solid rgba(255,255,255,0.08)",
                            borderRadius: 1,
                          }}
                        >
                          <Table
                            size="small"
                            stickyHeader
                          >
                            <TableHead>
                              <TableRow>
                                <TableCell>
                                  SID
                                </TableCell>

                                <TableCell>
                                  Action
                                </TableCell>

                                <TableCell>
                                  Protocol
                                </TableCell>

                                <TableCell>
                                  Source
                                </TableCell>

                                <TableCell>
                                  Destination
                                </TableCell>

                                <TableCell>
                                  Message
                                </TableCell>

                                <TableCell>
                                  Rev
                                </TableCell>
                              </TableRow>
                            </TableHead>

                            <TableBody>
                              {suricataRuleList.map(
                                (rule) => (
                                  <TableRow
                                    key={`${rule.sid ?? "no-sid"}-${rule.line}`}
                                    hover
                                  >
                                    <TableCell
                                      sx={{
                                        fontFamily:
                                          "monospace",
                                        whiteSpace:
                                          "nowrap",
                                      }}
                                    >
                                      {rule.sid ?? "—"}
                                    </TableCell>

                                    <TableCell>
                                      <Chip
                                        label={rule.action.toUpperCase()}
                                        size="small"
                                        color={
                                          rule.action ===
                                          "drop"
                                            ? "error"
                                            : rule.action ===
                                                "reject"
                                              ? "warning"
                                              : "default"
                                        }
                                        variant="outlined"
                                      />
                                    </TableCell>

                                    <TableCell>
                                      {rule.protocol.toUpperCase()}
                                    </TableCell>

                                    <TableCell
                                      sx={{
                                        minWidth: 180,
                                        fontFamily:
                                          "monospace",
                                      }}
                                    >
                                      {rule.source}
                                      {" "}
                                      {rule.source_port}
                                    </TableCell>

                                    <TableCell
                                      sx={{
                                        minWidth: 180,
                                        fontFamily:
                                          "monospace",
                                      }}
                                    >
                                      {rule.destination}
                                      {" "}
                                      {rule.destination_port}
                                    </TableCell>

                                    <TableCell
                                      sx={{
                                        minWidth: 320,
                                        maxWidth: 520,
                                      }}
                                    >
                                      <Typography
                                        variant="body2"
                                        sx={{
                                          overflow:
                                            "hidden",
                                          textOverflow:
                                            "ellipsis",
                                          display:
                                            "-webkit-box",
                                          WebkitLineClamp: 2,
                                          WebkitBoxOrient:
                                            "vertical",
                                        }}
                                      >
                                        {rule.message ??
                                          "No message"}
                                      </Typography>
                                    </TableCell>

                                    <TableCell>
                                      {rule.rev ?? "—"}
                                    </TableCell>
                                  </TableRow>
                                ),
                              )}
                            </TableBody>
                          </Table>
                        </TableContainer>

                        <Box
                          sx={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            flexWrap: "wrap",
                            gap: 2,
                            mt: 2,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{
                              color: "text.secondary",
                            }}
                          >
                            Showing{" "}
                            {(
                              (suricataRulePage - 1) *
                                50 +
                              1
                            ).toLocaleString()}{" "}
                           –{" "}
                            {Math.min(
                              suricataRulePage * 50,
                              suricataRuleTotal,
                            ).toLocaleString()}{" "}
                            of{" "}
                            {suricataRuleTotal.toLocaleString()}
                          </Typography>

                          <Pagination
                            count={Math.max(
                              1,
                              Math.ceil(
                                suricataRuleTotal / 50,
                              ),
                            )}
                            page={suricataRulePage}
                            onChange={(_, page) => {
                              setSuricataRulePage(page);
                            }}
                            color="primary"
                            size="small"
                            showFirstButton
                            showLastButton
                          />
                        </Box>
                      </>
                    )}
                  </Paper>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Recent Alerts
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    {suricata.alerts.lines.length === 0 ? (
                      <Typography
                        sx={{
                          color: "text.secondary",
                        }}
                      >
                        No recent alert events returned by
                        the Suricata API.
                      </Typography>
                    ) : (
                      <Stack spacing={1.5}>
                        {suricata.alerts.lines.map(
                          (alert, index) => (
                            <Box key={index}>
                              <Typography
                                sx={{ fontWeight: 700 }}
                              >
                                {alert.message ||
                                  "Unknown signature"}
                              </Typography>

                              <Typography
                                variant="body2"
                                sx={{
                                  color: "text.secondary",
                                }}
                              >
                                {alert.src_ip ?? "Unknown"}
                                {" → "}
                                {alert.dest_ip ?? "Unknown"}
                              </Typography>
                            </Box>
                          ),
                        )}
                      </Stack>
                    )}
                  </Paper>

                  <Typography
                    variant="body2"
                    sx={{
                      mt: 3,
                      color: "text.secondary",
                    }}
                  >
                    Suricata data refreshes every 10 seconds.
                  </Typography>

                </>
              )}
            </Paper>
          <Dialog
            open={customSuricataRuleDialogOpen}
            onClose={() =>
              setCustomSuricataRuleDialogOpen(false)
            }
            fullWidth
            maxWidth="md"
          >
            <DialogTitle>
              Add Custom Suricata Rule
            </DialogTitle>

            <DialogContent dividers>
              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    sm: "1fr 1fr",
                  },
                  gap: 2,
                  pt: 1,
                }}
              >
                <TextField
                  select
                  label="Action"
                  value={customSuricataAction}
                  onChange={(event) =>
                    setCustomSuricataAction(event.target.value)
                  }
                  fullWidth
                >
                  <MenuItem value="drop">Drop</MenuItem>
                  <MenuItem value="alert">Alert</MenuItem>
                  <MenuItem value="reject">Reject</MenuItem>
                </TextField>

                <TextField
                  select
                  label="Protocol"
                  value={customSuricataProtocol}
                  onChange={(event) =>
                    setCustomSuricataProtocol(event.target.value)
                  }
                  fullWidth
                >
                  <MenuItem value="tcp">TCP</MenuItem>
                  <MenuItem value="udp">UDP</MenuItem>
                  <MenuItem value="icmp">ICMP</MenuItem>
                  <MenuItem value="ip">IP</MenuItem>
                </TextField>

                <TextField
                  select
                  label="Source Address"
                  value={customSuricataSource}
                  onChange={(event) =>
                    setCustomSuricataSource(event.target.value)
                  }
                  fullWidth
                >
                  <MenuItem value="any">Any</MenuItem>
                  <MenuItem value="$EXTERNAL_NET">
                    $EXTERNAL_NET
                  </MenuItem>
                  <MenuItem value="$HOME_NET">
                    $HOME_NET
                  </MenuItem>
                </TextField>

                <TextField
                  label="Source Port"
                  value={customSuricataSourcePort}
                  onChange={(event) =>
                    setCustomSuricataSourcePort(event.target.value)
                  }
                  disabled={
                    customSuricataProtocol === "icmp" ||
                    customSuricataProtocol === "ip"
                  }
                  placeholder="any, 22, 80, 8000:9000"
                  fullWidth
                />

                <TextField
                  select
                  label="Direction"
                  value={customSuricataDirection}
                  onChange={(event) =>
                    setCustomSuricataDirection(event.target.value)
                  }
                  fullWidth
                >
                  <MenuItem value="->">→</MenuItem>
                  <MenuItem value="<>">↔</MenuItem>
                </TextField>

                <TextField
                  select
                  label="Destination Address"
                  value={customSuricataDestination}
                  onChange={(event) =>
                    setCustomSuricataDestination(event.target.value)
                  }
                  fullWidth
                >
                  <MenuItem value="any">Any</MenuItem>
                  <MenuItem value="$HOME_NET">
                    $HOME_NET
                  </MenuItem>
                  <MenuItem value="$EXTERNAL_NET">
                    $EXTERNAL_NET
                  </MenuItem>
                </TextField>

                <TextField
                  label="Destination Port"
                  value={customSuricataDestinationPort}
                  onChange={(event) =>
                    setCustomSuricataDestinationPort(event.target.value)
                  }
                  disabled={
                    customSuricataProtocol === "icmp" ||
                    customSuricataProtocol === "ip"
                  }
                  placeholder="any, 22, 443, 8000:9000"
                  fullWidth
                />

                <TextField
                  label="Message"
                  value={customSuricataMessage}
                  onChange={(event) =>
                    setCustomSuricataMessage(event.target.value)
                  }
                  placeholder="Describe what this rule detects"
                  fullWidth
                />

                <Box
                  sx={{
                    gridColumn: {
                      xs: "1",
                      sm: "1 / -1",
                    },
                  }}
                >
                  <Typography
                    variant="subtitle2"
                    sx={{
                      mb: 1,
                      fontWeight: 700,
                    }}
                  >
                    Generated Rule
                  </Typography>

                  <TextField
                    multiline
                    minRows={3}
                    value={
                      generatedCustomSuricataRule ||
                      "No available SID."
                    }
                    slotProps={{
                      htmlInput: {
                        readOnly: true,
                      },
                    }}
                    fullWidth
                  />

                  <Typography
                    variant="caption"
                    sx={{
                      display: "block",
                      mt: 1,
                      color: "text.secondary",
                    }}
                  >
                    SID is automatically selected from
                    1000000–1999999.
                  </Typography>
                </Box>

                {customSuricataRuleValidation && (
                  <Typography
                    variant="body2"
                    sx={{
                      gridColumn: {
                        xs: "1",
                        sm: "1 / -1",
                      },
                      color: customSuricataRuleValid
                        ? "success.main"
                        : "error.main",
                    }}
                  >
                    {customSuricataRuleValidation}
                  </Typography>
                )}
              </Box>
            </DialogContent>

            <DialogActions>
              <Button
                onClick={() =>
                  setCustomSuricataRuleDialogOpen(false)
                }
              >
                Cancel
              </Button>

              <Button
                variant="outlined"
                disabled={
                  customSuricataRuleLoading ||
                  !generatedCustomSuricataRule
                }
                onClick={validateCustomSuricataRule}
              >
                Validate
              </Button>

              <Button
                variant="contained"
                disabled={
                  customSuricataRuleLoading ||
                  !generatedCustomSuricataRule
                }
                onClick={addCustomSuricataRule}
              >
                Add Rule
              </Button>
            </DialogActions>
          </Dialog>

            </>
          ) : selected === "Snort" ? (
            <Paper
              elevation={0}
              sx={{
                p: 4,
                border:
                  "1px solid rgba(255,255,255,0.08)",
                borderRadius: 2,
                backgroundColor: "#111827",
              }}
            >
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: 2,
                }}
              >
                <Box>
                  <Typography
                    variant="h4"
                    sx={{ fontWeight: 800 }}
                  >
                    Snort
                  </Typography>

                  <Typography
                    sx={{
                      mt: 0.5,
                      color: "text.secondary",
                    }}
                  >
                    Intrusion detection engine • Passive monitoring
                  </Typography>
                </Box>

                <Chip
                  label={
                    snort?.service.active
                      ? "ACTIVE"
                      : "INACTIVE"
                  }
                  color={
                    snort?.service.active
                      ? "success"
                      : "error"
                  }
                  icon={
                    snort?.service.active ? (
                      <CheckCircleIcon />
                    ) : (
                      <WarningIcon />
                    )
                  }
                />
              </Box>

              {!snort ? (
                <Box
                  sx={{
                    mt: 5,
                    textAlign: "center",
                  }}
                >
                  <CircularProgress size={30} />

                  <Typography
                    sx={{
                      mt: 2,
                      color: "text.secondary",
                    }}
                  >
                    Loading Snort status...
                  </Typography>
                </Box>
              ) : (
                <>
                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(4, 1fr)",
                      },
                      gap: 2,
                      mt: 4,
                    }}
                  >
                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Engine
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        Snort 3
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Alerts
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {snort.alerts.lines.length}
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Interface
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {snort.alerts.lines[0]?.interface ??
                          "enp1s0"}
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Alert Source
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                          fontSize: "1rem",
                        }}
                      >
                        alert_json.txt
                      </Typography>
                    </Paper>
                  </Box>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Alert Summary
                  </Typography>

                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(3, 1fr)",
                      },
                      gap: 2,
                    }}
                  >
                    {[
                      [
                        "High",
                        snort.alerts.lines.filter(
                          (event) =>
                            event.severity.toLowerCase() ===
                            "high",
                        ).length,
                      ],
                      [
                        "Critical",
                        snort.alerts.lines.filter(
                          (event) =>
                            event.severity.toLowerCase() ===
                            "critical",
                        ).length,
                      ],
                    ].map(([label, count]) => (
                      <Paper
                        key={label}
                        elevation={0}
                        sx={{
                          p: 2.5,
                          border:
                            "1px solid rgba(255,255,255,0.08)",
                          borderRadius: 2,
                          backgroundColor: "#0b1220",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ color: "text.secondary" }}
                        >
                          {label}
                        </Typography>

                        <Typography
                          variant="h5"
                          sx={{
                            mt: 0.5,
                            fontWeight: 800,
                          }}
                        >
                          {count}
                        </Typography>
                      </Paper>
                    ))}
                  </Box>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Recent Alerts
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    {!snort.alerts.available ? (
                      <Typography
                        sx={{ color: "error.main" }}
                      >
                        {snort.alerts.error ??
                          "Snort alert data unavailable."}
                      </Typography>
                    ) : snort.alerts.lines.length === 0 ? (
                      <Typography
                        sx={{ color: "text.secondary" }}
                      >
                        No recent Snort alerts.
                      </Typography>
                    ) : (
                      <Stack spacing={1.5}>
                        {snort.alerts.lines.map(
                          (alert, index) => {
                            const severity =
                              alert.severity.toLowerCase();

                            return (
                              <Box
                                key={`${alert.sid ?? "unknown"}-${index}`}
                                sx={{
                                  p: 2,
                                  borderRadius: 1.5,
                                  backgroundColor:
                                    "rgba(255,255,255,0.025)",
                                  border:
                                    "1px solid rgba(255,255,255,0.06)",
                                }}
                              >
                                <Box
                                  sx={{
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent:
                                      "space-between",
                                    gap: 2,
                                    flexWrap: "wrap",
                                  }}
                                >
                                  <Typography
                                    sx={{
                                      fontWeight: 700,
                                    }}
                                  >
                                    {alert.message ??
                                      "Unknown Snort alert"}
                                  </Typography>

                                  <Chip
                                    size="small"
                                    label={severity.toUpperCase()}
                                    color={
                                      severity === "critical"
                                        ? "error"
                                        : severity === "high"
                                          ? "warning"
                                          : "default"
                                    }
                                    variant="outlined"
                                  />
                                </Box>

                                <Typography
                                  variant="body2"
                                  sx={{
                                    mt: 1,
                                    color: "text.secondary",
                                  }}
                                >
                                  {alert.src_ip ??
                                    "Unknown"}
                                  {alert.src_port != null
                                    ? `:${alert.src_port}`
                                    : ""}
                                  {" → "}
                                  {alert.dest_ip ??
                                    "Unknown"}
                                  {alert.dest_port != null
                                    ? `:${alert.dest_port}`
                                    : ""}
                                </Typography>

                                <Typography
                                  variant="caption"
                                  sx={{
                                    display: "block",
                                    mt: 0.75,
                                    color: "text.secondary",
                                  }}
                                >
                                  {alert.protocol ??
                                    "Unknown protocol"}
                                  {" • "}
                                  {alert.classification ??
                                    "Unclassified"}
                                  {" • SID "}
                                  {alert.sid ?? "N/A"}
                                  {" • "}
                                  {alert.action ??
                                    "unknown"}
                                </Typography>

                                <Typography
                                  variant="caption"
                                  sx={{
                                    display: "block",
                                    mt: 0.5,
                                    color: "text.secondary",
                                  }}
                                >
                                  {alert.timestamp ??
                                    "Unknown time"}
                                  {" • "}
                                  {alert.interface ??
                                    "Unknown interface"}
                                  {" • Rule "}
                                  {alert.rule ?? "N/A"}
                                </Typography>
                              </Box>
                            );
                          },
                        )}
                      </Stack>
                    )}
                  </Paper>



                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Custom Rules
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 3,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    <Typography
                      variant="body2"
                      sx={{
                        mb: 3,
                        color: "text.secondary",
                      }}
                    >
                      Create administrator-managed Snort rules
                      using the same firewall-style builder used
                      by the Suricata IPS configuration.
                    </Typography>

                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: {
                          xs: "1fr",
                          md: "repeat(2, 1fr)",
                        },
                        gap: 2,
                      }}
                    >
                      <TextField
                        select
                        label="Action"
                        value={customSnortAction}
                        onChange={(event) => {
                          setCustomSnortAction(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        fullWidth
                      >
                        <MenuItem value="alert">Alert</MenuItem>
                        <MenuItem value="drop">Drop</MenuItem>
                        <MenuItem value="reject">Reject</MenuItem>
                      </TextField>

                      <TextField
                        select
                        label="Protocol"
                        value={customSnortProtocol}
                        onChange={(event) => {
                          setCustomSnortProtocol(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        fullWidth
                      >
                        <MenuItem value="tcp">TCP</MenuItem>
                        <MenuItem value="udp">UDP</MenuItem>
                        <MenuItem value="icmp">ICMP</MenuItem>
                        <MenuItem value="ip">IP</MenuItem>
                      </TextField>

                      <TextField
                        label="Source Address"
                        value={customSnortSource}
                        onChange={(event) => {
                          setCustomSnortSource(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        placeholder="$EXTERNAL_NET"
                        fullWidth
                      />

                      <TextField
                        label="Source Port"
                        value={customSnortSourcePort}
                        onChange={(event) => {
                          setCustomSnortSourcePort(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        placeholder="any"
                        disabled={
                          customSnortProtocol !== "tcp" &&
                          customSnortProtocol !== "udp"
                        }
                        fullWidth
                      />

                      <TextField
                        select
                        label="Direction"
                        value={customSnortDirection}
                        onChange={(event) => {
                          setCustomSnortDirection(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        fullWidth
                      >
                        <MenuItem value="->">-&gt;</MenuItem>
                        <MenuItem value="<>">&lt;&gt;</MenuItem>
                      </TextField>

                      <TextField
                        label="Destination Address"
                        value={customSnortDestination}
                        onChange={(event) => {
                          setCustomSnortDestination(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        placeholder="$HOME_NET"
                        fullWidth
                      />

                      <TextField
                        label="Destination Port"
                        value={customSnortDestinationPort}
                        onChange={(event) => {
                          setCustomSnortDestinationPort(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        placeholder="any"
                        disabled={
                          customSnortProtocol !== "tcp" &&
                          customSnortProtocol !== "udp"
                        }
                        fullWidth
                      />

                      <TextField
                        label="Message"
                        value={customSnortMessage}
                        onChange={(event) => {
                          setCustomSnortMessage(event.target.value);
                          setCustomSnortRuleValid(false);
                          setCustomSnortRuleValidation(null);
                        }}
                        placeholder="Administrator managed Snort rule"
                        fullWidth
                        sx={{
                          gridColumn: {
                            xs: "auto",
                            md: "1 / -1",
                          },
                        }}
                      />
                    </Box>

                    <Typography
                      variant="subtitle2"
                      sx={{
                        mt: 3,
                        mb: 1,
                        fontWeight: 700,
                      }}
                    >
                      Generated Rule
                    </Typography>

                    <TextField
                      value={
                        generatedCustomSnortRule ||
                        "Complete the fields above to generate a rule."
                      }
                      fullWidth
                      multiline
                      minRows={3}
                      slotProps={{
                        htmlInput: {
                          readOnly: true,
                        },
                      }}
                    />

                    {customSnortRuleValidation && (
                      <Alert
                        severity={
                          customSnortRuleValid
                            ? "success"
                            : "error"
                        }
                        sx={{ mt: 2 }}
                      >
                        {customSnortRuleValidation}
                      </Alert>
                    )}

                    <Box
                      sx={{
                        display: "flex",
                        justifyContent: "flex-end",
                        gap: 1.5,
                        mt: 2,
                        flexWrap: "wrap",
                      }}
                    >
                      <Button
                        variant="outlined"
                        disabled={
                          customSnortRuleLoading ||
                          !generatedCustomSnortRule
                        }
                        onClick={validateCustomSnortRule}
                      >
                        Validate
                      </Button>

                      <Button
                        variant="contained"
                        disabled={
                          customSnortRuleLoading ||
                          !generatedCustomSnortRule ||
                          !customSnortRuleValid
                        }
                        onClick={addCustomSnortRule}
                      >
                        Add Rule
                      </Button>
                    </Box>
                  </Paper>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Installed Custom Rules
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 3,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    {!customSnortRules?.rules ||
                    customSnortRules.rules.length === 0 ? (
                      <Typography
                        sx={{ color: "text.secondary" }}
                      >
                        No custom Snort rules installed.
                      </Typography>
                    ) : (
                      <Stack spacing={1.5}>
                        {customSnortRules.rules.map(
                          (rule: any) => (
                            <Box
                              key={String(rule.sid)}
                              sx={{
                                p: 2,
                                borderRadius: 1.5,
                                backgroundColor:
                                  "rgba(255,255,255,0.025)",
                                border:
                                  "1px solid rgba(255,255,255,0.06)",
                              }}
                            >
                              <Box
                                sx={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent:
                                    "space-between",
                                  gap: 2,
                                  flexWrap: "wrap",
                                }}
                              >
                                <Box>
                                  <Typography
                                    sx={{
                                      fontWeight: 700,
                                    }}
                                  >
                                    SID {rule.sid}
                                  </Typography>

                                  <Typography
                                    variant="body2"
                                    sx={{
                                      mt: 0.5,
                                      color: "text.secondary",
                                    }}
                                  >
                                    {rule.rule}
                                  </Typography>
                                </Box>

                                <Button
                                  color="error"
                                  variant="outlined"
                                  size="small"
                                  disabled={
                                    customSnortRuleLoading
                                  }
                                  onClick={async () => {
                                    if (
                                      !window.confirm(
                                        `Delete Snort custom rule SID ${rule.sid}?`
                                      )
                                    ) {
                                      return;
                                    }

                                    setCustomSnortRuleLoading(
                                      true
                                    );

                                    try {
                                      const csrfToken =
                                        await getCsrfToken();

                                      const response =
                                        await fetch(
                                          `/api/snort/custom-rules/${rule.sid}/`,
                                          {
                                            method: "DELETE",
                                            credentials:
                                              "include",
                                            headers: {
                                              "X-CSRFToken":
                                                csrfToken,
                                            },
                                          }
                                        );

                                      const data =
                                        await response.json();

                                      if (!response.ok) {
                                        throw new Error(
                                          data.error ||
                                            data.message ||
                                            "Failed to delete Snort rule."
                                        );
                                      }

                                      setCustomSnortRuleValidation(
                                        data.message ||
                                          "Snort rule deleted successfully."
                                      );
                                      setCustomSnortRuleValid(
                                        false
                                      );

                                      await loadCustomSnortRules();
                                    } catch (error: any) {
                                      setCustomSnortRuleValidation(
                                        error?.message ||
                                          "Failed to delete Snort rule."
                                      );
                                    } finally {
                                      setCustomSnortRuleLoading(
                                        false
                                      );
                                    }
                                  }}
                                >
                                  Delete
                                </Button>
                              </Box>
                            </Box>
                          )
                        )}
                      </Stack>
                    )}
                  </Paper>
                  <Typography
                    variant="body2"
                    sx={{
                      mt: 3,
                      color: "text.secondary",
                    }}
                  >
                    Snort data refreshes every 10 seconds.
                  </Typography>
                </>
              )}
            </Paper>
          ) : selected === "Fail2Ban" ? (
            <Paper
              elevation={0}
              sx={{
                p: 4,
                border:
                  "1px solid rgba(255,255,255,0.08)",
                borderRadius: 2,
                backgroundColor: "#111827",
              }}
            >
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: 2,
                }}
              >
                <Box>
                  <Typography
                    variant="h4"
                    sx={{ fontWeight: 800 }}
                  >
                    Fail2Ban
                  </Typography>

                  <Typography
                    sx={{
                      mt: 0.5,
                      color: "text.secondary",
                    }}
                  >
                    Host-based intrusion prevention
                  </Typography>
                </Box>

                <Chip
                  label={
                    fail2ban?.service.active
                      ? "ACTIVE"
                      : "INACTIVE"
                  }
                  color={
                    fail2ban?.service.active
                      ? "success"
                      : "error"
                  }
                  icon={
                    fail2ban?.service.active
                      ? <CheckCircleIcon />
                      : <WarningIcon />
                  }
                />
              </Box>

              {!fail2ban ? (
                <Box
                  sx={{
                    mt: 5,
                    textAlign: "center",
                  }}
                >
                  <CircularProgress size={30} />

                  <Typography
                    sx={{
                      mt: 2,
                      color: "text.secondary",
                    }}
                  >
                    Loading Fail2Ban status...
                  </Typography>
                </Box>
              ) : (
                <>
                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(3, 1fr)",
                      },
                      gap: 2,
                      mt: 4,
                    }}
                  >
                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Service
                      </Typography>

                      <Typography
                        variant="h6"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {fail2ban.service.status}
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Active Jails
                      </Typography>

                      <Typography
                        variant="h4"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {fail2ban.jails.length}
                      </Typography>
                    </Paper>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#0b1220",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Currently Banned
                      </Typography>

                      <Typography
                        variant="h4"
                        sx={{
                          mt: 0.5,
                          fontWeight: 800,
                        }}
                      >
                        {fail2ban.jails.reduce(
                          (total, jail) =>
                            total + jail.currently_banned,
                          0,
                        )}
                      </Typography>
                    </Paper>
                  </Box>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Jails
                  </Typography>

                  <Stack spacing={2}>
                    {fail2ban.jails.map((jail) => (
                      <Paper
                        key={jail.name}
                        elevation={0}
                        sx={{
                          p: 2.5,
                          border:
                            "1px solid rgba(255,255,255,0.08)",
                          borderRadius: 2,
                          backgroundColor: "#0b1220",
                        }}
                      >
                        <Box
                          sx={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            flexWrap: "wrap",
                            gap: 1,
                          }}
                        >
                          <Typography
                            variant="h6"
                            sx={{ fontWeight: 800 }}
                          >
                            {jail.name}
                          </Typography>

                          <Chip
                            label={
                              jail.error
                                ? "ERROR"
                                : "MONITORING"
                            }
                            color={
                              jail.error
                                ? "error"
                                : "success"
                            }
                            size="small"
                          />
                        </Box>

                        <Box
                          sx={{
                            display: "grid",
                            gridTemplateColumns: {
                              xs: "1fr 1fr",
                              sm: "repeat(4, 1fr)",
                            },
                            gap: 2,
                            mt: 2,
                          }}
                        >
                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Currently Failed
                            </Typography>

                            <Typography
                              variant="h6"
                              sx={{ fontWeight: 700 }}
                            >
                              {jail.currently_failed}
                            </Typography>
                          </Box>

                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Total Failed
                            </Typography>

                            <Typography
                              variant="h6"
                              sx={{ fontWeight: 700 }}
                            >
                              {jail.total_failed}
                            </Typography>
                          </Box>

                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Currently Banned
                            </Typography>

                            <Typography
                              variant="h6"
                              sx={{ fontWeight: 700 }}
                            >
                              {jail.currently_banned}
                            </Typography>
                          </Box>

                          <Box>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Total Banned
                            </Typography>

                            <Typography
                              variant="h6"
                              sx={{ fontWeight: 700 }}
                            >
                              {jail.total_banned}
                            </Typography>
                          </Box>
                        </Box>

                        {jail.file_list.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Log Sources
                            </Typography>

                            {jail.file_list.map((file) => (
                              <Typography
                                key={file}
                                variant="body2"
                                sx={{ mt: 0.5 }}
                              >
                                {file}
                              </Typography>
                            ))}
                          </Box>
                        )}

                        {jail.journal_matches.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Journal Match
                            </Typography>

                            {jail.journal_matches.map(
                              (match) => (
                                <Typography
                                  key={match}
                                  variant="body2"
                                  sx={{ mt: 0.5 }}
                                >
                                  {match}
                                </Typography>
                              ),
                            )}
                          </Box>
                        )}

                        {jail.banned_ips.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography
                              variant="body2"
                              sx={{
                                color: "text.secondary",
                              }}
                            >
                              Banned IPs
                            </Typography>

                            <Stack
                              direction="row"
                              spacing={1}
                              sx={{
                                mt: 1,
                                flexWrap: "wrap",
                                gap: 1,
                              }}
                            >
                              {jail.banned_ips.map((ip) => (
                                <Chip
                                  key={ip}
                                  label={ip}
                                  color="error"
                                  size="small"
                                  variant="outlined"
                                />
                              ))}
                            </Stack>
                          </Box>
                        )}
                      </Paper>
                    ))}
                  </Stack>

                  <Typography
                    variant="h6"
                    sx={{
                      mt: 4,
                      mb: 2,
                      fontWeight: 700,
                    }}
                  >
                    Custom Fail2Ban Jails
                  </Typography>

                  <Paper
                    elevation={0}
                    sx={{
                      p: 2.5,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 2,
                      backgroundColor: "#0b1220",
                    }}
                  >
                    <Typography
                      variant="body2"
                      sx={{
                        color: "text.secondary",
                        mb: 2.5,
                      }}
                    >
                      Administrator-managed Fail2Ban jails.
                      Custom jails are stored separately from
                      the existing system jails.
                    </Typography>

                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: {
                          xs: "1fr",
                          md: "1fr 1fr",
                        },
                        gap: 2,
                      }}
                    >
                      <TextField
                        label="Jail Name"
                        value={fail2banCustomJailName}
                        onChange={(event) => {
                          setFail2banCustomJailName(
                            event.target.value,
                          );
                          setFail2banCustomJailValid(null);
                          setFail2banCustomJailValidation(null);
                        }}
                        placeholder="hpc-auth-abuse"
                        helperText="1–48 characters: letters, numbers, underscore, hyphen"
                        fullWidth
                        size="small"
                        required
                      />

                      <TextField
                        label="Log Path"
                        value={fail2banCustomJailLogpath}
                        onChange={(event) => {
                          setFail2banCustomJailLogpath(
                            event.target.value,
                          );
                          setFail2banCustomJailValid(null);
                          setFail2banCustomJailValidation(null);
                        }}
                        placeholder="/var/log/example.log"
                        helperText="Absolute filesystem path"
                        fullWidth
                        size="small"
                        required
                      />

                      <TextField
                        select
                        label="What should trigger the ban?"
                        value={fail2banCustomJailTrigger}
                        onChange={(event) => {
                          setFail2banCustomJailTrigger(
                            event.target.value,
                          );
                          setFail2banCustomJailValid(null);
                          setFail2banCustomJailValidation(null);
                        }}
                        helperText={
                          fail2banTriggerOptions.find(
                            (option) =>
                              option.value ===
                              fail2banCustomJailTrigger,
                          )?.description ||
                          "Choose the activity that should trigger a ban."
                        }
                        fullWidth
                        size="small"
                        required
                      >
                        {fail2banTriggerOptions.map(
                          (option) => (
                            <MenuItem
                              key={option.value}
                              value={option.value}
                            >
                              {option.label}
                            </MenuItem>
                          ),
                        )}
                      </TextField>

                      <TextField
                        label="Failed Attempts"
                        value={fail2banCustomJailMaxretry}
                        onChange={(event) =>
                          setFail2banCustomJailMaxretry(
                            event.target.value,
                          )
                        }
                        type="number"
                        fullWidth
                        size="small"
                        required
                      />

                      <TextField
                        label="Within"
                        value={fail2banCustomJailFindtime}
                        onChange={(event) =>
                          setFail2banCustomJailFindtime(
                            event.target.value,
                          )
                        }
                        placeholder="10m"
                        helperText="Example: 10 minutes"
                        fullWidth
                        size="small"
                        required
                      />

                      <TextField
                        label="Ban For"
                        value={fail2banCustomJailBantime}
                        onChange={(event) =>
                          setFail2banCustomJailBantime(
                            event.target.value,
                          )
                        }
                        placeholder="1h"
                        helperText="Examples: 1h, 24h, 1d"
                        fullWidth
                        size="small"
                        required
                      />
                    </Box>

                    <Stack
                      direction="row"
                      spacing={1.5}
                      sx={{
                        mt: 2.5,
                        flexWrap: "wrap",
                        gap: 1,
                      }}
                    >
                      <Button
                        variant="outlined"
                        disabled={
                          fail2banCustomJailLoading
                        }
                        onClick={
                          validateFail2BanCustomJail
                        }
                      >
                        {fail2banCustomJailLoading
                          ? "VALIDATING..."
                          : "VALIDATE"}
                      </Button>

                      <Button
                        variant="contained"
                        disabled={
                          fail2banCustomJailLoading
                        }
                        onClick={
                          addFail2BanCustomJail
                        }
                      >
                        {fail2banCustomJailLoading
                          ? "PROCESSING..."
                          : "ADD JAIL"}
                      </Button>
                    </Stack>

                    {fail2banCustomJailValidation && (
                      <Alert
                        severity={
                          fail2banCustomJailValid === true
                            ? "success"
                            : fail2banCustomJailValid ===
                                false
                              ? "error"
                              : "info"
                        }
                        sx={{ mt: 2 }}
                      >
                        {fail2banCustomJailValidation}
                      </Alert>
                    )}

                    <Divider sx={{ my: 3 }} />

                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent:
                          "space-between",
                        flexWrap: "wrap",
                        gap: 1,
                        mb: 2,
                      }}
                    >
                      <Typography
                        variant="subtitle1"
                        sx={{ fontWeight: 700 }}
                      >
                        Installed Custom Jails
                      </Typography>

                      <Chip
                        label={
                          fail2banCustomJails
                            ? `${fail2banCustomJails.count} custom jail${fail2banCustomJails.count === 1 ? "" : "s"}`
                            : "Unavailable"
                        }
                        color={
                          fail2banCustomJails
                            ? "primary"
                            : "default"
                        }
                        size="small"
                      />
                    </Box>

                    {fail2banCustomJails?.error && (
                      <Alert
                        severity="error"
                        sx={{ mb: 2 }}
                      >
                        {fail2banCustomJails.error}
                      </Alert>
                    )}

                    {fail2banCustomJails &&
                    fail2banCustomJails.jails.length >
                      0 ? (
                      <TableContainer>
                        <Table
                          size="small"
                          sx={{
                            minWidth: 850,
                          }}
                        >
                          <TableHead>
                            <TableRow>
                              <TableCell>
                                JAIL
                              </TableCell>
                              <TableCell>
                                STATUS
                              </TableCell>
                              <TableCell>
                                LOG PATH
                              </TableCell>
                              <TableCell>
                                RETRY
                              </TableCell>
                              <TableCell>
                                FIND TIME
                              </TableCell>
                              <TableCell>
                                BAN TIME
                              </TableCell>
                              <TableCell align="right">
                                ACTION
                              </TableCell>
                            </TableRow>
                          </TableHead>

                          <TableBody>
                            {fail2banCustomJails.jails.map(
                              (jail) => (
                                <TableRow
                                  key={jail.name}
                                >
                                  <TableCell>
                                    <Typography
                                      variant="body2"
                                      sx={{
                                        fontWeight: 700,
                                      }}
                                    >
                                      {jail.jail_name}
                                    </Typography>
                                  </TableCell>

                                  <TableCell>
                                    <Chip
                                      label={
                                        jail.error
                                          ? "ERROR"
                                          : jail.active
                                            ? "ACTIVE"
                                            : "INACTIVE"
                                      }
                                      color={
                                        jail.error
                                          ? "error"
                                          : jail.active
                                            ? "success"
                                            : "default"
                                      }
                                      size="small"
                                    />
                                  </TableCell>

                                  <TableCell>
                                    <Typography
                                      variant="body2"
                                      sx={{
                                        maxWidth: 260,
                                        overflow:
                                          "hidden",
                                        textOverflow:
                                          "ellipsis",
                                        whiteSpace:
                                          "nowrap",
                                      }}
                                    >
                                      {jail.logpath}
                                    </Typography>
                                  </TableCell>

                                  <TableCell>
                                    {jail.maxretry}
                                  </TableCell>

                                  <TableCell>
                                    {jail.findtime}
                                  </TableCell>

                                  <TableCell>
                                    {jail.bantime}
                                  </TableCell>

                                  <TableCell align="right">
                                    <Button
                                      color="error"
                                      size="small"
                                      variant="outlined"
                                      disabled={
                                        fail2banCustomJailLoading
                                      }
                                      onClick={() =>
                                        deleteFail2BanCustomJail(
                                          jail.name,
                                        )
                                      }
                                    >
                                      DELETE
                                    </Button>
                                  </TableCell>
                                </TableRow>
                              ),
                            )}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Typography
                        variant="body2"
                        sx={{
                          color: "text.secondary",
                        }}
                      >
                        No custom Fail2Ban jails are
                        currently installed.
                      </Typography>
                    )}

                    <Typography
                      variant="caption"
                      sx={{
                        display: "block",
                        mt: 2,
                        color: "text.secondary",
                      }}
                    >
                      Custom jail files:
                      {" /etc/fail2ban/jail.d/hpc-custom-*.local"}
                      {" • "}
                      Filter files:
                      {" /etc/fail2ban/filter.d/hpc-custom-*.conf"}
                    </Typography>
                  </Paper>

                  {fail2ban.error && (
                    <Typography
                      sx={{
                        mt: 3,
                        color: "error.main",
                      }}
                    >
                      {fail2ban.error}
                    </Typography>
                  )}

                  <Typography
                    variant="body2"
                    sx={{
                      mt: 3,
                      color: "text.secondary",
                    }}
                  >
                    Fail2Ban data refreshes every 10 seconds.
                  </Typography>
                </>
              )}
            </Paper>
          ) : selected === "Reports" ? (
            <Box>
              <Stack spacing={3}>
                <Box>
                  <Typography
                    variant="h4"
                    sx={{
                      fontWeight: 800,
                      letterSpacing: "-0.02em",
                    }}
                  >
                    Security Reports
                  </Typography>

                  <Typography
                    sx={{
                      mt: 0.75,
                      color: "text.secondary",
                    }}
                  >
                    Generate a security activity report for a
                    selected time period and download it as CSV
                    or PDF.
                  </Typography>
                </Box>

                <Paper
                  elevation={0}
                  sx={{
                    p: 3,
                    border:
                      "1px solid rgba(255,255,255,0.08)",
                    borderRadius: 2,
                    backgroundColor: "#111827",
                  }}
                >
                  <Typography
                    variant="h6"
                    sx={{
                      fontWeight: 700,
                      mb: 2,
                    }}
                  >
                    Report Period
                  </Typography>

                  <Stack
                    direction={{ xs: "column", md: "row" }}
                    spacing={2}
                  >
                    <TextField
                      select
                      label="Time Period"
                      value={reportPeriod}
                      onChange={(event) => {
                        setReportPeriod(event.target.value);
                        setReportGenerated(false);
                        setReportError("");
                      }}
                      sx={{
                        minWidth: 210,
                      }}
                    >
                      <MenuItem value="second">
                        Last Second
                      </MenuItem>
                      <MenuItem value="minute">
                        Last Minute
                      </MenuItem>
                      <MenuItem value="hour">
                        Last Hour
                      </MenuItem>
                      <MenuItem value="day">
                        Last 24 Hours
                      </MenuItem>
                      <MenuItem value="week">
                        Last 7 Days
                      </MenuItem>
                      <MenuItem value="month">
                        Last 30 Days
                      </MenuItem>
                      <MenuItem value="year">
                        Last 365 Days
                      </MenuItem>
                      <MenuItem value="custom">
                        Custom Range
                      </MenuItem>
                    </TextField>

                    {reportPeriod === "custom" && (
                      <>
                        <TextField
                          label="Start Date & Time"
                          type="datetime-local"
                          value={reportStart}
                          onChange={(event) => {
                            setReportStart(event.target.value);
                            setReportGenerated(false);
                          }}
                          slotProps={{
                            inputLabel: {
                              shrink: true,
                            },
                          }}
                          fullWidth
                        />

                        <TextField
                          label="End Date & Time"
                          type="datetime-local"
                          value={reportEnd}
                          onChange={(event) => {
                            setReportEnd(event.target.value);
                            setReportGenerated(false);
                          }}
                          slotProps={{
                            inputLabel: {
                              shrink: true,
                            },
                          }}
                          fullWidth
                        />
                      </>
                    )}
                  </Stack>

                  {reportPeriod !== "custom" && (
                    <Typography
                      variant="body2"
                      sx={{
                        mt: 1.5,
                        color: "text.secondary",
                      }}
                    >
                      The report uses the current gateway time
                      and includes only events recorded inside
                      the selected period.
                    </Typography>
                  )}

                  {reportError && (
                    <Alert
                      severity="error"
                      sx={{ mt: 2 }}
                    >
                      {reportError}
                    </Alert>
                  )}

                  <Stack
                    direction={{ xs: "column", sm: "row" }}
                    spacing={1.5}
                    sx={{ mt: 3 }}
                  >
                    <Button
                      variant="contained"
                      onClick={generateReport}
                      disabled={reportLoading}
                    >
                      {reportLoading
                        ? "GENERATING..."
                        : "GENERATE REPORT"}
                    </Button>

                    <Button
                      variant="outlined"
                      onClick={() =>
                        downloadReport("csv")
                      }
                    >
                      DOWNLOAD CSV
                    </Button>

                    <Button
                      variant="outlined"
                      onClick={() =>
                        downloadReport("pdf")
                      }
                    >
                      DOWNLOAD PDF
                    </Button>
                  </Stack>
                </Paper>

                {report && reportGenerated && (
                  <>
                    <Paper
                      elevation={0}
                      sx={{
                        p: 2.5,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#111827",
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{ color: "text.secondary" }}
                      >
                        Reporting period
                      </Typography>

                      <Typography
                        sx={{
                          mt: 0.5,
                          fontWeight: 600,
                        }}
                      >
                        {formatReportDate(
                          report.period.start
                        )}{" "}
                        —{" "}
                        {formatReportDate(
                          report.period.end
                        )}
                      </Typography>
                    </Paper>

                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: {
                          xs: "1fr",
                          sm: "repeat(2, 1fr)",
                          lg: "repeat(4, 1fr)",
                        },
                        gap: 2,
                      }}
                    >
                      {[
                        [
                          "Total Events",
                          report.summary.total_events,
                        ],
                        [
                          "Blocked Events",
                          report.summary.blocked_events,
                        ],
                        [
                          "Detected Events",
                          report.summary.detected_events,
                        ],
                        [
                          "Fail2Ban Bans",
                          report.summary.fail2ban_bans,
                        ],
                      ].map(([title, value]) => (
                        <Paper
                          key={String(title)}
                          elevation={0}
                          sx={{
                            p: 2.5,
                            border:
                              "1px solid rgba(255,255,255,0.08)",
                            borderRadius: 2,
                            backgroundColor: "#111827",
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{
                              color: "text.secondary",
                            }}
                          >
                            {title}
                          </Typography>

                          <Typography
                            variant="h4"
                            sx={{
                              mt: 0.75,
                              fontWeight: 800,
                            }}
                          >
                            {value}
                          </Typography>
                        </Paper>
                      ))}
                    </Box>

                    <Paper
                      elevation={0}
                      sx={{
                        p: 3,
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#111827",
                      }}
                    >
                      <Typography
                        variant="h6"
                        sx={{
                          fontWeight: 700,
                          mb: 2,
                        }}
                      >
                        Security Control Activity
                      </Typography>

                      <Box
                        sx={{
                          display: "grid",
                          gridTemplateColumns: {
                            xs: "1fr",
                            sm: "repeat(2, 1fr)",
                            lg: "repeat(3, 1fr)",
                          },
                          gap: 1.5,
                        }}
                      >
                        {Object.entries(
                          report.controls
                        ).map(([name, count]) => (
                          <Box
                            key={name}
                            sx={{
                              p: 1.75,
                              border:
                                "1px solid rgba(255,255,255,0.06)",
                              borderRadius: 1.5,
                              display: "flex",
                              justifyContent:
                                "space-between",
                              alignItems: "center",
                            }}
                          >
                            <Typography>
                              {name}
                            </Typography>

                            <Chip
                              label={count}
                              size="small"
                            />
                          </Box>
                        ))}
                      </Box>
                    </Paper>

                    {report.top_sources.length > 0 && (
                      <Paper
                        elevation={0}
                        sx={{
                          p: 3,
                          border:
                            "1px solid rgba(255,255,255,0.08)",
                          borderRadius: 2,
                          backgroundColor: "#111827",
                        }}
                      >
                        <Typography
                          variant="h6"
                          sx={{
                            fontWeight: 700,
                            mb: 2,
                          }}
                        >
                          Top Source IPs
                        </Typography>

                        <Stack spacing={1}>
                          {report.top_sources.map(
                            (item) => (
                              <Box
                                key={item.ip}
                                sx={{
                                  display: "flex",
                                  justifyContent:
                                    "space-between",
                                  alignItems: "center",
                                  p: 1.25,
                                  borderRadius: 1,
                                  backgroundColor:
                                    "rgba(255,255,255,0.03)",
                                }}
                              >
                                <Typography>
                                  {item.ip}
                                </Typography>

                                <Chip
                                  label={`${item.count} events`}
                                  size="small"
                                />
                              </Box>
                            )
                          )}
                        </Stack>
                      </Paper>
                    )}

                    <Paper
                      elevation={0}
                      sx={{
                        border:
                          "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 2,
                        backgroundColor: "#111827",
                        overflow: "hidden",
                      }}
                    >
                      <Box sx={{ p: 3, pb: 2 }}>
                        <Typography
                          variant="h6"
                          sx={{ fontWeight: 700 }}
                        >
                          Event Details
                        </Typography>

                        <Typography
                          variant="body2"
                          sx={{
                            mt: 0.5,
                            color: "text.secondary",
                          }}
                        >
                          {report.events.length} events
                          returned for this report.
                        </Typography>
                      </Box>

                      {report.events.length === 0 ? (
                        <Box sx={{ p: 4, pt: 2 }}>
                          <Typography
                            sx={{
                              color: "text.secondary",
                              textAlign: "center",
                            }}
                          >
                            No security events were
                            recorded during this period.
                          </Typography>
                        </Box>
                      ) : (
                        <TableContainer
                          sx={{
                            maxHeight: 560,
                          }}
                        >
                          <Table
                            stickyHeader
                            size="small"
                          >
                            <TableHead>
                              <TableRow>
                                <TableCell>
                                  Time
                                </TableCell>
                                <TableCell>
                                  Source
                                </TableCell>
                                <TableCell>
                                  Severity
                                </TableCell>
                                <TableCell>
                                  Event
                                </TableCell>
                              </TableRow>
                            </TableHead>

                            <TableBody>
                              {report.events.map(
                                (event, index) => (
                                  <TableRow
                                    key={`${event.timestamp}-${index}`}
                                    hover
                                  >
                                    <TableCell
                                      sx={{
                                        whiteSpace:
                                          "nowrap",
                                      }}
                                    >
                                      {formatReportDate(
                                        event.timestamp
                                      )}
                                    </TableCell>

                                    <TableCell>
                                      <Chip
                                        label={
                                          event.source
                                        }
                                        size="small"
                                      />
                                    </TableCell>

                                    <TableCell>
                                      {event.severity ??
                                        event.priority ??
                                        "—"}
                                    </TableCell>

                                    <TableCell
                                      sx={{
                                        minWidth: 420,
                                        whiteSpace:
                                          "normal",
                                        wordBreak:
                                          "break-word",
                                      }}
                                    >
                                      {event.message}
                                    </TableCell>
                                  </TableRow>
                                )
                              )}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      )}
                    </Paper>
                  </>
                )}
              </Stack>
            </Box>
          ) : (
            <Paper
              elevation={0}
              sx={{
                p: 4,
                border:
                  "1px solid rgba(255,255,255,0.08)",
                borderRadius: 2,
                backgroundColor: "#111827",
              }}
            >
              <Typography
                variant="h4"
                sx={{ fontWeight: 800 }}
              >
                {selected}
              </Typography>

              <Typography
                sx={{
                  mt: 2,
                  color: "text.secondary",
                }}
              >
                This module is being built and will be
                connected to the security-control APIs in
                the next phases.
              </Typography>
            </Paper>
          )}
        </Box>
      </Box>
    </ThemeProvider>
  );
}

export default App;

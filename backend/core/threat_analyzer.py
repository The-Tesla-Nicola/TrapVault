"""
Threat Analyzer
===============
Pattern-based attack classification engine. Analyses raw HTTP request data
and returns a structured result containing attack type, severity, confidence
score, matched patterns, and extracted IOCs.

No external ML dependencies are required. Pattern lists are tuned to match
the most common offensive payloads seen in the wild.
"""

import re
import json
from typing import Any, Dict, List, Tuple


class ThreatAnalyzer:
    """
    Stateless threat analysis engine. Instantiate once and call .analyze()
    for each incoming event.
    """

    # ------------------------------------------------------------------
    # SQL Injection patterns  (pattern, rule_name, confidence)
    # ------------------------------------------------------------------
    SQL_PATTERNS: List[Tuple[str, str, float]] = [
        (r"'\s*(or|and)\s+\d+\s*=\s*\d+", "sqli_boolean_basic", 0.95),
        (r"union\s+select", "sqli_union_select", 0.95),
        (r"union\s+all\s+select", "sqli_union_all_select", 0.95),
        (r";\s*(drop|truncate|delete|alter)\s+table", "sqli_destructive", 0.99),
        (r"select\s+.*\s+from\s+", "sqli_select_from", 0.80),
        (r"insert\s+into\s+", "sqli_insert", 0.80),
        (r"update\s+\w+\s+set\s+", "sqli_update", 0.80),
        (r"exec\s*\(|execute\s*\(", "sqli_exec", 0.90),
        (r"xp_cmdshell", "sqli_xp_cmdshell", 0.99),
        (r"sp_executesql", "sqli_sp_executesql", 0.95),
        (r"0x[0-9a-f]{4,}", "sqli_hex_encoding", 0.70),
        (r"char\s*\(\s*\d+", "sqli_char_function", 0.75),
        (r"concat\s*\(", "sqli_concat", 0.60),
        (r"group_concat\s*\(", "sqli_group_concat", 0.85),
        (r"information_schema", "sqli_information_schema", 0.90),
        (r"sleep\s*\(\s*\d+", "sqli_time_delay", 0.90),
        (r"benchmark\s*\(", "sqli_benchmark", 0.90),
        (r"waitfor\s+delay", "sqli_waitfor", 0.95),
        (r"load_file\s*\(", "sqli_load_file", 0.90),
        (r"into\s+outfile", "sqli_outfile", 0.95),
        (r"--\s*$", "sqli_comment_double_dash", 0.65),
        (r"#\s*$", "sqli_comment_hash", 0.55),
        (r"/\*.*?\*/", "sqli_inline_comment", 0.60),
    ]

    # ------------------------------------------------------------------
    # XSS patterns
    # ------------------------------------------------------------------
    XSS_PATTERNS: List[Tuple[str, str, float]] = [
        (r"<script[\s>]", "xss_script_tag", 0.95),
        (r"</script>", "xss_script_close", 0.90),
        (r"javascript\s*:", "xss_javascript_proto", 0.95),
        (
            r"on\w+\s*=\s*['\"]?\s*(javascript|alert|eval|document)",
            "xss_event_handler",
            0.90,
        ),
        (r"eval\s*\(", "xss_eval", 0.80),
        (r"document\.cookie", "xss_cookie_access", 0.95),
        (r"document\.write\s*\(", "xss_doc_write", 0.85),
        (r"\.innerHTML\s*=", "xss_innerhtml", 0.80),
        (r"window\.location", "xss_location_redirect", 0.75),
        (r"<img[^>]+src\s*=\s*['\"]?javascript", "xss_img_javascript", 0.95),
        (r"<iframe", "xss_iframe", 0.75),
        (r"<object", "xss_object_tag", 0.75),
        (r"<embed", "xss_embed_tag", 0.75),
        (r"vbscript\s*:", "xss_vbscript", 0.90),
        (r"expression\s*\(", "xss_css_expression", 0.85),
        (r"&#x[0-9a-f]+;", "xss_hex_entity", 0.65),
        (r"\\u00[0-9a-f]{2}", "xss_unicode_escape", 0.60),
        (r"String\.fromCharCode\s*\(", "xss_fromcharcode", 0.85),
        (r"alert\s*\(", "xss_alert_function", 0.70),
        (r"confirm\s*\(", "xss_confirm_function", 0.65),
        (r"prompt\s*\(", "xss_prompt_function", 0.65),
        (r"<svg[^>]*onload", "xss_svg_onload", 0.95),
    ]

    # ------------------------------------------------------------------
    # Path traversal patterns
    # ------------------------------------------------------------------
    TRAVERSAL_PATTERNS: List[Tuple[str, str, float]] = [
        (r"\.\./", "traversal_dotdot_slash", 0.90),
        (r"\.\.\\", "traversal_dotdot_backslash", 0.90),
        (r"%2e%2e%2f", "traversal_url_encoded", 0.95),
        (r"%2e%2e/", "traversal_partial_encoded", 0.90),
        (r"\.\.%2f", "traversal_mixed_encoded", 0.90),
        (r"/etc/passwd", "traversal_etc_passwd", 0.99),
        (r"/etc/shadow", "traversal_etc_shadow", 0.99),
        (r"/etc/hosts", "traversal_etc_hosts", 0.85),
        (r"c:\\windows", "traversal_win_system", 0.95),
        (r"c:/windows", "traversal_win_forward", 0.95),
        (r"cmd\.exe", "traversal_cmd_exe", 0.99),
        (r"/bin/bash", "traversal_bash", 0.90),
        (r"/bin/sh", "traversal_sh", 0.85),
        (r"win\.ini", "traversal_win_ini", 0.90),
        (r"boot\.ini", "traversal_boot_ini", 0.90),
        (r"/proc/self/", "traversal_proc_self", 0.85),
    ]

    # ------------------------------------------------------------------
    # Command injection patterns
    # ------------------------------------------------------------------
    COMMAND_PATTERNS: List[Tuple[str, str, float]] = [
        (r";\s*(ls|cat|id|whoami|uname|pwd|echo)\b", "cmdinj_semicolon", 0.90),
        (r"\|\s*(ls|cat|id|whoami|uname|wget|curl)\b", "cmdinj_pipe", 0.90),
        (r"&&\s*(ls|cat|id|whoami|uname)\b", "cmdinj_and", 0.85),
        (r"`[^`]{1,200}`", "cmdinj_backtick", 0.80),
        (r"\$\([^)]{1,200}\)", "cmdinj_subshell", 0.85),
        (r";\s*wget\s+http", "cmdinj_wget", 0.95),
        (r";\s*curl\s+http", "cmdinj_curl", 0.95),
        (r";\s*nc\s+", "cmdinj_netcat", 0.95),
        (r";\s*python\s+-c", "cmdinj_python", 0.90),
        (r";\s*perl\s+-e", "cmdinj_perl", 0.90),
        (r"/dev/tcp/", "cmdinj_dev_tcp", 0.95),
        (r"base64\s+-d", "cmdinj_base64_decode", 0.80),
        (r"chmod\s+[0-9]+\s+", "cmdinj_chmod", 0.85),
        (r"crontab\s+-", "cmdinj_crontab", 0.85),
        (r"mkfifo\s+", "cmdinj_mkfifo", 0.90),
    ]

    # ------------------------------------------------------------------
    # SSRF patterns
    # ------------------------------------------------------------------
    SSRF_PATTERNS: List[Tuple[str, str, float]] = [
        (r"http://localhost", "ssrf_localhost", 0.85),
        (r"http://127\.0\.0\.1", "ssrf_loopback", 0.90),
        (r"http://0\.0\.0\.0", "ssrf_zero_host", 0.85),
        (r"http://169\.254\.169\.254", "ssrf_aws_metadata", 0.99),
        (r"http://metadata\.google\.internal", "ssrf_gcp_metadata", 0.99),
        (r"http://100\.100\.100\.200", "ssrf_alibaba_metadata", 0.99),
        (r"file:///", "ssrf_file_scheme", 0.95),
        (r"dict://", "ssrf_dict_scheme", 0.90),
        (r"gopher://", "ssrf_gopher_scheme", 0.90),
        (r"ftp://.*@", "ssrf_ftp_creds", 0.85),
        (r"http://192\.168\.", "ssrf_rfc1918_192", 0.80),
        (r"http://10\.", "ssrf_rfc1918_10", 0.80),
        (r"http://172\.(1[6-9]|2\d|3[01])\.", "ssrf_rfc1918_172", 0.80),
    ]

    # ------------------------------------------------------------------
    # XXE patterns
    # ------------------------------------------------------------------
    XXE_PATTERNS: List[Tuple[str, str, float]] = [
        (r"<!ENTITY", "xxe_entity_declaration", 0.90),
        (r"<!DOCTYPE[^>]+SYSTEM", "xxe_doctype_system", 0.95),
        (r"SYSTEM\s+[\"'][^\"']+[\"']", "xxe_system_identifier", 0.90),
        (r"file:///", "xxe_file_scheme", 0.85),
        (r"<!DOCTYPE[^>]+PUBLIC", "xxe_doctype_public", 0.85),
        (r"ENTITY\s+\w+\s+SYSTEM", "xxe_entity_system", 0.95),
    ]

    # ------------------------------------------------------------------
    # Reconnaissance patterns (matched against path only)
    # ------------------------------------------------------------------
    RECON_PATTERNS: List[Tuple[str, str, float]] = [
        (r"\.env$", "recon_env_file", 0.90),
        (r"\.git/config", "recon_git_config", 0.95),
        (r"\.git/HEAD", "recon_git_head", 0.90),
        (r"/wp-admin", "recon_wp_admin", 0.70),
        (r"/wp-login", "recon_wp_login", 0.70),
        (r"/phpmyadmin", "recon_phpmyadmin", 0.75),
        (r"/adminer", "recon_adminer", 0.75),
        (r"/manager/html", "recon_tomcat_manager", 0.85),
        (r"/actuator", "recon_spring_actuator", 0.85),
        (r"/__debug__", "recon_django_debug", 0.80),
        (r"/server-status", "recon_apache_status", 0.80),
        (r"/phpinfo", "recon_phpinfo", 0.80),
        (r"/robots\.txt", "recon_robots", 0.40),
        (r"/sitemap\.xml", "recon_sitemap", 0.35),
        (r"backup\.(sql|zip|tar|gz|bak)", "recon_backup_file", 0.85),
        (r"config\.(php|yml|yaml|json|xml)", "recon_config_file", 0.80),
        (r"(admin|administrator|manage)\.(php|asp|aspx)", "recon_admin_panel", 0.75),
    ]

    # ------------------------------------------------------------------
    # Well-known default credentials
    # ------------------------------------------------------------------
    DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("admin", ""),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("root", ""),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("user", "user"),
        ("test", "test"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("sa", "sa"),
        ("sa", ""),
        ("postgres", "postgres"),
        ("mysql", "mysql"),
        ("pi", "raspberry"),
        ("ubnt", "ubnt"),
    ]

    COMMON_PASSWORDS: List[str] = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "monkey",
        "1234567",
        "letmein",
        "trustno1",
        "dragon",
        "baseball",
        "iloveyou",
        "master",
        "sunshine",
        "welcome",
        "passw0rd",
        "shadow",
        "123123",
        "654321",
        "1234",
        "password1",
        "qwerty123",
        "admin",
        "changeme",
        "default",
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, event) -> Dict[str, Any]:
        """
        Perform comprehensive threat analysis on an AttackEvent instance.

        Returns a dictionary with keys:
            attack_type, severity, confidence, patterns, rules, iocs
        """
        patterns_found: List[str] = []
        rules_matched: List[str] = []
        iocs: List[Dict[str, str]] = []
        max_confidence: float = 0.0
        attack_type: str = "other"

        # Build a single concatenated search corpus from all request fields
        corpus = self._build_corpus(event)

        # Run each detector category
        for category, patterns, candidate_type in [
            (corpus, self.SQL_PATTERNS, "sql_injection"),
            (corpus, self.XSS_PATTERNS, "xss"),
            (corpus, self.TRAVERSAL_PATTERNS, "path_traversal"),
            (corpus, self.COMMAND_PATTERNS, "command_injection"),
            (corpus, self.SSRF_PATTERNS, "ssrf"),
            (corpus, self.XXE_PATTERNS, "xxe"),
        ]:
            score, matched = self._check_patterns(category, patterns)
            if score > max_confidence:
                max_confidence = score
                attack_type = candidate_type
            patterns_found.extend(matched)
            rules_matched.extend(matched)

        # Recon check – matched against path only
        path_lower = (event.path or "").lower()
        recon_score, recon_patterns = self._check_patterns(
            path_lower, self.RECON_PATTERNS
        )
        if recon_score > max_confidence and not patterns_found:
            max_confidence = recon_score
            attack_type = "reconnaissance"
        patterns_found.extend(recon_patterns)

        # Login attempt detection
        if ("/login" in path_lower or "/auth" in path_lower) and getattr(
            event, "method", ""
        ) == "POST":
            if attack_type == "other":
                attack_type = "login_attempt"
                max_confidence = max(max_confidence, 0.5)
            rules_matched.append("login_endpoint_post")

        # Extract IOCs
        iocs = self._extract_iocs(event)

        # Determine severity
        severity = self._calculate_severity(max_confidence, attack_type)

        return {
            "attack_type": attack_type,
            "severity": severity,
            "confidence": round(max_confidence, 2),
            "patterns": list(set(patterns_found)),
            "rules": list(set(rules_matched)),
            "iocs": iocs,
        }

    def analyze_credentials(self, username: str, password: str) -> Dict[str, Any]:
        """Analyse a captured username/password pair."""
        result = {
            "is_default": False,
            "is_common_password": False,
            "password_strength": "unknown",
            "credential_type": "unknown",
        }

        if (username.lower(), password.lower()) in self.DEFAULT_CREDENTIALS:
            result["is_default"] = True
            result["credential_type"] = "default_credential"

        if password.lower() in self.COMMON_PASSWORDS:
            result["is_common_password"] = True

        # Strength heuristic
        if len(password) == 0:
            result["password_strength"] = "empty"
        elif len(password) < 6:
            result["password_strength"] = "very_weak"
        elif len(password) < 8:
            result["password_strength"] = "weak"
        elif (
            re.search(r"[A-Z]", password)
            and re.search(r"[0-9]", password)
            and re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
        ):
            result["password_strength"] = "strong"
        else:
            result["password_strength"] = "moderate"

        # Credential type
        if result.get("credential_type") == "default_credential":
            pass
        elif "admin" in username.lower():
            result["credential_type"] = "admin_attempt"
        elif "@" in username:
            result["credential_type"] = "email_based"
        elif username.lower() in ["root", "administrator", "system", "sa"]:
            result["credential_type"] = "system_account"
        else:
            result["credential_type"] = "standard"

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_corpus(self, event) -> str:
        parts = [
            getattr(event, "path", "") or "",
            getattr(event, "query_string", "") or "",
            getattr(event, "body", "") or "",
        ]
        body_json = getattr(event, "body_json", None)
        if body_json:
            parts.append(json.dumps(body_json))
        headers = getattr(event, "headers", None)
        if headers:
            parts.append(json.dumps(headers))
        return " ".join(parts).lower()

    def _check_patterns(
        self, text: str, patterns: List[Tuple[str, str, float]]
    ) -> Tuple[float, List[str]]:
        max_confidence = 0.0
        matched: List[str] = []
        for pattern, name, confidence in patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                    matched.append(name)
                    max_confidence = max(max_confidence, confidence)
            except re.error:
                continue
        return max_confidence, matched

    def _calculate_severity(self, confidence: float, attack_type: str) -> str:
        critical_types = {"command_injection", "xxe", "ssrf", "path_traversal"}
        high_types = {"sql_injection", "xss", "auth_bypass", "data_exfil"}

        if attack_type in critical_types:
            if confidence >= 0.8:
                return "critical"
            if confidence >= 0.5:
                return "high"
        elif attack_type in high_types:
            if confidence >= 0.8:
                return "high"
            if confidence >= 0.5:
                return "medium"

        if confidence >= 0.7:
            return "medium"
        if confidence >= 0.3:
            return "low"
        return "info"

    def _extract_iocs(self, event) -> List[Dict[str, str]]:
        """Extract Indicators of Compromise from request data."""
        iocs: List[Dict[str, str]] = []
        seen: set = set()

        text = " ".join(
            [
                getattr(event, "path", "") or "",
                getattr(event, "query_string", "") or "",
                getattr(event, "body", "") or "",
            ]
        )

        def add_ioc(ioc_type: str, value: str) -> None:
            key = "{}:{}".format(ioc_type, value)
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value})

        # IP addresses (exclude loopback)
        for ip in re.findall(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            text,
        ):
            if not ip.startswith("127.") and ip != "0.0.0.0":
                add_ioc("ip", ip)

        # Domain names
        for domain in re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
            text,
            re.IGNORECASE,
        ):
            if "." in domain and len(domain) > 4:
                add_ioc("domain", domain.lower())

        # File paths
        for path in re.findall(r"(?:/[\w.\-]+){2,}", text):
            if len(path) > 5:
                add_ioc("path", path)

        # MD5 hashes
        for h in re.findall(r"\b[a-fA-F0-9]{32}\b", text):
            add_ioc("md5", h.lower())

        # SHA-1 hashes
        for h in re.findall(r"\b[a-fA-F0-9]{40}\b", text):
            add_ioc("sha1", h.lower())

        # SHA-256 hashes
        for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
            add_ioc("sha256", h.lower())

        return iocs[:25]

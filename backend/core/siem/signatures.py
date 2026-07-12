"""
Attack Signature Engine
"""

import re
import json
import hashlib
from typing import Any, Dict, List, Tuple

SIGNATURES: List[Tuple[str, str, float]] = [
    (r"'\s*(or|and)\s+[\d'\"]+\s*=\s*[\d'\"]+", "sqli_boolean_basic", 0.95),
    (r"union\s+(all\s+)?select", "sqli_union_select", 0.97),
    (r";\s*(drop|truncate|alter|delete)\s+table", "sqli_destructive_ddl", 0.99),
    (r"select\s+.{1,80}\s+from\s+\w+", "sqli_select_from", 0.82),
    (r"insert\s+into\s+\w+", "sqli_insert", 0.80),
    (r"update\s+\w+\s+set\s+\w+\s*=", "sqli_update", 0.80),
    (r"exec(\s|\()+(xp_|sp_)", "sqli_stored_proc", 0.98),
    (r"xp_cmdshell", "sqli_xp_cmdshell", 0.99),
    (r"information_schema\.(tables|columns)", "sqli_info_schema", 0.95),
    (r"sleep\s*\(\s*\d+\s*\)", "sqli_time_sleep", 0.93),
    (r"benchmark\s*\(\s*\d+", "sqli_benchmark", 0.92),
    (r"waitfor\s+delay\s+'", "sqli_waitfor", 0.97),
    (r"pg_sleep\s*\(", "sqli_pg_sleep", 0.93),
    (r"load_file\s*\(", "sqli_load_file", 0.92),
    (r"into\s+(out|dump)file", "sqli_outfile", 0.97),
    (r"0x[0-9a-f]{6,}", "sqli_hex_literal", 0.72),
    (r"char\s*\(\s*\d{2,3}", "sqli_char_fn", 0.77),
    (r"group_concat\s*\(", "sqli_group_concat", 0.88),
    (r"extractvalue\s*\(", "sqli_extractvalue", 0.92),
    (r"updatexml\s*\(", "sqli_updatexml", 0.92),
    (r"floor\s*\(rand\s*\(", "sqli_floor_rand", 0.90),
    (r"(--|#|/\*)\s*$", "sqli_comment_eol", 0.68),
    (r"'\s*;\s*--", "sqli_comment_inject", 0.88),
    (r"declare\s+@\w+", "sqli_mssql_declare", 0.90),
    (r"cast\s*\(.+\s+as\s+\w+\)", "sqli_cast", 0.72),
    (r"convert\s*\(.+,\s*.+\)", "sqli_convert", 0.70),
    (r"sys\.(tables|columns|objects)", "sqli_sys_catalog", 0.90),
    (r"user()\s*=\s*0x", "sqli_user_hex", 0.88),
    (r"@@version", "sqli_version_var", 0.90),
    (r"@@datadir", "sqli_datadir_var", 0.90),
    (r"<script[\s>\/]", "xss_script_open", 0.97),
    (r"</script\s*>", "xss_script_close", 0.92),
    (r"javascript\s*:", "xss_js_proto", 0.97),
    (
        r"on(error|load|click|mouseover|focus|blur|input|change|submit|keyup|keydown)\s*=",
        "xss_event_handler",
        0.92,
    ),
    (r"eval\s*\(", "xss_eval", 0.83),
    (r"document\s*\.\s*cookie", "xss_cookie", 0.97),
    (r"document\s*\.\s*write\s*\(", "xss_doc_write", 0.87),
    (r"\.innerHTML\s*=", "xss_innerhtml", 0.83),
    (r"window\s*\.\s*location", "xss_location", 0.78),
    (r"<img[^>]+src\s*=\s*['\"]?javascript", "xss_img_js", 0.97),
    (r"<(iframe|frame|object|embed|applet)", "xss_embed_tag", 0.78),
    (r"vbscript\s*:", "xss_vbscript", 0.92),
    (r"expression\s*\(", "xss_css_expr", 0.87),
    (r"String\.fromCharCode\s*\(", "xss_fromcharcode", 0.87),
    (r"<svg[^>]*(onload|onerror)\s*=", "xss_svg_event", 0.97),
    (r"<math[^>]*href\s*=\s*['\"]?javascript", "xss_mathml", 0.92),
    (r"&#x?[0-9a-f]{2,4};", "xss_html_entity", 0.65),
    (r"\\u00[0-9a-f]{2}", "xss_unicode_esc", 0.62),
    (r"<details[^>]*open[^>]*ontoggle", "xss_details_toggle", 0.95),
    (r"data:text/html", "xss_data_uri_html", 0.88),
    (r"srcdoc\s*=", "xss_srcdoc", 0.85),
    (r"importScripts\s*\(", "xss_import_scripts", 0.85),
    (r"fetch\s*\(\s*['\"]http", "xss_fetch_exfil", 0.80),
    (r"new\s+Function\s*\(", "xss_new_function", 0.85),
    (r"\.\./", "traversal_dotdot_slash", 0.90),
    (r"\.\.\\", "traversal_dotdot_bs", 0.90),
    (r"%2e%2e%2f", "traversal_url_enc", 0.95),
    (r"%2e%2e/", "traversal_partial_enc", 0.90),
    (r"\.\.%2f", "traversal_mixed_enc", 0.90),
    (r"%252e%252e", "traversal_double_enc", 0.95),
    (r"/etc/passwd", "traversal_etc_passwd", 0.99),
    (r"/etc/(shadow|hosts|group|crontab)", "traversal_etc_sensitive", 0.99),
    (r"c:\\\\windows|c:/windows", "traversal_win_sys", 0.97),
    (r"cmd\.exe|command\.com", "traversal_cmd_exe", 0.99),
    (r"/bin/(bash|sh|zsh|ksh)", "traversal_shell", 0.92),
    (r"win\.ini|boot\.ini|system\.ini", "traversal_win_ini", 0.90),
    (r"/proc/self/(environ|cmdline|fd)", "traversal_proc_self", 0.90),
    (r"/var/log/", "traversal_var_log", 0.78),
    (r"\x00", "traversal_null_byte", 0.85),
    (r";\s*(ls|cat|id|whoami|uname|pwd|env|printenv)\b", "cmdinj_unix_enum", 0.93),
    (r"\|\s*(ls|cat|id|whoami|uname|wget|curl|nc)\b", "cmdinj_pipe", 0.93),
    (r"&&\s*(ls|cat|id|whoami)", "cmdinj_and", 0.88),
    (r"`[^`]{1,200}`", "cmdinj_backtick", 0.83),
    (r"\$\([^)]{1,200}\)", "cmdinj_subshell", 0.87),
    (r";\s*(wget|curl)\s+http", "cmdinj_download", 0.97),
    (r";\s*nc\s+(-[elp]+\s+)?\d{2,5}", "cmdinj_netcat", 0.97),
    (r";\s*python\d?\s+-c\s+['\"]", "cmdinj_python", 0.93),
    (r";\s*(perl|ruby|php|node)\s+-e\s+", "cmdinj_scripting", 0.93),
    (r"/dev/tcp/", "cmdinj_dev_tcp", 0.97),
    (r"base64\s+-d\s+", "cmdinj_base64_dec", 0.83),
    (r"chmod\s+[0-7]{3,4}\s+", "cmdinj_chmod", 0.87),
    (r"crontab\s+-[elu]", "cmdinj_crontab", 0.90),
    (r"mkfifo\s+\S+", "cmdinj_mkfifo", 0.92),
    (r"nohup\s+", "cmdinj_nohup", 0.82),
    (r";\s*powershell(\s+-\w+)+", "cmdinj_powershell", 0.95),
    (r"IEX\s*\(", "cmdinj_iex", 0.97),
    (r"Invoke-Expression", "cmdinj_invoke_expr", 0.97),
    (r"cmd\s*/[cC]\s+", "cmdinj_cmd_c", 0.92),
    (r"certutil\s+(-urlcache|-decode)", "cmdinj_certutil", 0.95),
    (r"mshta\s+http", "cmdinj_mshta", 0.97),
    (r"http://(127\.0\.0\.1|localhost)", "ssrf_loopback", 0.92),
    (r"http://0\.0\.0\.0", "ssrf_zero_host", 0.88),
    (r"http://169\.254\.169\.254", "ssrf_aws_imds", 0.99),
    (r"http://metadata\.google\.internal", "ssrf_gcp_metadata", 0.99),
    (r"http://100\.100\.100\.200", "ssrf_alibaba_imds", 0.99),
    (r"http://192\.168\.\d+\.\d+", "ssrf_rfc1918_192", 0.82),
    (r"http://10\.\d+\.\d+\.\d+", "ssrf_rfc1918_10", 0.82),
    (r"http://172\.(1[6-9]|2\d|3[01])\.", "ssrf_rfc1918_172", 0.82),
    (r"file:///", "ssrf_file_scheme", 0.97),
    (r"dict://", "ssrf_dict_scheme", 0.92),
    (r"gopher://", "ssrf_gopher_scheme", 0.92),
    (r"ftp://[^@]+@", "ssrf_ftp_creds", 0.87),
    (r"sftp://", "ssrf_sftp", 0.85),
    (r"ldap://", "ssrf_ldap_scheme", 0.88),
    (r"imds/latest/meta-data", "ssrf_aws_imds_path", 0.99),
    (r"<!ENTITY\s+\w+\s+SYSTEM", "xxe_entity_system", 0.97),
    (r"<!DOCTYPE[^>]+SYSTEM\s+['\"]", "xxe_doctype_system", 0.97),
    (r"<!DOCTYPE[^>]+PUBLIC\s+['\"]", "xxe_doctype_public", 0.88),
    (r"<!ENTITY\s+%\s+\w+", "xxe_param_entity", 0.95),
    (r"ENTITY\s+\w+\s+SYSTEM\s+['\"]file://", "xxe_file_entity", 0.99),
    (r"<!ATTLIST[^>]+CDATA", "xxe_attlist", 0.80),
    (r"O:\d+:\"[A-Za-z]+\"", "deser_php_object", 0.95),
    (r"rO0AB", "deser_java_base64", 0.97),
    (r"aced0005", "deser_java_hex", 0.97),
    (r"\$\{.*Runtime.*exec", "deser_java_runtime", 0.99),
    (r"__reduce__|__import__", "deser_python_pickle", 0.95),
    (r"Marshal\.load|YAML\.load", "deser_ruby_marshal", 0.95),
    (r"BinaryFormatter", "deser_dotnet_binary", 0.90),
    (r"(require|include)(_once)?\s*\(['\"]http", "rfi_remote_include", 0.97),
    (
        r"(require|include)(_once)?\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)",
        "lfi_user_input_include",
        0.97,
    ),
    (r"php://filter", "lfi_php_filter", 0.95),
    (r"php://input", "lfi_php_input", 0.90),
    (r"expect://", "lfi_php_expect", 0.97),
    (r"zip://", "lfi_zip_wrapper", 0.88),
    (r"data://text/plain", "lfi_data_wrapper", 0.90),
    (r"phar://", "lfi_phar_wrapper", 0.90),
    (r"\{\{.{1,80}\}\}", "ssti_double_brace", 0.88),
    (r"\{%.{1,80}%\}", "ssti_block_tag", 0.85),
    (r"\$\{.{1,80}\}", "ssti_dollar_brace", 0.83),
    (r"<%=.{1,80}%>", "ssti_erb_tag", 0.88),
    (r"#{.{1,80}}", "ssti_ruby_interp", 0.80),
    (r"\{\{config\.__class__", "ssti_flask_config", 0.99),
    (r"__class__.*__mro__", "ssti_python_mro", 0.99),
    (r"lipsum|cycler|joiner|namespace", "ssti_jinja2_globals", 0.88),
    (r"freemarker|velocity|smarty", "ssti_template_engine", 0.83),
    (r"\*\)\(\|", "ldap_wildcard_or", 0.97),
    (r"\(\|\(", "ldap_or_filter", 0.92),
    (r"\)\s*\(\s*\|", "ldap_close_or", 0.90),
    (r"cn=\*", "ldap_cn_wildcard", 0.85),
    (r"objectClass=\*", "ldap_objectclass_wild", 0.88),
    (r"\(\&\(\w+=", "ldap_and_filter", 0.83),
    (r"\$where\s*:", "nosql_where", 0.97),
    (r"\$gt\s*:|(\$lt\s*:|\$ne\s*:|\$in\s*:)", "nosql_comparison_op", 0.92),
    (r"\$regex\s*:", "nosql_regex_op", 0.90),
    (r"\$or\s*:\s*\[", "nosql_or_op", 0.90),
    (r"'\s*\|\|\s*'1", "nosql_boolean_bypass", 0.95),
    (r";\s*return\s+true", "nosql_js_return_true", 0.97),
    (r"(\r\n|\r|\n)(Set-Cookie|Location|Content-Type)\s*:", "header_crlf_inject", 0.97),
    (r"%0[aAdD](Set-Cookie|Location)", "header_crlf_encoded", 0.97),
    (r"\r\nHTTP/", "header_response_split", 0.99),
    (
        r"(redirect|return|next|url|redir|dest|destination|continue|forward)\s*=\s*https?://(?![^/]*(yourdomain|localhost))",
        "redirect_open",
        0.83,
    ),
    (r"//[a-z0-9.-]+\.[a-z]{2,}/", "redirect_protocol_rel", 0.78),
    (r"\\\\[a-z0-9.-]+\\", "redirect_unc_path", 0.88),
    (
        r"(admin|root|administrator|superuser)\s*['\"]?\s*:\s*['\"]?\s*(admin|root|password|123)",
        "auth_default_creds",
        0.90,
    ),
    (r"password\s*=\s*['\"]?\s*['\"]", "auth_empty_password", 0.85),
    (
        r"(bypass|skip|ignore)\s*(auth|authentication|login|security)",
        "auth_bypass_keyword",
        0.88,
    ),
    (r"x-forwarded-for\s*:\s*127\.0\.0\.1", "auth_xff_spoof", 0.90),
    (r"x-real-ip\s*:\s*127\.0\.0\.1", "auth_xri_spoof", 0.88),
    (r"x-originating-ip\s*:\s*127\.", "auth_xoi_spoof", 0.88),
    (r"x-custom-ip-authorization", "auth_custom_ip_header", 0.87),
    (r"(hydra|medusa|ncrack|patator|crowbar)", "bruteforce_tool_ua", 0.97),
    (r"password\d{1,4}[!@#$]?", "bruteforce_pattern_pass", 0.72),
    (
        r"(pass|pwd|password)\s*=\s*(123456|qwerty|abc123|letmein|welcome)",
        "bruteforce_common_pass",
        0.90,
    ),
    (r"\.(env|git|svn|hg|bzr)/", "recon_vcs_dotfile", 0.92),
    (r"/(wp-admin|wp-login|xmlrpc)\.php", "recon_wordpress", 0.85),
    (r"/(phpmyadmin|adminer|dbadmin)", "recon_db_admin", 0.88),
    (r"/actuator(/|$)", "recon_spring", 0.88),
    (r"/__debug__", "recon_django_debug", 0.85),
    (r"/server-status", "recon_apache_status", 0.83),
    (r"/phpinfo(\.php)?", "recon_phpinfo", 0.85),
    (
        r"/(backup|bak|old|archive|dump)\.(sql|zip|tar|gz|bz2|7z)",
        "recon_backup_file",
        0.90,
    ),
    (r"/config\.(php|yml|yaml|json|xml|ini)", "recon_config_file", 0.85),
    (r"/(robots|sitemap)\.(txt|xml)", "recon_crawler", 0.45),
    (r"nmap|masscan|shodan|censys|fofa", "recon_scanner_ua", 0.95),
    (r"sqlmap|nikto|dirbuster|gobuster|wfuzz|ffuf", "recon_attack_tool_ua", 0.99),
    (r"curl/\d|python-requests|go-http-client", "recon_scripted_client", 0.70),
    (r"/\.well-known/security\.txt", "recon_security_txt", 0.45),
    (r"/(console|shell|terminal|exec)(\.php)?", "recon_shell_path", 0.90),
    (
        r"(cmd|shell|exec|system|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)",
        "webshell_php_exec",
        0.99,
    ),
    (r"eval\s*\(\s*base64_decode\s*\(", "webshell_php_b64", 0.99),
    (r"eval\s*\(\s*gzinflate", "webshell_php_gz", 0.99),
    (r"c99|r57|b374k|wso shell", "webshell_known_name", 0.99),
    (r"<\?php.*system\s*\(", "webshell_php_system", 0.99),
    (r"\"cmd\"\s*,\s*\"/c\"", "webshell_aspx_cmd", 0.99),
    (r"__proto__\s*[\[.]", "proto_pollution", 0.95),
    (r"constructor\s*\[", "proto_constructor", 0.88),
    (r"prototype\s*\[", "proto_prototype", 0.88),
    (r"\[\"__proto__\"\]", "proto_quoted", 0.95),
]


_CATEGORY_MAP = {
    "sqli_": "sql_injection",
    "xss_": "xss",
    "traversal_": "path_traversal",
    "cmdinj_": "command_injection",
    "ssrf_": "ssrf",
    "xxe_": "xxe",
    "deser_": "deserialization",
    "rfi_": "rfi",
    "lfi_": "lfi",
    "ssti_": "ssti",
    "ldap_": "ldap_injection",
    "nosql_": "nosql_injection",
    "header_": "header_injection",
    "redirect_": "open_redirect",
    "auth_": "auth_bypass",
    "bruteforce_": "brute_force",
    "recon_": "reconnaissance",
    "webshell_": "web_shell",
    "proto_": "prototype_pollution",
}

SEVERITY_MAP = {
    "web_shell": "critical",
    "command_injection": "critical",
    "xxe": "critical",
    "ssrf": "critical",
    "deserialization": "critical",
    "path_traversal": "high",
    "sql_injection": "high",
    "ssti": "high",
    "lfi": "high",
    "rfi": "high",
    "ldap_injection": "high",
    "nosql_injection": "high",
    "xss": "medium",
    "header_injection": "medium",
    "open_redirect": "medium",
    "auth_bypass": "medium",
    "prototype_pollution": "medium",
    "brute_force": "low",
    "reconnaissance": "low",
    "other": "info",
}


def classify(corpus: str) -> dict:
    """
    Run all signatures against the lowercased corpus string.
    Returns { attack_type, severity, confidence, patterns_matched, rule_ids }.
    """
    corpus_lower = corpus.lower()
    matched_rules = []
    category_scores: dict = {}

    for pattern, rule_id, confidence in SIGNATURES:
        try:
            if re.search(pattern, corpus_lower, re.IGNORECASE | re.DOTALL):
                matched_rules.append({"rule": rule_id, "confidence": confidence})
                for prefix, cat in _CATEGORY_MAP.items():
                    if rule_id.startswith(prefix):
                        if (
                            cat not in category_scores
                            or category_scores[cat] < confidence
                        ):
                            category_scores[cat] = confidence
                        break
        except re.error:
            continue

    if not category_scores:
        return {
            "attack_type": "other",
            "severity": "info",
            "confidence": 0.0,
            "patterns_matched": [],
            "rule_ids": [],
        }

    best_type = max(category_scores, key=lambda k: category_scores[k])
    best_conf = category_scores[best_type]

    return {
        "attack_type": best_type,
        "severity": SEVERITY_MAP.get(best_type, "info"),
        "confidence": round(best_conf, 2),
        "patterns_matched": [r["rule"] for r in matched_rules],
        "rule_ids": matched_rules,
        "all_categories": category_scores,
    }


def is_attack(corpus: str, threshold: float = 0.50) -> bool:
    result = classify(corpus)
    return result["confidence"] >= threshold


def fingerprint_session(
    ip: str, ua: str, accept_lang: str = "", accept_enc: str = ""
) -> str:
    raw = "|".join([ip, ua, accept_lang, accept_enc])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

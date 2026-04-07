from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    supabase_url: str = ""
    supabase_key: str = ""
    wpscan_api_token: str = ""
    patchstack_api_token: str = ""  # ← add this
    researcher_tier: str = "standard"
    app_env: str = "development"
    cors_origins: str = '["http://localhost:5173"]'

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


# Wordfence install count thresholds by tier and vuln class
SCOPE_THRESHOLDS = {
    "high_threat": 25,          # RCE, Auth Bypass, Priv Esc, etc — all tiers
    "common_dangerous": 500,    # Stored XSS, SQLi — all tiers
    "other": {
        "standard":    50_000,
        "resourceful": 10_000,
        "1337":        500,
    },
}

HIGH_THREAT_TYPES = {
    "arbitrary_file_upload",
    "arbitrary_file_deletion",
    "arbitrary_options_update",
    "remote_code_execution",
    "authentication_bypass",
    "privilege_escalation",
}

COMMON_DANGEROUS_TYPES = {
    "stored_xss",
    "sql_injection",
}

# CSRF grep patterns
CSRF_PATTERNS = {
    "ajax_handlers": r"add_action\s*\(\s*['\"]wp_ajax_",
    "admin_post":    r"add_action\s*\(\s*['\"]admin_post_",
    "post_data":     r"\$_POST\s*\[",
    "get_data":      r"\$_GET\s*\[",
    "request_data":  r"\$_REQUEST\s*\[",
    "update_option": r"update_option\s*\(",
    "add_option":    r"add_option\s*\(",
    "delete_option": r"delete_option\s*\(",
    "wp_insert":     r"wp_insert_",
    "wp_update":     r"wp_update_",
    "wp_delete":     r"wp_delete_",
}

NONCE_PATTERNS = {
    "check_ajax_referer":  r"check_ajax_referer\s*\(",
    "check_admin_referer": r"check_admin_referer\s*\(",
    "wp_verify_nonce":     r"wp_verify_nonce\s*\(",
    "wp_nonce_field":      r"wp_nonce_field\s*\(",
    "wp_create_nonce":     r"wp_create_nonce\s*\(",
    "nonce":               r"nonce",
}

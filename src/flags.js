const FLAGS = {
  command_injection: "FLAG{ops_tool_shell_breakout}",
  sqli_login: "FLAG{legacy_login_bypass}",
  sqli_blind: "FLAG{boolean_oracle_invoice_probe}",
  sqli_second_order: "FLAG{stored_filter_bites_back}",
  xss_reflected: "FLAG{search_preview_breakout}",
  xss_stored: "FLAG{comment_feed_kept_receipts}",
  ssti: "FLAG{template_preview_went_too_far}",
  idor: "FLAG{cross_tenant_object_walk}",
  csrf: "FLAG{session_riding_on_profile}",
  broken_access: "FLAG{support_badge_became_admin}",
  business_logic: "FLAG{negative_seats_positive_access}",
  file_upload: "FLAG{branding_asset_executes_code}",
  insecure_deserialization: "FLAG{imported_preferences_executed}",
  jwt: "FLAG{decode_me_if_you_can}",
  api_mass_assignment: "FLAG{patch_role_patch_power}",
  api_missing_auth: "FLAG{widget_feed_no_guardrails}"
};

module.exports = { FLAGS };

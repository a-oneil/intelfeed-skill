#!/usr/bin/env python3
"""CLI for IntelFeed API — used by Claude skills to interact with IntelFeed.

Executes one or more tool calls against the running IntelFeed API and prints
JSON results to stdout. Zero external dependencies — stdlib only.

Environment variables:
    INTELFEED_API_URL       Base URL of the IntelFeed API (default: https://intelfeed.cc)
    INTELFEED_USERNAME      Username for authentication
    INTELFEED_PASSWORD      Password for authentication

Usage:
    # Single tool call
    python intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'

    # Tool call with no arguments
    python intelfeed_cli.py get_dashboard_stats

    # Multiple tool calls in one invocation
    python intelfeed_cli.py search_entries '{"query": "APT29"}' get_feeds '{"limit": 10}'

    # List available tools
    python intelfeed_cli.py --list-tools

    # Show help for a specific tool
    python intelfeed_cli.py --help-tool search_entries
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("INTELFEED_API_URL", "https://intelfeed.cc").rstrip("/")
WEB_URL = os.environ.get("INTELFEED_WEB_URL", "https://intelfeed.cc").rstrip("/")
USERNAME = os.environ.get("INTELFEED_USERNAME", "")
PASSWORD = os.environ.get("INTELFEED_PASSWORD", "")

# Hard read-only mode. When INTELFEED_READ_ONLY is truthy, any call to a WRITE
# tool is refused BEFORE hitting the API — the process prints a JSON error to
# stdout and exits non-zero. This is the physical boundary that keeps the
# read-only copilot from mutating data even if its system prompt is bypassed.
READ_ONLY = os.environ.get("INTELFEED_READ_ONLY", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# Explicit denylist of tools that create / mutate / delete state. Any tool NOT
# in this set (search_*/get_*/list_*/check_*/pivot_*/export_*/validate_*/
# generate_* read-only analyses, etc.) is a read tool and runs normally.
# Kept explicit (not prefix-inferred) so a new write tool must be consciously
# added here — a missing entry fails safe toward "read" only for genuinely
# read-only tools; every mutating tool below is enumerated.
WRITE_TOOLS: frozenset[str] = frozenset(
    {
        # entity creation
        "create_threat_actor",
        "create_malware",
        "create_detection_rule",
        "create_campaign",
        "create_feed",
        "add_telegram_feed",
        "create_note",
        "create_entity_note",
        "create_automation_rule",
        "create_intel_report",
        "create_requirement",
        # AI-identify tools that PERSIST new / linked entities
        "extract_ttps",
        "extract_cves",
        "extract_threat_actors",
        "extract_malware",
        "run_ai_task",
        # tagging / linking / campaign membership
        "add_tag",
        "add_to_campaign",
        "link_entities",
        # updates
        "update_entity_profile",
        "update_requirement",
        # merges / reclassification (destructive)
        "merge_threat_actors",
        "merge_malware",
        "merge_vendors",
        "merge_products",
        "merge_tools",
        "reclassify_entity",
        # automation execution (mutates data via actions)
        "test_automation_rule",
        "run_automation_rule",
        # report generation / publishing (persists reports)
        "publish_report",
        "generate_full_report",
        "generate_campaign_report",
        "export_report",
        # deletes
        "delete_entity",
    }
)

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "add_requirement_match": {
        "description": (
            "Manually match an entry to an intelligence requirement (match_type 'manual'). Increments "
            "the requirement's match count and stamps last_matched_at. Errors if the entry is already "
            "matched. Relevance: high, medium, or low."
        ),
        "params": {
            "requirement_id": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "relevance": {
                "type": 'str',
                "default": 'medium',
                "enum": ['high', 'medium', 'low'],
            },
        },
    },
    "add_tag": {
        "description": 'Tag an entry with an existing or new tag.',
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "tag_name": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "add_telegram_feed": {
        "description": (
            "Subscribe to a Telegram channel feed. Requires server-side Telegram setup "
            "(scripts/telegram_login.py). The channel must be public OR the IntelFeed account must "
            "already be a member. Accepts @handle, t.me/https://t.me URLs (including /s/ preview "
            "URLs), or a numeric channel id; invite links (+hash / joinchat) are rejected \u2014 join "
            "first, then subscribe by handle or id. Queues an initial fetch on creation. Optionally "
            "auto-attribute every message to a threat actor or campaign \u2014 use this for ransomware "
            "leak channels, hacktivist channels, and broker channels that are themselves the actor."
        ),
        "params": {
            "channel": {
                "type": 'str',
                "required": True,
            },
            "title": {
                "type": 'str',
                "default": None,
            },
            "include_media": {
                "type": 'bool',
                "default": True,
            },
            "extract_forwards": {
                "type": 'bool',
                "default": True,
            },
            "max_message_age_days": {
                "type": 'int',
                "default": 30,
            },
            "max_messages_per_fetch": {
                "type": 'int',
                "default": 200,
            },
            "fetch_interval_minutes": {
                "type": 'int',
                "default": 30,
            },
            "threat_actor_id": {
                "type": 'str',
                "default": None,
            },
            "campaign_id": {
                "type": 'str',
                "default": None,
            },
            "session_name": {
                "type": 'str',
                "default": None,
            },
            "category": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "add_to_campaign": {
        "description": (
            "Link an entry or entity to a campaign. Re-linking an already-linked entry/entity returns "
            "already_linked instead of an error. Note: the campaign UI and reports resolve names only "
            "for threat_actor, malware, cve, ttp and ransomware_victim links \u2014 other entity types are "
            "stored but render as bare IDs in campaign views."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "entity_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'ransomware_victim',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "default": None,
            },
            "role": {
                "type": 'str',
                "default": 'related',
                "enum": ['primary', 'secondary', 'related'],
            },
        },
    },
    "archive_intel_report": {
        "description": "Archive an intel report (status becomes 'archived'; the report is retained, not deleted).",
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "bookmark_entry": {
        "description": (
            "Set an entry's bookmarked flag for the current user (bookmarked=true by default; pass "
            "false to remove the bookmark). Syncs the flag to the search index. Returns the new "
            "value."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "bookmarked": {
                "type": 'bool',
                "default": None,
            },
        },
    },
    "build_detection_summary": {
        "description": (
            "Full detection engineering analysis: gathers all intelligence context for entries and "
            "produces comprehensive attack chain analysis and detection gaps. Optional focus steers "
            "the analysis angle; include_existing controls whether existing detection rules are "
            "folded into the context."
        ),
        "params": {
            "entry_ids": {
                "type": 'list[str]',
                "required": True,
            },
            "rule_formats": {
                "type": 'list[str]',
                "required": True,
            },
            "focus": {
                "type": 'str',
                "default": 'campaign',
                "enum": ['campaign', 'vulnerability', 'malware', 'actor'],
            },
            "include_existing": {
                "type": 'bool',
                "default": True,
            },
        },
    },
    "bulk_entry_action": {
        "description": (
            "Apply one state action to a list of entries for the current user: read, unread, star, "
            "unstar, bookmark, unbookmark, or hide (hide also marks the entries read). Syncs state to "
            "the search index. Returns the count of entries actually changed."
        ),
        "params": {
            "entry_ids": {
                "type": 'list[str]',
                "required": True,
            },
            "action": {
                "type": 'str',
                "required": True,
                "enum": ['bookmark', 'hide', 'read', 'star', 'unbookmark', 'unread', 'unstar'],
            },
        },
    },
    "bulk_unlink_entities": {
        "description": (
            "Remove up to 500 entry\u2192entity autolinks in one call. Each item is {entity_type, "
            "entity_id, entry_id}; items whose junction row no longer exists are skipped. Invalidates "
            "each affected entity's cached pivots/graphs. Returns the number actually deleted."
        ),
        "params": {
            "items": {
                "type": 'list[dict]',
                "required": True,
            },
        },
    },
    "check_detection_gaps": {
        "description": (
            "ATT&CK coverage analysis: observed TTPs vs non-draft detection rules, with per-tactic "
            "summary and the list of uncovered techniques. TTP-only \u2014 CVEs are not part of this "
            "analysis."
        ),
        "params": {},
    },
    "check_requirement_match": {
        "description": (
            "Check an entry against all active intelligence requirements using the real matching "
            "engine (linked-entity hits, then title/body keyword hits, gated by each requirement's "
            "min_relevance and feed filter). Read-only: persists nothing; also returns matches the "
            "automated pipeline already persisted for this entry."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "check_telemetry_feasibility": {
        "description": (
            "Check if detection rules are feasible given configured telemetry sources. Identifies "
            "what log sources are needed vs available."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "confirm_extraction_entities": {
        "description": (
            "Analyst sign-off on AI-created entities: clears the needs_review flag on the given "
            "entities of one type so they no longer show in the extraction review queue. Returns how "
            "many rows were updated."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['cve', 'malware', 'threat_actor', 'tool', 'ttp'],
            },
            "ids": {
                "type": 'list[str]',
                "required": True,
            },
        },
    },
    "confirm_relationship": {
        "description": (
            "Trust-ladder confirm: upgrade a relationship to source='analyst_confirmed' and "
            "confidence='confirmed', then invalidate cached pivots/graphs for both endpoints. Returns "
            "the updated relationship."
        ),
        "params": {
            "relationship_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "convert_detection_rule": {
        "description": (
            "Convert a detection rule to a different rule language using the AI provider assigned to "
            "the detection_rules task. Target formats: crowdstrike_ql, elastic_ql, kql, nuclei, "
            "panther, sigma, snort_suricata, splunk_spl, yara. Returns the converted content without "
            "changing the source rule. With save=true, the conversion is stored on the rule's "
            "metadata under rule_conversions (same place the UI keeps saved conversions)."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "target_format": {
                "type": 'str',
                "required": True,
                "enum": [
                    'crowdstrike_ql',
                    'elastic_ql',
                    'kql',
                    'nuclei',
                    'panther',
                    'sigma',
                    'snort_suricata',
                    'splunk_spl',
                    'yara',
                ],
            },
            "save": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "create_automation_rule": {
        "description": (
            "Set up an automation rule with trigger, conditions, and actions. Trigger types: "
            "on_correlation_event, on_cve_detected, on_keyword_match, on_manual, on_new_entry, "
            "on_schedule. Each action is {type, config}; valid action types: add_tags, "
            "add_to_campaign, bookmark_entry, branch, chain_rule, create_intel_report, create_note, "
            "export_to, extract_cves, extract_malware, extract_threat_actors, extract_ttps, "
            "generate_detection_rules, hide_entry, mark_priority, mark_read, remove_tags, "
            "run_ai_task, run_webhook, send_notification, star_entry. The rule is created enabled."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "trigger_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'on_correlation_event',
                    'on_cve_detected',
                    'on_keyword_match',
                    'on_manual',
                    'on_new_entry',
                    'on_schedule',
                ],
            },
            "trigger_config": {
                "type": 'dict',
                "default": None,
            },
            "conditions": {
                "type": 'dict',
                "default": None,
            },
            "actions": {
                "type": 'list[dict]',
                "required": True,
            },
        },
    },
    "create_campaign": {
        "description": (
            "Create a new campaign to track a threat operation and link entities/entries to it. TLP "
            "markings use TLP 2.0 (TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED); the legacy TLP:WHITE is "
            "accepted and normalized to TLP:CLEAR."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": 'active',
                "enum": ['active', 'monitoring', 'closed', 'historical'],
            },
            "tlp_marking": {
                "type": 'str',
                "default": 'TLP:GREEN',
                "enum": ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED', 'TLP:WHITE'],
            },
        },
    },
    "create_category": {
        "description": (
            "Create a feed category. Returns the existing category instead if one with the same name "
            "exists."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "create_detection_rule": {
        "description": (
            "Save a detection rule to the library. The rule is stored as a DRAFT (is_draft=true) \u2014 an "
            "analyst promotes it from the Detection workbench. Optional provenance: tags, reference "
            "URLs, and source entry UUIDs the rule was derived from."
        ),
        "params": {
            "title": {
                "type": 'str',
                "required": True,
            },
            "rule_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'crowdstrike_ql',
                    'elastic_ql',
                    'kql',
                    'nuclei',
                    'panther',
                    'sigma',
                    'snort_suricata',
                    'splunk_spl',
                    'yara',
                ],
            },
            "rule_content": {
                "type": 'str',
                "required": True,
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "severity": {
                "type": 'str',
                "default": None,
                "enum": ['critical', 'high', 'medium', 'low', 'info'],
            },
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "tags": {
                "type": 'list[str]',
                "default": None,
            },
            "references": {
                "type": 'list[str]',
                "default": None,
            },
            "source_entry_ids": {
                "type": 'list[str]',
                "default": None,
            },
        },
    },
    "create_entity_note": {
        "description": (
            "Add an analytical note to an intelligence entity. Supported entity types: campaign, "
            "country, cve, malware, mitigation, product, threat_actor, tool, ttp, vendor (matches the "
            "entity_notes DB constraint; ransomware victims are not supported)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "content": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "create_feed": {
        "description": (
            "Subscribe to a new feed. feed_type covers every registered adapter (rss, atom, youtube, "
            "podcast, reddit, github_releases, github_advisories, github_repo, nvd, mastodon, "
            "web_scraper, telegram, bluesky \u2014 for telegram prefer add_telegram_feed). Rejects "
            "duplicate URLs with a structured error and queues an initial fetch via Celery. Extended "
            "adapter types usually need an adapter_config (see the adapter's expected keys). If a "
            "named category does not exist the feed is still created and a warning is returned."
        ),
        "params": {
            "url": {
                "type": 'str',
                "required": True,
            },
            "title": {
                "type": 'str',
                "default": None,
            },
            "feed_type": {
                "type": 'str',
                "default": 'rss',
                "enum": [
                    'atom',
                    'bluesky',
                    'github_advisories',
                    'github_releases',
                    'github_repo',
                    'mastodon',
                    'nvd',
                    'podcast',
                    'reddit',
                    'rss',
                    'telegram',
                    'web_scraper',
                    'youtube',
                ],
            },
            "category": {
                "type": 'str',
                "default": None,
            },
            "adapter_config": {
                "type": 'dict',
                "default": None,
            },
        },
    },
    "create_glossary_term": {
        "description": (
            "Create a user glossary term. Requires name, category (free-form; NIST CSF functions "
            "govern/identify/protect/detect/respond/recover get special coloring), and description. "
            "Optional: maturity ('emerging', 'trending', or 'mature'), long_description, technologies "
            "(name + optional url), and search_terms aliases used for detection. Fails if a term with "
            "the same name already exists."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "category": {
                "type": 'str',
                "required": True,
            },
            "description": {
                "type": 'str',
                "required": True,
            },
            "maturity": {
                "type": 'str',
                "default": None,
                "enum": ['emerging', 'trending', 'mature'],
            },
            "long_description": {
                "type": 'str',
                "default": None,
            },
            "technologies": {
                "type": 'list[dict]',
                "default": None,
            },
            "search_terms": {
                "type": 'list[str]',
                "default": None,
            },
        },
    },
    "create_intel_report": {
        "description": (
            "Create a draft intelligence report from a template with linked entities and entries. "
            "Templates: actor_profile, campaign_tracker, detection_report, flash_alert, "
            "landscape_report. TLP 2.0 markings; the legacy TLP:WHITE is accepted and normalized to "
            "TLP:CLEAR."
        ),
        "params": {
            "title": {
                "type": 'str',
                "required": True,
            },
            "template_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'actor_profile',
                    'campaign_tracker',
                    'detection_report',
                    'flash_alert',
                    'landscape_report',
                ],
            },
            "entry_ids": {
                "type": 'list[str]',
                "default": None,
            },
            "entity_ids": {
                "type": 'dict',
                "default": None,
            },
            "tlp_marking": {
                "type": 'str',
                "default": 'TLP:GREEN',
                "enum": ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED', 'TLP:WHITE'],
            },
        },
    },
    "create_malware": {
        "description": (
            "Create a new malware family entity. Runs the entity resolver first: if the name or an "
            "alias matches an existing family, that entity is returned (created: false) with new "
            "aliases folded in; if the creation gates reject the name the result is blocked: true "
            "with a reason. malware_type is coerced onto the controlled vocabulary (raw value kept in "
            "metadata)."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "malware_type": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "create_note": {
        "description": (
            "Add an analyst note to an entry. Markdown content is rendered and stored as HTML (same "
            "as the notes API). If no title is given, one is derived from the first line of the "
            "content, falling back to the entry title."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "content": {
                "type": 'str',
                "required": True,
            },
            "title": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "create_requirement": {
        "description": 'Create a new Priority Intelligence Requirement (PIR).',
        "params": {
            "title": {
                "type": 'str',
                "required": True,
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "priority": {
                "type": 'str',
                "default": 'medium',
                "enum": ['critical', 'high', 'medium', 'low'],
            },
            "category": {
                "type": 'str',
                "default": 'operational',
                "enum": ['strategic', 'operational', 'tactical', 'technical'],
            },
            "keywords": {
                "type": 'list[str]',
                "required": True,
            },
            "auto_match": {
                "type": 'bool',
                "default": True,
            },
        },
    },
    "create_saved_search": {
        "description": (
            "Create a saved search from a query-language string (e.g. \"ransomware "
            "cve.severity:critical is:unread\"). Saved searches are shared across users and appear in "
            "the reader sidebar. display_name optionally sets a friendlier label than the name."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "query": {
                "type": 'str',
                "required": True,
            },
            "display_name": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "create_share_link": {
        "description": (
            "Create a public (unauthenticated) share link for an entry, or return the existing active "
            "one. ttl_days optionally sets an expiry on a newly created link (the API default is no "
            "expiry); it is ignored when an active link already exists. When server-side TTS is "
            "enabled, read-aloud audio is pre-generated best-effort with a 24h eviction TTL."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "ttl_days": {
                "type": 'float',
                "default": None,
            },
        },
    },
    "create_threat_actor": {
        "description": (
            "Create a new threat actor entity. Runs the entity resolver first: if the name or an "
            "alias matches an existing actor, that entity is returned (created: false) with new "
            "aliases folded in; if the creation gates reject the name (tombstone, dictionary word, "
            "etc.) the result is blocked: true with a reason instead of a new entity."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "country": {
                "type": 'str',
                "default": None,
            },
            "motivation": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "create_webhook_preset": {
        "description": (
            "Create a webhook preset \u2014 a reusable URL + payload + headers combination that automation "
            "rule actions can reference by preset id instead of repeating the URL."
        ),
        "params": {
            "name": {
                "type": 'str',
                "required": True,
            },
            "url": {
                "type": 'str',
                "default": '',
            },
            "payload": {
                "type": 'str',
                "default": '{}',
            },
            "headers": {
                "type": 'dict',
                "default": {},
            },
            "preset_type": {
                "type": 'str',
                "default": 'webhook',
            },
            "config": {
                "type": 'dict',
                "default": {},
            },
        },
    },
    "delete_automation_rule": {
        "description": (
            "Delete an automation rule permanently. REQUIRES user confirmation. First call returns a "
            "confirmation prompt with a token \u2014 present it to the user. Only call again with the "
            "confirmation_token after the user explicitly approves. To just stop a rule from running, "
            "use toggle_automation_rule instead."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_campaign": {
        "description": (
            "Delete a campaign and its entry/entity/saved-search links. Linked entries and entities "
            "themselves are NOT deleted. REQUIRES user confirmation. First call returns a "
            "confirmation prompt with link counts \u2014 present it to the user. Only call again with the "
            "confirmation_token after the user explicitly approves."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_detection_rule": {
        "description": (
            "Delete a detection rule permanently; its version history is removed with it. REQUIRES "
            "user confirmation: the first call returns a confirmation prompt and token \u2014 present it "
            "to the user and only call again with confirmation_token after they explicitly approve."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_entity": {
        "description": (
            "Delete a record: feed, entry, note, detection rule, campaign, automation rule, "
            "intelligence requirement, intel report, tag, or any intelligence entity (threat actor, "
            "malware, CVE, TTP, country, tool, vendor, product, mitigation). Intelligence entities "
            "get the same cleanup as the API delete endpoints: entry links and entity relationships "
            "are removed and the search-index document is dropped. No tombstone is written \u2014 the "
            "autolinker/extraction pipeline may re-create the entity from future articles; use the "
            "false-positive workflow if the name must stay gone. REQUIRES user confirmation. First "
            "call returns a confirmation prompt \u2014 present it to the user. Only call again with the "
            "confirmation_token after the user explicitly approves."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'feed',
                    'entry',
                    'note',
                    'detection_rule',
                    'campaign',
                    'automation_rule',
                    'intelligence_requirement',
                    'intel_report',
                    'ttp',
                    'threat_actor',
                    'malware',
                    'tag',
                    'cve',
                    'country',
                    'tool',
                    'vendor',
                    'product',
                    'mitigation',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_entity_note": {
        "description": 'Permanently delete an entity note. The entity it was attached to is not affected.',
        "params": {
            "note_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "delete_feed": {
        "description": (
            "Delete a feed and ALL of its entries (cascade), removing them from the search index "
            "first. REQUIRES user confirmation. First call returns a confirmation prompt with an "
            "entry count \u2014 present it to the user. Only call again with the confirmation_token after "
            "the user explicitly approves."
        ),
        "params": {
            "feed_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_glossary_term": {
        "description": (
            "Delete a user-created glossary term by UUID. Built-in system terms cannot be deleted. "
            "Single-row removal; no confirmation required."
        ),
        "params": {
            "term_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "delete_intel_report": {
        "description": (
            "Delete a draft intel report permanently (published or archived reports cannot be deleted "
            "\u2014 archive instead). REQUIRES user confirmation: the first call returns a confirmation "
            "prompt and token \u2014 present it to the user and only call again with confirmation_token "
            "after they explicitly approve."
        ),
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_note": {
        "description": 'Delete an analyst note. The entry it was attached to (if any) is not affected.',
        "params": {
            "note_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "delete_relationship": {
        "description": (
            "Hard-delete an entity\u2194entity relationship and invalidate cached pivots/graphs for both "
            "endpoints. Reversible via re-create, so no confirmation is required \u2014 but prefer "
            "reject_relationship for auto-extracted edges: a deleted row can be recreated by "
            "re-ingestion, a rejected one cannot."
        ),
        "params": {
            "relationship_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "delete_requirement": {
        "description": (
            "Delete an intelligence requirement (PIR) permanently, along with its entry matches. "
            "REQUIRES user confirmation: the first call returns a confirmation prompt and token \u2014 "
            "present it to the user and only call again with confirmation_token after they explicitly "
            "approve."
        ),
        "params": {
            "requirement_id": {
                "type": 'str',
                "required": True,
            },
            "confirmation_token": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "delete_saved_search": {
        "description": (
            "Delete a saved search by id. Saved searches are shared, so this removes it for all "
            "users; the underlying entries are untouched and the search is trivially recreatable from "
            "its name and query."
        ),
        "params": {
            "search_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "delete_webhook_preset": {
        "description": (
            "Delete a webhook preset. Automation actions referencing it by id will stop resolving \u2014 "
            "check rules that use it first."
        ),
        "params": {
            "preset_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "detect_glossary_terms": {
        "description": (
            "Detect which glossary terms appear in an entry's text (word-boundary matching over each "
            "term's name and search-term aliases). Returns matched terms with per-term match counts, "
            "highest first. Note: takes an entry UUID, not raw text \u2014 that is what the API supports."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "discover_telegram_channels": {
        "description": (
            "List every Telegram channel the IntelFeed bootstrap account is joined to, with "
            "is_subscribed = whether IntelFeed already ingests it. Use this to see which channels "
            "you've joined in your Telegram client app but haven't yet wired up as IntelFeed feeds."
        ),
        "params": {
            "session_name": {
                "type": 'str',
                "default": None,
            },
            "only_unsubscribed": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "export_attack_layer": {
        "description": (
            "Export MITRE ATT&CK Navigator layer JSON for visualization. With entry_id, uses the "
            "entry's linked techniques with real tactic and per-link confidence/source text; without "
            "it, covers observed techniques (linked to at least one entry, non-deprecated, top 500 by "
            "article count)."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "title": {
                "type": 'str',
                "default": 'IntelFeed ATT&CK Layer',
            },
        },
    },
    "export_campaign": {
        "description": (
            "Export a complete campaign intel package: linked entries, every entity type extracted "
            "from those entries (TTPs, CVEs, actors, malware, tools, vendors, products, countries, "
            "mitigations), explicitly linked entities, and detection rules sourced from the campaign."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "export_report": {
        "description": 'Export an intelligence report in markdown or HTML format.',
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
            "format": {
                "type": 'str',
                "required": True,
                "enum": ['markdown', 'html'],
            },
        },
    },
    "extract_cves": {
        "description": 'Extract CVE references from an entry and optionally enrich from NVD. Stores results.',
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "extract_malware": {
        "description": (
            "Identify malware families in an entry via the consolidated entry_analysis AI task (may "
            "return the cached ingest-time analysis instead of a fresh AI call). Creates or links "
            "malware entities."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "extract_threat_actors": {
        "description": (
            "Identify threat actors in an entry via the consolidated entry_analysis AI task (may "
            "return the cached ingest-time analysis instead of a fresh AI call). Creates or links "
            "threat actor entities."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "extract_ttps": {
        "description": (
            "Extract MITRE ATT&CK techniques (TTPs) from an entry. Always runs regex matching; use_ai "
            "adds the ttp_mapping AI task (its result is cached per entry \u2014 reruns reuse the current "
            "AIResult). Stores links."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "use_ai": {
                "type": 'bool',
                "default": True,
            },
        },
    },
    "fulfill_requirement": {
        "description": (
            "Mark an intelligence requirement fulfilled, optionally linking the intel report that "
            "fulfilled it (report_id)."
        ),
        "params": {
            "requirement_id": {
                "type": 'str',
                "required": True,
            },
            "report_id": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "generate_campaign_report": {
        "description": (
            "Generate an intelligence report from a campaign's linked entries and entities (draft + "
            "queued AI generation). Templates: actor_profile, campaign_tracker, detection_report, "
            "flash_alert, landscape_report (default campaign_tracker). TLP 2.0 markings; legacy "
            "TLP:WHITE is normalized to TLP:CLEAR."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "template_type": {
                "type": 'str',
                "default": 'campaign_tracker',
                "enum": [
                    'actor_profile',
                    'campaign_tracker',
                    'detection_report',
                    'flash_alert',
                    'landscape_report',
                ],
            },
            "title": {
                "type": 'str',
                "default": None,
            },
            "tlp_marking": {
                "type": 'str',
                "default": 'TLP:GREEN',
                "enum": ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED', 'TLP:WHITE'],
            },
        },
    },
    "generate_detection_rules": {
        "description": (
            "Generate detection rules from an entry's TTPs via the detection_rules AI task and store "
            "them as drafts. Supported formats: crowdstrike_ql, elastic_ql, kql, sigma, "
            "snort_suricata, splunk_spl, yara."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "rule_types": {
                "type": 'list[str]',
                "required": True,
            },
        },
    },
    "generate_full_report": {
        "description": (
            "Generate an AI-powered intelligence report from source entries (created as a draft, then "
            "AI generation is queued via Celery). Templates: actor_profile, campaign_tracker, "
            "detection_report, flash_alert, landscape_report. TLP 2.0 markings; legacy TLP:WHITE is "
            "normalized to TLP:CLEAR."
        ),
        "params": {
            "title": {
                "type": 'str',
                "required": True,
            },
            "template_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'actor_profile',
                    'campaign_tracker',
                    'detection_report',
                    'flash_alert',
                    'landscape_report',
                ],
            },
            "entry_ids": {
                "type": 'list[str]',
                "required": True,
            },
            "focus": {
                "type": 'str',
                "default": None,
            },
            "tlp_marking": {
                "type": 'str',
                "default": 'TLP:GREEN',
                "enum": ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED', 'TLP:WHITE'],
            },
        },
    },
    "get_analytics": {
        "description": (
            "Get platform analytics: trending entities, intelligence velocity, detection coverage "
            "gaps, and overview stats."
        ),
        "params": {
            "metric": {
                "type": 'str',
                "required": True,
                "enum": ['overview', 'trending', 'detection_coverage', 'velocity'],
            },
            "entity_type": {
                "type": 'str',
                "default": None,
            },
            "days": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_attack_layer": {
        "description": (
            "Get MITRE ATT&CK Navigator layer JSON for a specific entry's TTPs, or (without entry_id) "
            "for all observed techniques \u2014 those linked to at least one entry, excluding deprecated "
            "catalog techniques."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "title": {
                "type": 'str',
                "default": 'IntelFeed ATT&CK Coverage',
            },
        },
    },
    "get_automation_logs": {
        "description": 'Get recent automation execution logs.',
        "params": {
            "rule_id": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_automation_rules": {
        "description": 'List automation rules with optional label filter.',
        "params": {
            "label": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_automation_templates": {
        "description": 'List pre-built automation rule templates with categories.',
        "params": {},
    },
    "get_campaign": {
        "description": 'Get campaign details with timeline, linked entries, linked entities, and detection gaps.',
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaign_attack_layer": {
        "description": 'Get MITRE ATT&CK Navigator layer JSON for all TTPs linked to a campaign.',
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaign_detection_gaps": {
        "description": (
            "Telemetry-aware detection coverage for a campaign's TTPs: covered, library_only (rules "
            "blocked by missing telemetry), and gaps (no rule)."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaign_timeline": {
        "description": 'Get chronological entries in a campaign, sorted by publication date.',
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaigns": {
        "description": 'List campaigns with optional status filter.',
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['active', 'monitoring', 'closed', 'historical'],
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_correlation_events": {
        "description": (
            "Get recent correlation events \u2014 coverage gaps, trending entities, campaign and "
            "requirement matches, new TTPs/malware for known actors or malware, actor-malware "
            "co-occurrence, feed staleness/errors, exploit and CVE score changes, and KEV additions."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 30,
            },
            "unread_only": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "get_cve": {
        "description": (
            "Get CVE details including CVSS/EPSS scores, severity, CISA KEV status, GitHub PoC and "
            "Metasploit availability, structured NVD affected vendor/product links, and linked "
            "article count."
        ),
        "params": {
            "cve_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_daily_summary": {
        "description": (
            "Return the cached AI daily summary (briefing) for a day, or null if none has been "
            "generated. date is YYYY-MM-DD, defaulting to today (UTC). Read-only: this never "
            "generates a summary \u2014 generation runs via the daily_summary AI task/automation."
        ),
        "params": {
            "date": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "get_dashboard_stats": {
        "description": (
            "Get system-wide statistics: total entries, feeds, detection rules, counts for every "
            "entity type (ttp = observed techniques with linked articles; full catalog size in "
            "ttp_catalog_size), and recent activity (entries in the last 24h/7d)."
        ),
        "params": {},
    },
    "get_detection_rule": {
        "description": (
            "Get a single detection rule with full rule content, provenance (source "
            "repo/author/license/references), draft/published status, telemetry feasibility against "
            "the enabled Telemetry Sources inventory, and a syntax-validation summary."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_detection_rule_versions": {
        "description": (
            "List a detection rule's saved versions, newest first. Versions are snapshots taken "
            "whenever rule_content changed or a rollback occurred."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_detection_rules": {
        "description": (
            "List detection rules. Optionally filter by rule type (crowdstrike_ql, elastic_ql, kql, "
            "nuclei, panther, sigma, snort_suricata, splunk_spl, yara)."
        ),
        "params": {
            "rule_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'crowdstrike_ql',
                    'elastic_ql',
                    'kql',
                    'nuclei',
                    'panther',
                    'sigma',
                    'snort_suricata',
                    'splunk_spl',
                    'yara',
                ],
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_enrichment_data": {
        "description": (
            "Get enrichment results stored on an entity: CVE (EPSS, KEV, GitHub PoCs, Metasploit, NVD "
            "data), malware (Malpedia, Wikipedia), threat actor (Wikipedia), or TTP (Wikipedia)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['cve', 'malware', 'threat_actor', 'ttp'],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entity_graph": {
        "description": (
            "Build a relationship graph centered on an entity. Claims-only: edges are typed "
            "relationship records (verb, direction, confidence, provenance) at confirmed/reported "
            "confidence \u2014 pure co-occurrence pairs are excluded; co-occurrence data only enriches "
            "edges with proximity and evidence articles."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "depth": {
                "type": 'int',
                "default": 1,
            },
            "window_days": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_entity_link_stats": {
        "description": (
            "Autolinking health signals: total entry\u2192entity links by entity type and provenance "
            "source, the held-match (pending autolink) queue depth and how many held matches are "
            "high-confidence ready, plus the count of non-rejected entity\u2194entity relationships."
        ),
        "params": {},
    },
    "get_entity_timeline": {
        "description": 'Get chronological timeline of when an entity appeared in articles.',
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry": {
        "description": (
            "Fetch a single RSS entry by ID with full content and all extracted intelligence: TTPs, "
            "CVEs, threat actors, malware, tools, vendors, products, countries, and mitigations."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_graph": {
        "description": 'Get relationship graph for all entities linked to a single entry.',
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_insights": {
        "description": "Get actionable intelligence insights for a specific entry's entities.",
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_story": {
        "description": (
            "Chain follow-up/precursor articles to an entry via shared entities: within a \u00b130 day "
            "window, entries sharing at least one strong entity (CVE, threat actor, malware) or two "
            "entities of any type join the story. Ordered chronologically (a timeline, not a "
            "relevance ranking \u2014 use get_similar_entries for that)."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_extraction_stats": {
        "description": (
            "Aggregate stats over AI-created entities (created_via='ai_extraction' across threat "
            "actors, malware, tools, CVEs, TTPs): totals by type, needs-review / orphaned / "
            "likely-duplicate / auto-confirmed counts, and how many were created in the requested "
            "window vs the preceding one."
        ),
        "params": {
            "window": {
                "type": 'str',
                "default": '7d',
                "enum": ['24h', '30d', '7d', 'all'],
            },
        },
    },
    "get_feed_entries": {
        "description": 'List recent entries from a specific feed.',
        "params": {
            "feed_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "get_feed_value": {
        "description": 'Get feed value scores — composite 0-100 intelligence contribution metric per feed.',
        "params": {
            "days": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_feeds": {
        "description": (
            "List configured feeds of any registered adapter type (atom, bluesky, github_advisories, "
            "github_releases, github_repo, mastodon, nvd, podcast, reddit, rss, telegram, "
            "web_scraper, youtube) with health status."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "get_hygiene_feed": {
        "description": (
            "Chronological hygiene feed: a merge of the link-validator and entity-maintenance logs, "
            "normalized (action, mode, applied, subject, reason, affected-entity links, AI review "
            "verdict). Filter by action code (comma-separate for several), log source, mode, AI "
            "review verdict, pending-only, or a since timestamp. Read-only \u2014 applying or dismissing "
            "proposals happens in the Hygiene admin UI."
        ),
        "params": {
            "action": {
                "type": 'str',
                "default": None,
            },
            "source": {
                "type": 'str',
                "default": None,
                "enum": ['link_validator', 'entity_maintenance'],
            },
            "mode": {
                "type": 'str',
                "default": None,
                "enum": ['shadow', 'apply'],
            },
            "review": {
                "type": 'str',
                "default": None,
                "enum": ['approve', 'reject', 'unsure', 'unreviewed'],
            },
            "pending": {
                "type": 'bool',
                "default": False,
            },
            "since": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "get_hygiene_stats": {
        "description": (
            "Combined entity-hygiene counters across the link validator and entity-maintenance "
            "systems: operating modes (shadow/apply), pending reclassify advisories and "
            "merge/name/alias/vendor/id proposals, AI review verdict counts, orphan entity count, "
            "validator scan progress, last run times, and how many actions were applied in the last "
            "24h / 7d."
        ),
        "params": {},
    },
    "get_intel_report": {
        "description": 'Get a single intel report including its full content (all sections, metadata, references).',
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_malware": {
        "description": (
            "Get malware family profile with aliases, type, targeted sectors, associated actors, and "
            "the count of linked articles (article_count)."
        ),
        "params": {
            "malware_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_ransomware_disclosures": {
        "description": (
            "Reverse-chronological feed of ransomware leak-site victim disclosures (Leak Watch), with "
            "filters for group name, canonical sector slug, country (ISO code or name), posting "
            "recency, substring search, and the user's watched victims/groups. sort is 'recent', "
            "'group', or 'sector' (newest-first tiebreak). Returns a paginated list; empty when the "
            "ransomware tracker has not synced yet."
        ),
        "params": {
            "group": {
                "type": 'list[str]',
                "default": None,
            },
            "sector": {
                "type": 'list[str]',
                "default": None,
            },
            "country": {
                "type": 'list[str]',
                "default": None,
            },
            "watched_only": {
                "type": 'bool',
                "default": None,
            },
            "since": {
                "type": 'int',
                "default": None,
            },
            "q": {
                "type": 'str',
                "default": None,
            },
            "sort": {
                "type": 'str',
                "default": None,
                "enum": ['recent', 'group', 'sector'],
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
            "offset": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_ransomware_group_victims": {
        "description": (
            "Paginated list of victim organizations disclosed by a ransomware group (a ThreatActor), "
            "newest activity first. Returns an empty page if the actor has no tracked disclosures."
        ),
        "params": {
            "actor_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
            "offset": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_ransomware_stats": {
        "description": (
            "Ransomware Landscape aggregates over a trailing window: victim totals with "
            "week-over-week change, weekly timeseries, top groups (with WoW trend), top sectors, top "
            "countries, and the user's watchlist exposure (watched groups/orgs/sectors vs new "
            "disclosures). All-zero when the ransomware tracker has not synced yet."
        ),
        "params": {
            "days": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_ransomware_victim": {
        "description": (
            "Fetch one ransomware victim organization by UUID: name/domain/aliases, sector, country, "
            "first/last seen, whether the user watches it, the groups that listed it, and every "
            "leak-site disclosure."
        ),
        "params": {
            "victim_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_requirement_coverage": {
        "description": (
            "Get intelligence requirements coverage summary \u2014 counts by status, priority, category, "
            "and staleness."
        ),
        "params": {},
    },
    "get_requirements": {
        "description": 'Get intelligence requirements and their coverage status.',
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['active', 'fulfilled', 'expired', 'draft'],
            },
        },
    },
    "get_search_facets": {
        "description": (
            "Get available search facets: feed types (feed count per type), categories (feed count "
            "per category), and top tags (by entry usage). Useful for understanding what's in the "
            "system before searching."
        ),
        "params": {},
    },
    "get_share_link": {
        "description": (
            "Return an entry's active public share link ({token, url, created_at, expires_at}), or "
            "null if unshared."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_similar_entries": {
        "description": (
            "Find entries similar to the given entry using content-based search over the search "
            "index. Excludes the entry itself and its exact duplicates (same content hash)."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_source_reliability": {
        "description": (
            "Get feeds ranked by intelligence contribution: entity extractions across every entity "
            "junction type, plus detection rules generated from each feed's entries."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "get_stack_exposure": {
        "description": (
            "My Stack exposure board: every CVE affecting the vendors/products the user has declared "
            "as their stack (watchlist mode='stack'), ranked by exposure lift (KEV/EPSS/weaponization "
            "multipliers), each with a detection posture (defended / blind / no_rule) from the org's "
            "telemetry inventory, plus per-asset CVE tallies and the urgency x posture matrix counts. "
            "Empty if the user has no stack entities declared."
        ),
        "params": {},
    },
    "get_telemetry_sources": {
        "description": (
            "List configured telemetry/log sources and their coverage. Useful for assessing detection "
            "feasibility."
        ),
        "params": {},
    },
    "get_temporal_clusters": {
        "description": 'Find entries sharing entities within time windows — useful for detecting emerging campaigns.',
        "params": {
            "days": {
                "type": 'int',
                "default": 14,
            },
            "window_hours": {
                "type": 'int',
                "default": 72,
            },
            "min_shared": {
                "type": 'int',
                "default": 3,
            },
            "limit": {
                "type": 'int',
                "default": 10,
            },
        },
    },
    "get_threat_actor": {
        "description": (
            "Get a threat actor profile including aliases, actor type, motivation, origin country, "
            "targeted sectors, associated TTPs, and the count of linked articles (article_count)."
        ),
        "params": {
            "actor_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_trending_entities": {
        "description": 'Get top entities by mention count over a time window.',
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['threat_actor', 'malware', 'cve', 'ttp'],
            },
            "days": {
                "type": 'int',
                "default": 30,
            },
            "limit": {
                "type": 'int',
                "default": 10,
            },
        },
    },
    "get_triage_queue": {
        "description": (
            "Get priority-scored entry queue for analyst review. Uses the signal-engine ranking when "
            "signal_engine_surface is enabled, otherwise the legacy composite heuristic \u2014 mirroring "
            "GET /api/entries/triage."
        ),
        "params": {
            "days": {
                "type": 'int',
                "default": 7,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "get_ttp": {
        "description": (
            "Get a MITRE ATT&CK technique (TTP) by ID, including tactic, platforms, data sources, and "
            "linked articles."
        ),
        "params": {
            "ttp_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "ingest_url": {
        "description": (
            "Ingest a web page/article URL as a manual entry: fetches and sanitizes the content, "
            "stores it under the Manual Uploads feed, dispatches the full intelligence pipeline "
            "(autolink + extraction), indexes it for search, and broadcasts an ingest event. "
            "Optionally overrides the extracted title. Errors if the URL was already ingested."
        ),
        "params": {
            "url": {
                "type": 'str',
                "required": True,
            },
            "title": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "link_entities": {
        "description": (
            "Assert an analyst-grade relationship between two intelligence entities. The (source, "
            "verb, target) triple is validated against the semantic relationship matrix and "
            "auto-flipped into its canonical orientation (e.g. 'cve exploited-by actor' is stored as "
            "'actor exploits cve'). Valid verbs (per-pair restrictions apply): attributed_to, "
            "communicates_with, delivers, drops, exploits, overlaps_with, related_to, subgroup_of, "
            "successor_of, targets, uses, variant_of. Written with source=analyst_created; "
            "re-asserting an existing triple promotes it to analyst_created and merges "
            "confidence/description/evidence instead of erroring."
        ),
        "params": {
            "source_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "target_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "target_id": {
                "type": 'str',
                "required": True,
            },
            "relationship_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'attributed_to',
                    'communicates_with',
                    'delivers',
                    'drops',
                    'exploits',
                    'overlaps_with',
                    'related_to',
                    'subgroup_of',
                    'successor_of',
                    'targets',
                    'uses',
                    'variant_of',
                ],
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "confidence": {
                "type": 'str',
                "default": 'possible',
                "enum": ['possible', 'probable', 'confirmed'],
            },
            "evidence_entry_ids": {
                "type": 'list[str]',
                "default": None,
            },
        },
    },
    "list_categories": {
        "description": (
            "List feed categories as a tree (top-level categories with nested children), each with "
            "its direct feed count."
        ),
        "params": {},
    },
    "list_entity_links": {
        "description": (
            "List entry\u2192entity autolinks (junction rows) unioned across all seven junction tables, "
            "newest first. Filter by entity_type, entity_id, entry_id, source provenance (auto_link, "
            "ai, ai_reconcile, auto_extracted, manual \u2014 TTP/CVE junctions record no source and are "
            "excluded when set), confidence (high, medium, low \u2014 the CVE junction has none and is "
            "excluded when set), a substring search on entity name / entry title, or a recency window "
            "in days."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "default": None,
                "enum": ['cve', 'malware', 'product', 'threat_actor', 'tool', 'ttp', 'vendor'],
            },
            "entity_id": {
                "type": 'str',
                "default": None,
            },
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "source": {
                "type": 'str',
                "default": None,
            },
            "confidence": {
                "type": 'str',
                "default": None,
            },
            "search": {
                "type": 'str',
                "default": None,
            },
            "days": {
                "type": 'int',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_entity_notes": {
        "description": (
            "List the analytical notes attached to one intelligence entity, newest first, with author "
            "usernames. Supported entity types match the entity_notes constraint (ransomware victims "
            "are not supported)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "list_entity_relationships": {
        "description": (
            "All entity\u2194entity relationships where the given entity is source or target, newest "
            "first, with endpoint display names resolved. Each row carries verb (relationship_type), "
            "confidence (possible/probable/confirmed), provenance source and evidence_entry_ids. "
            "Analyst-rejected edges and edges below the configured min-confidence display setting are "
            "hidden unless include_rejected is set."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "relationship_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'attributed_to',
                    'communicates_with',
                    'delivers',
                    'drops',
                    'exploits',
                    'overlaps_with',
                    'related_to',
                    'subgroup_of',
                    'successor_of',
                    'targets',
                    'uses',
                    'variant_of',
                ],
            },
            "include_rejected": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "list_extraction_entities": {
        "description": (
            "List AI-created entities (created_via='ai_extraction') with a computed lifecycle status: "
            "linked (in use), review (needs analyst sign-off), orphan (zero articles), or dupe "
            "(near-duplicate sibling exists, with duplicate_of naming it). Filterable by type, "
            "status, creation window, text search and source entry; sorted and paginated. Includes "
            "provenance: created_confidence, needs_review, created_from_entry_id and the source entry "
            "title."
        ),
        "params": {
            "types": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": 'all',
                "enum": ['all', 'linked', 'review', 'orphan', 'dupe'],
            },
            "window": {
                "type": 'str',
                "default": '7d',
                "enum": ['24h', '30d', '7d', 'all'],
            },
            "q": {
                "type": 'str',
                "default": None,
            },
            "source_entry_id": {
                "type": 'str',
                "default": None,
            },
            "sort_by": {
                "type": 'str',
                "default": 'created',
                "enum": ['created', 'entries', 'confidence', 'name'],
            },
            "sort_order": {
                "type": 'str',
                "default": 'desc',
                "enum": ['asc', 'desc'],
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_glossary_terms": {
        "description": (
            "List security glossary terms alphabetically with optional filters: exact category (e.g. "
            "a NIST CSF function like 'detect'), case-insensitive name substring search, and built-in "
            "vs user-created (is_system). Each term carries maturity, descriptions, technologies, and "
            "search-term aliases."
        ),
        "params": {
            "category": {
                "type": 'str',
                "default": None,
            },
            "search": {
                "type": 'str',
                "default": None,
            },
            "is_system": {
                "type": 'bool',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "list_intel_reports": {
        "description": (
            "List intel reports, newest-updated first, optionally filtered by status (draft, "
            "published, archived) or template_type slug. Rows are lightweight \u2014 section names only, "
            "no section content (use get_intel_report for the full report)."
        ),
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['draft', 'published', 'archived'],
            },
            "template_type": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 25,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_notes": {
        "description": (
            "List analyst notes (entry-attached and standalone), pinned first then most recently "
            "updated. Optionally filter to one entry or search title/content by substring. Each note "
            "includes its author and, when attached to an entry, the entry and feed titles."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "search": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "list_saved_searches": {
        "description": (
            "List all saved searches (shared across users) with this user's unread/total entry "
            "counts. Counts come from a 10-minute cache and are computed inline (via search-index "
            "queries) on a cache miss."
        ),
        "params": {},
    },
    "list_telegram_feeds": {
        "description": (
            "List Telegram channel feeds with their adapter config \u2014 channel, last_seen_id, "
            "attribution, session, error state."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "list_watches": {
        "description": (
            "List the current user's entity watchlist rows with resolved display names. Each row has "
            "mode 'watch' (priority boost), 'mute' (suppressed), or 'stack' ('I run this' \u2014 "
            "vendors/products feeding My Stack exposure scoring)."
        ),
        "params": {
            "mode": {
                "type": 'str',
                "default": None,
                "enum": ['watch', 'mute', 'stack'],
            },
        },
    },
    "list_webhook_presets": {
        "description": (
            "List saved webhook presets (reusable URL + payload + header combinations for automation "
            "actions), ordered by name. Webhook URLs and header values are redacted \u2014 inspect them in "
            "the web UI if needed."
        ),
        "params": {
            "preset_type": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 100,
            },
        },
    },
    "mark_all_read": {
        "description": (
            "Bulk-mark entries as read for the current user, optionally scoped to a single feed or a "
            "category. With no scope, marks EVERY entry in every feed as read \u2014 confirm intent before "
            "calling unscoped. The search-index sync runs on a background worker. Returns the number "
            "of entries marked."
        ),
        "params": {
            "feed_id": {
                "type": 'str',
                "default": None,
            },
            "category_id": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "mark_entry_read": {
        "description": (
            "Mark an entry as read (read=true, the default) or unread (read=false) for the current "
            "user. Also syncs the flag to the search index and invalidates the feed unread-count "
            "cache."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "read": {
                "type": 'bool',
                "default": None,
            },
        },
    },
    "merge_malware": {
        "description": (
            "Merge a duplicate malware family into another. Same semantics as merge_threat_actors but "
            "for malware. Use mode='shadow' for dry-run; always include 'reasoning'."
        ),
        "params": {
            "target_id": {
                "type": 'str',
                "required": True,
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "mode": {
                "type": 'str',
                "default": 'apply',
                "enum": ['shadow', 'apply'],
            },
            "new_description": {
                "type": 'str',
                "default": None,
            },
            "extra_aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "reasoning": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "merge_products": {
        "description": 'Merge a duplicate product into another. Same semantics as merge_vendors.',
        "params": {
            "target_id": {
                "type": 'str',
                "required": True,
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "mode": {
                "type": 'str',
                "default": 'apply',
                "enum": ['shadow', 'apply'],
            },
            "new_description": {
                "type": 'str',
                "default": None,
            },
            "extra_aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "reasoning": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "merge_threat_actors": {
        "description": (
            "Merge a duplicate threat actor into another. Moves all entries and country links from "
            "source \u2192 target, unions aliases (source.name + source.aliases get added to "
            "target.aliases), optionally updates the description, then deletes the source actor. Set "
            "mode='shadow' to log what would happen without making changes. ALWAYS supply 'reasoning' "
            "so the maintenance log can be audited."
        ),
        "params": {
            "target_id": {
                "type": 'str',
                "required": True,
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "mode": {
                "type": 'str',
                "default": 'apply',
                "enum": ['shadow', 'apply'],
            },
            "new_description": {
                "type": 'str',
                "default": None,
            },
            "extra_aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "reasoning": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "merge_tools": {
        "description": 'Merge a duplicate tool into another. Same semantics as merge_vendors.',
        "params": {
            "target_id": {
                "type": 'str',
                "required": True,
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "mode": {
                "type": 'str',
                "default": 'apply',
                "enum": ['shadow', 'apply'],
            },
            "new_description": {
                "type": 'str',
                "default": None,
            },
            "extra_aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "reasoning": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "merge_vendors": {
        "description": (
            "Merge a duplicate vendor into another. Same semantics as merge_threat_actors. Moves all "
            "entries, unions aliases, optionally rewrites description, then deletes the source. "
            "Always include reasoning."
        ),
        "params": {
            "target_id": {
                "type": 'str',
                "required": True,
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "mode": {
                "type": 'str',
                "default": 'apply',
                "enum": ['shadow', 'apply'],
            },
            "new_description": {
                "type": 'str',
                "default": None,
            },
            "extra_aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "reasoning": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "pivot_entity": {
        "description": (
            "Find all entities related to a given entity via co-occurrence in entries. One-hop pivot. "
            "Related lists carry strength tiers (weak/moderate/strong) and are ranked, "
            "tier-filterable, window-filterable and paginated; related_counts reports pre-slice "
            "totals."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "limit_per_type": {
                "type": 'int',
                "default": 50,
            },
            "window_days": {
                "type": 'int',
                "default": None,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
            "sort": {
                "type": 'str',
                "default": 'strength',
                "enum": ['strength', 'recent', 'articles'],
            },
            "min_tier": {
                "type": 'str',
                "default": None,
                "enum": ['weak', 'moderate', 'strong'],
            },
        },
    },
    "publish_report": {
        "description": 'Publish an intelligence report — saves current version and sets status to published.',
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "reclassify_entity": {
        "description": (
            "Move an entity from one type to another (cross-type) when it was filed under the wrong "
            "type \u2014 e.g. a malware that's actually a tool, or a product mistakenly stored as a "
            "vendor. Supports malware / product / threat_actor / tool / vendor. If target_id is "
            "given, the source is merged into that existing entity in the target type; if omitted, a "
            "new entity is created in target_type by copying name/aliases/description. Type-specific "
            "fields (motivation, malware_type, vendor_id, tool_type, etc.) are NOT carried across \u2014 "
            "fix them after with update_entity_profile. Use mode='shadow' to log without acting; "
            "always include reasoning."
        ),
        "params": {
            "source_type": {
                "type": 'str',
                "required": True,
                "enum": ['malware', 'product', 'threat_actor', 'tool', 'vendor'],
            },
            "source_id": {
                "type": 'str',
                "required": True,
            },
            "target_type": {
                "type": 'str',
                "required": True,
                "enum": ['malware', 'product', 'threat_actor', 'tool', 'vendor'],
            },
            "target_id": {
                "type": 'str',
                "default": None,
            },
            "mode": {
                "type": 'str',
                "default": 'apply',
                "enum": ['shadow', 'apply'],
            },
            "new_description": {
                "type": 'str',
                "default": None,
            },
            "extra_aliases": {
                "type": 'list[str]',
                "default": [],
            },
            "reasoning": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "refresh_feed": {
        "description": (
            "Queue an immediate background fetch of a feed via Celery (same as the UI's refresh "
            "button). Returns as soon as the fetch task is queued; new entries appear once the worker "
            "completes."
        ),
        "params": {
            "feed_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "reject_relationship": {
        "description": (
            "Trust-ladder reject: mark a relationship source='analyst_rejected'. The row is kept (not "
            "deleted) so re-ingestion and the co-occurrence engine cannot resurrect or accumulate "
            "evidence on it; it is hidden from pivot/graph/list surfaces. Invalidates cached "
            "pivots/graphs for both endpoints."
        ),
        "params": {
            "relationship_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "remove_from_campaign": {
        "description": (
            "Unlink an entry or entity from a campaign (the reverse of add_to_campaign). Provide "
            "either entry_id, or entity_type + entity_id. The entry/entity itself is not deleted, "
            "only the campaign link \u2014 no confirmation needed."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "entity_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'ransomware_victim',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "remove_requirement_match": {
        "description": (
            "Remove a matched entry from an intelligence requirement and decrement its match count. "
            "Reversible (the entry can be re-matched), so no confirmation is needed."
        ),
        "params": {
            "requirement_id": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "report_false_positive": {
        "description": (
            "Report a mislinked entity (autolinker noise). Always writes a FalsePositiveRecord audit "
            "row. With source_entry_id set, unlinks the entity from that entry. scope='entry' stops "
            "there; scope='global' also adds the surface form (entity_value) to the autolinker's "
            "false-positive name list and rebuilds the matching vocabulary so future entries stop "
            "matching it (existing links on other entries are not retroactively removed)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'mitigation',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "entity_value": {
                "type": 'str',
                "required": True,
            },
            "scope": {
                "type": 'str',
                "required": True,
                "enum": ['entry', 'global'],
            },
            "source_entry_id": {
                "type": 'str',
                "default": None,
            },
            "reason": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "revoke_share_link": {
        "description": (
            "Deactivate an entry's active public share link so the public URL stops resolving. "
            "Reversible in effect (create_share_link issues a fresh link, with a new token)."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "rollback_detection_rule": {
        "description": (
            "Restore a detection rule's content (and type) from a saved version, identified by its "
            "version number (see get_detection_rule_versions). The current content is snapshotted as "
            "a new version first, so a rollback is itself reversible."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "version": {
                "type": 'int',
                "required": True,
            },
        },
    },
    "run_ai_task": {
        "description": (
            "Run a registered AI task against an entry (e.g. article_summary, threat_assessment, "
            "detection_rules, entry_analysis). Returns the current cached AIResult when one exists "
            "for this entry+task; pass force=true to re-run and replace it. The 'cached' field "
            "reports which happened."
        ),
        "params": {
            "task_name": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "force": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "run_automation_rule": {
        "description": (
            "Execute an automation rule immediately, once per matching recent entry. Trigger-level "
            "filters (keyword pattern, CVE severity) and rule conditions are applied first; only "
            "entries whose actions actually ran count as matched. WARNING: this executes actions PER "
            "ENTRY \u2014 never use it to test batch/briefing rules (it will flood one briefing per "
            "entry); use test_automation_rule (dry-run) or the rule's schedule instead."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "hours": {
                "type": 'int',
                "default": 24,
            },
        },
    },
    "search_entities": {
        "description": (
            "Search across all 12 intelligence entity types: TTPs, CVEs, threat actors, malware, "
            "detection rules, tools, vendors, products, countries, mitigations, campaigns, and intel "
            "reports. Returns matching entities with type and key details."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "search_entries": {
        "description": (
            "Full-text search across RSS entries. Returns titles, summaries, dates, and feed names. "
            "Supports the full query language: AND/OR/NOT, quoted phrases, entry fields (feed:, tag:, "
            "type:, date:, is:, media:, lang:, title:, author:), entity filters (threat_actor:APT29, "
            "malware:, cve:, ttp:, tool:, vendor:, product:, country:, campaign:, rule:), and sort: \u2014 "
            "all filters are executed, not just the text terms. Supports pagination via offset for "
            "pulling large result sets."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
            "sort": {
                "type": 'str',
                "default": 'relevance',
                "enum": ['longest', 'newest', 'oldest', 'relevance', 'shortest', 'title_asc', 'title_desc'],
            },
        },
    },
    "search_unified": {
        "description": (
            "Unified search across both entries and entities simultaneously, with the full query "
            "language (boolean operators, entry fields like feed:/tag:/date:, entity filters like "
            "threat_actor:APT29, sort:). Entity filters constrain entry results via linked entries. "
            "Returns combined results grouped by type."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "set_detection_rule_status": {
        "description": (
            "Set a detection rule's lifecycle status: 'draft' or 'published' (mirrors the API's "
            "is_draft toggle \u2014 detection rules have no other states)."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "status": {
                "type": 'str',
                "required": True,
                "enum": ['draft', 'published'],
            },
        },
    },
    "star_entry": {
        "description": (
            "Set an entry's starred flag for the current user (starred=true by default; pass false to "
            "unstar). Syncs the flag to the search index. Returns the new value."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "starred": {
                "type": 'bool',
                "default": None,
            },
        },
    },
    "suggest_campaign_entries": {
        "description": "Suggest entries that share entities with a campaign but aren't yet linked to it.",
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 10,
            },
        },
    },
    "test_automation_rule": {
        "description": (
            "Dry-run an automation rule against an entry to see what would happen without executing "
            "actions."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "toggle_automation_rule": {
        "description": "Flip an automation rule's enabled state and return the new state.",
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "translate_entry": {
        "description": (
            "Translate an entry's HTML content (and title) via the LibreTranslate sidecar and store "
            "the translation on the entry row. Re-requesting with the same target language returns "
            "the cached translation; a different target re-translates. target is an ISO-639-1 code "
            "and defaults to the configured target language (usually 'en')."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "target": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "unlink_entity_from_entry": {
        "description": (
            "Remove a single entry\u2192entity autolink (junction row) and invalidate the entity's cached "
            "pivots/graphs. Reversible (the autolinker or an analyst can re-create it), so no "
            "confirmation is required. Does not touch the entity or the entry themselves."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['cve', 'malware', 'product', 'threat_actor', 'tool', 'ttp', 'vendor'],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "unwatch_entity": {
        "description": (
            "Remove the current user's watch/mute/stack row on an entity. Reversible (re-add with "
            "watch_entity); no confirmation required."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'product',
                    'ransomware_victim',
                    'threat_actor',
                    'tool',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "update_automation_rule": {
        "description": (
            "Partially update an automation rule \u2014 only the provided fields change (mirrors PUT "
            "/api/automation/rules/{id}). Trigger types: on_correlation_event, on_cve_detected, "
            "on_keyword_match, on_manual, on_new_entry, on_schedule. Each action is {type, config}; "
            "valid action types: add_tags, add_to_campaign, bookmark_entry, branch, chain_rule, "
            "create_intel_report, create_note, export_to, extract_cves, extract_malware, "
            "extract_threat_actors, extract_ttps, generate_detection_rules, hide_entry, "
            "mark_priority, mark_read, remove_tags, run_ai_task, run_webhook, send_notification, "
            "star_entry (branch sub-actions are validated recursively). Note: actions replaces the "
            "whole list."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "name": {
                "type": 'str',
                "default": None,
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "trigger_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'on_correlation_event',
                    'on_cve_detected',
                    'on_keyword_match',
                    'on_manual',
                    'on_new_entry',
                    'on_schedule',
                ],
            },
            "trigger_config": {
                "type": 'dict',
                "default": None,
            },
            "conditions": {
                "type": 'dict',
                "default": None,
            },
            "actions": {
                "type": 'list[dict]',
                "default": None,
            },
            "labels": {
                "type": 'list[str]',
                "default": None,
            },
            "is_enabled": {
                "type": 'bool',
                "default": None,
            },
        },
    },
    "update_campaign": {
        "description": (
            "Partially update a campaign \u2014 only the provided fields change (mirrors PUT "
            "/api/campaigns/{id}). Statuses: active, monitoring, closed, historical. TLP markings use "
            "TLP 2.0; the legacy TLP:WHITE is accepted and normalized to TLP:CLEAR. Note: tags "
            "replaces the whole tag list."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "name": {
                "type": 'str',
                "default": None,
            },
            "description": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['active', 'monitoring', 'closed', 'historical'],
            },
            "tlp_marking": {
                "type": 'str',
                "default": None,
                "enum": ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED', 'TLP:WHITE'],
            },
            "start_date": {
                "type": 'str',
                "default": None,
            },
            "end_date": {
                "type": 'str',
                "default": None,
            },
            "tags": {
                "type": 'list[str]',
                "default": None,
            },
        },
    },
    "update_detection_rule": {
        "description": (
            "Update fields of a detection rule. Updatable keys: title, description, rule_content, "
            "rule_type (crowdstrike_ql, elastic_ql, kql, nuclei, panther, sigma, snort_suricata, "
            "splunk_spl, yara), severity, tags, is_draft, log_sources, mitre_tactics, data_sources, "
            "notes, source_ttps, source_entries, source_actors, source_campaigns, metadata, "
            "change_description. Changing rule_content snapshots the previous content as a new "
            "version; content or type changes re-extract rule metadata into unset fields (same as the "
            "API PUT)."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
            "updates": {
                "type": 'dict',
                "required": True,
            },
        },
    },
    "update_entity_note": {
        "description": (
            "Update the content of an existing entity note. Other fields (title, type, tags) are "
            "unchanged."
        ),
        "params": {
            "note_id": {
                "type": 'str',
                "required": True,
            },
            "content": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "update_entity_profile": {
        "description": (
            "Update an entity's profile. Supports every profile type with per-type editable fields: "
            "threat_actor (name/aliases/description/mitre_id/country/motivation), malware "
            "(name/aliases/description/malpedia_url/malware_type), cve "
            "(description/severity/exploit_status/affected_products/exploit_availability), ttp "
            "(technique_name/tactic/description), country (name/iso_code/aliases/region/description), "
            "tool (name/aliases/description/tool_type/malpedia_url/github_url), vendor "
            "(name/aliases/description/website/vendor_type), product "
            "(name/aliases/description/product_type/website/vendor_id), campaign "
            "(name/description/status/tags/tlp_marking). Renames are checked for name clashes; "
            "removing aliases unlinks entries matched only via those aliases; new aliases queue a "
            "retro-scan of existing entries; the search-index document is refreshed."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'product',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "updates": {
                "type": 'dict',
                "required": True,
            },
        },
    },
    "update_feed": {
        "description": (
            "Partially update a feed \u2014 only the provided fields change (mirrors PUT /api/feeds/{id}). "
            "Changing the URL resets fetch state (etag, error counters) and rejects duplicates. "
            "category is resolved by name and must already exist. exclude_shorts only applies to "
            "YouTube feeds. adapter_config is merged into the existing config (Telegram channel URLs "
            "are normalized, Bluesky app passwords encrypted at rest). Setting any "
            "reliability/timeliness/relevance rating or analyst notes stamps last_reviewed_at."
        ),
        "params": {
            "feed_id": {
                "type": 'str',
                "required": True,
            },
            "url": {
                "type": 'str',
                "default": None,
            },
            "title": {
                "type": 'str',
                "default": None,
            },
            "category": {
                "type": 'str',
                "default": None,
            },
            "is_muted": {
                "type": 'bool',
                "default": None,
            },
            "is_active": {
                "type": 'bool',
                "default": None,
            },
            "fetch_interval_minutes": {
                "type": 'int',
                "default": None,
            },
            "exclude_shorts": {
                "type": 'bool',
                "default": None,
            },
            "feed_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'atom',
                    'bluesky',
                    'podcast',
                    'reddit',
                    'rss',
                    'telegram',
                    'web_scraper',
                    'youtube',
                ],
            },
            "retention_days": {
                "type": 'int',
                "default": None,
            },
            "reliability_rating": {
                "type": 'str',
                "default": None,
                "enum": ['A', 'B', 'C', 'D', 'E', 'F'],
            },
            "timeliness_rating": {
                "type": 'str',
                "default": None,
                "enum": ['excellent', 'good', 'fair', 'poor'],
            },
            "relevance_rating": {
                "type": 'str',
                "default": None,
                "enum": ['high', 'medium', 'low'],
            },
            "analyst_notes": {
                "type": 'str',
                "default": None,
            },
            "intel_extraction_mode": {
                "type": 'str',
                "default": None,
                "enum": ['full', 'selective', 'manual', 'none'],
            },
            "auto_extract_on_ingest": {
                "type": 'bool',
                "default": None,
            },
            "extract_detection_rules": {
                "type": 'bool',
                "default": None,
            },
            "adapter_config": {
                "type": 'dict',
                "default": None,
            },
        },
    },
    "update_intel_report": {
        "description": (
            "Update fields of an intel report. Updatable keys: title, tlp_marking (TLP 2.0; legacy "
            "TLP:WHITE is normalized to TLP:CLEAR), status (draft, published, archived), content "
            "(full content dict including sections), summary, entry_ids, entity_ids, tags, "
            "change_description. Changing content snapshots the previous content as a version and "
            "increments the version number; setting status to published stamps published_at."
        ),
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
            "updates": {
                "type": 'dict',
                "required": True,
            },
        },
    },
    "update_note": {
        "description": (
            "Update an analyst note's markdown content (and optionally its title). The stored HTML is "
            "re-rendered from the new markdown, same as the notes API."
        ),
        "params": {
            "note_id": {
                "type": 'str',
                "required": True,
            },
            "content": {
                "type": 'str',
                "required": True,
            },
            "title": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "update_requirement": {
        "description": 'Update an existing intelligence requirement (keywords, status, priority, etc.).',
        "params": {
            "requirement_id": {
                "type": 'str',
                "required": True,
            },
            "updates": {
                "type": 'dict',
                "required": True,
            },
        },
    },
    "validate_detection_rule": {
        "description": (
            "Validate detection rule syntax. Returns validation errors, warnings, and suggestions. "
            "Supported formats: crowdstrike_ql, elastic_ql, kql, nuclei, panther, sigma, "
            "snort_suricata, splunk_spl, yara."
        ),
        "params": {
            "rule_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'crowdstrike_ql',
                    'elastic_ql',
                    'kql',
                    'nuclei',
                    'panther',
                    'sigma',
                    'snort_suricata',
                    'splunk_spl',
                    'yara',
                ],
            },
            "rule_content": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "watch_entity": {
        "description": (
            "Create or update the current user's watch on an entity (upsert on entity type + id). "
            "mode 'watch' boosts the entity in priority scoring, 'mute' suppresses its entries, "
            "'stack' declares 'I run this' and is only valid for vendors and products (feeds My Stack "
            "exposure scoring). boost weights priority scoring (0-5, default 1.0)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'malware',
                    'product',
                    'ransomware_victim',
                    'threat_actor',
                    'tool',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "mode": {
                "type": 'str',
                "required": True,
                "enum": ['watch', 'mute', 'stack'],
            },
            "boost": {
                "type": 'float',
                "default": None,
            },
        },
    },
}


# ---------------------------------------------------------------------------
# API Client (stdlib only — no external dependencies)
# ---------------------------------------------------------------------------


class IntelFeedClient:
    """Synchronous HTTP client for IntelFeed API using urllib."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    def _post(
        self, path: str, body: dict, headers: dict[str, str] | None = None
    ) -> tuple[int, dict | str]:
        """Send a POST request and return (status_code, parsed_json_or_text)."""
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "IntelFeed-CLI/1.0",
                **(headers or {}),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8")
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, raw

    def login(self) -> None:
        if not USERNAME or not PASSWORD:
            print(
                "Error: INTELFEED_USERNAME and INTELFEED_PASSWORD must be set.",
                file=sys.stderr,
            )
            sys.exit(1)
        status, data = self._post(
            "/api/auth/login",
            {"username": USERNAME, "password": PASSWORD},
        )
        if status != 200:
            print(f"Error: Login failed ({status}): {data}", file=sys.stderr)
            sys.exit(1)
        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]

    def _refresh(self) -> None:
        if not self.refresh_token:
            self.login()
            return
        status, data = self._post(
            "/api/auth/refresh",
            {"refresh_token": self.refresh_token},
        )
        if status == 200:
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
        else:
            self.login()

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def execute_tool(self, tool_name: str, args: dict) -> str:
        status, data = self._post(
            "/api/tools/execute",
            {"tool_name": tool_name, "args": args},
            headers=self._auth_headers(),
        )
        if status == 401:
            self._refresh()
            status, data = self._post(
                "/api/tools/execute",
                {"tool_name": tool_name, "args": args},
                headers=self._auth_headers(),
            )
        if status != 200:
            return json.dumps({"error": f"API returned {status}", "detail": str(data)})
        return data["result"]


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def print_tool_list() -> None:
    """Print all available tools grouped by category."""
    print("Available IntelFeed tools:\n")
    for name, info in TOOLS.items():
        required = [k for k, v in info["params"].items() if v.get("required")]
        optional = [k for k, v in info["params"].items() if not v.get("required")]
        req_str = ", ".join(required) if required else ""
        opt_str = ", ".join(f"[{k}]" for k in optional) if optional else ""
        params_str = "  ".join(filter(None, [req_str, opt_str]))
        print(f"  {name}")
        print(f"    {info['description']}")
        if params_str:
            print(f"    Params: {params_str}")
        print()


def print_tool_help(tool_name: str) -> None:
    """Print detailed help for a single tool."""
    if tool_name not in TOOLS:
        print(f"Error: Unknown tool '{tool_name}'", file=sys.stderr)
        print("Run with --list-tools to see available tools.", file=sys.stderr)
        sys.exit(1)

    info = TOOLS[tool_name]
    print(f"{tool_name}")
    print(f"  {info['description']}\n")
    if info["params"]:
        print("  Parameters:")
        for pname, pinfo in info["params"].items():
            req = (
                "required"
                if pinfo.get("required")
                else f"default: {pinfo.get('default')}"
            )
            enum_str = f", values: {pinfo['enum']}" if pinfo.get("enum") else ""
            print(f"    {pname} ({pinfo['type']}) — {req}{enum_str}")
    else:
        print("  No parameters.")
    print("\n  Example:")
    example_args = {}
    for pname, pinfo in info["params"].items():
        if pinfo.get("required"):
            if pinfo["type"] == "str":
                example_args[pname] = f"<{pname}>"
            elif pinfo["type"] == "int":
                example_args[pname] = 10
            elif pinfo["type"].startswith("list"):
                example_args[pname] = [f"<{pname}_1>"]
            elif pinfo["type"] == "dict":
                example_args[pname] = {}
            elif pinfo["type"] == "bool":
                example_args[pname] = True
    print(f"    python intelfeed_cli.py {tool_name} '{json.dumps(example_args)}'")


def parse_tool_calls(args: list[str]) -> list[tuple[str, dict]]:
    """Parse CLI args into (tool_name, args_dict) pairs.

    Supports:
      tool_name '{"key": "val"}'       — tool with JSON args
      tool_name                         — tool with no args (next arg is another tool name)
    """
    calls: list[tuple[str, dict]] = []
    i = 0
    while i < len(args):
        tool_name = args[i]
        if tool_name not in TOOLS:
            print(f"Error: Unknown tool '{tool_name}'", file=sys.stderr)
            print("Run with --list-tools to see available tools.", file=sys.stderr)
            sys.exit(1)

        i += 1
        tool_args: dict = {}

        # Check if next arg is a JSON string (starts with '{')
        if i < len(args) and args[i].startswith("{"):
            try:
                tool_args = json.loads(args[i])
            except json.JSONDecodeError as e:
                print(
                    f"Error: Invalid JSON for tool '{tool_name}': {e}", file=sys.stderr
                )
                sys.exit(1)
            i += 1

        calls.append((tool_name, tool_args))

    return calls


def _is_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if args[0] == "--list-tools":
        print_tool_list()
        sys.exit(0)

    if args[0] == "--help-tool":
        if len(args) < 2:
            print("Usage: --help-tool <tool_name>", file=sys.stderr)
            sys.exit(1)
        print_tool_help(args[1])
        sys.exit(0)

    # Parse tool calls from remaining args
    calls = parse_tool_calls(args)

    if not calls:
        print("Error: No tool calls specified.", file=sys.stderr)
        sys.exit(1)

    # Hard read-only enforcement: refuse write tools without touching the API.
    if READ_ONLY:
        for tool_name, _ in calls:
            if tool_name in WRITE_TOOLS:
                print(
                    json.dumps(
                        {
                            "error": f"read-only mode: {tool_name} is a write action and is disabled"
                        }
                    )
                )
                sys.exit(2)

    # Execute
    client = IntelFeedClient(API_URL)
    client.login()

    results = []
    for tool_name, tool_args in calls:
        # Strip None values
        cleaned_args = {k: v for k, v in tool_args.items() if v is not None}
        result = client.execute_tool(tool_name, cleaned_args)
        results.append(
            {
                "tool": tool_name,
                "result": json.loads(result) if _is_json(result) else result,
            }
        )

    # Output: single result unwrapped, multiple wrapped in array
    if len(results) == 1:
        output = results[0]
    else:
        output = results

    # ensure_ascii=False: titles contain emoji/unicode; escaped \uXXXX sequences
    # get transcribed literally by the model into copilot answers.
    print(json.dumps(output, indent=2, default=str, ensure_ascii=False))


if __name__ == "__main__":
    main()

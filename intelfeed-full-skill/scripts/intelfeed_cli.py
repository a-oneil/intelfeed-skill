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

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    # --- Search & Discovery ---
    "search_entries": {
        "description": 'Full-text search across RSS entries. Supports query language: field filters (title:, content:, author:, feed:, tag:, type:rss/atom/youtube/podcast, date:>YYYY-MM-DD, is:starred/unread/bookmarked/noted, media:audio/video/image/document, lang:), entity filters (cve:, ttp:, actor:, malware:, country:, rule:, pir: with sub-fields like cve.cvss:>9.0), boolean operators (AND, OR, NOT), wildcards (*), exact phrases ("..."), grouping with parentheses, and sort:newest/oldest/relevance.',
        "params": {
            "query": {"type": "str", "required": True},
            "limit": {"type": "int", "default": 20},
            "sort": {
                "type": "str",
                "default": "relevance",
                "enum": ["relevance", "newest", "oldest"],
            },
        },
    },
    "search_entities": {
        "description": "Search across all intelligence entities (TTPs, CVEs, threat actors, malware). Returns matching entities with type and key details.",
        "params": {
            "query": {"type": "str", "required": True},
            "limit": {"type": "int", "default": 30},
        },
    },
    "search_unified": {
        "description": "Unified search across both entries and entities simultaneously. Returns combined results grouped by type.",
        "params": {
            "query": {"type": "str", "required": True},
            "limit": {"type": "int", "default": 20},
        },
    },
    "get_search_facets": {
        "description": "Get available search facets: feeds, categories, tags, and feed types. Useful for understanding what's in the system before searching.",
        "params": {},
    },
    # --- Read Operations ---
    "get_entry": {
        "description": "Fetch a single RSS entry by ID with full content and any extracted intelligence (TTPs, CVEs, threat actors, malware).",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    "get_feed_entries": {
        "description": "List recent entries from a specific feed.",
        "params": {
            "feed_id": {"type": "str", "required": True},
            "limit": {"type": "int", "default": 20},
        },
    },
    "get_threat_actor": {
        "description": "Get a threat actor profile including aliases, motivation, country, associated TTPs, and linked articles.",
        "params": {"actor_id": {"type": "str", "required": True}},
    },
    "get_malware": {
        "description": "Get malware family profile with aliases, type, associated actors, and linked articles.",
        "params": {"malware_id": {"type": "str", "required": True}},
    },
    "get_cve": {
        "description": "Get CVE details including CVSS score, severity, EPSS score, affected products, and linked articles.",
        "params": {"cve_id": {"type": "str", "required": True}},
    },
    "get_ttp": {
        "description": "Get a MITRE ATT&CK technique (TTP) by ID, including tactic, platforms, data sources, and linked articles.",
        "params": {"ttp_id": {"type": "str", "required": True}},
    },
    "get_campaign": {
        "description": "Get campaign details with timeline, linked entries, linked entities, and detection gaps.",
        "params": {"campaign_id": {"type": "str", "required": True}},
    },
    "get_feeds": {
        "description": "List configured RSS/Atom/YouTube/podcast feeds with health status.",
        "params": {"limit": {"type": "int", "default": 50}},
    },
    "get_detection_rules": {
        "description": "List detection rules. Optionally filter by rule type.",
        "params": {
            "rule_type": {
                "type": "str",
                "default": None,
                "enum": [
                    "sigma",
                    "splunk_spl",
                    "crowdstrike_ql",
                    "elastic_ql",
                    "kql",
                    "yara",
                    "snort_suricata",
                ],
            },
            "limit": {"type": "int", "default": 30},
        },
    },
    "get_boards": {
        "description": "List reading boards and their entries.",
        "params": {"limit": {"type": "int", "default": 20}},
    },
    "get_requirements": {
        "description": "Get intelligence requirements and their coverage status.",
        "params": {
            "status": {
                "type": "str",
                "default": None,
                "enum": ["active", "fulfilled", "expired", "draft"],
            }
        },
    },
    "get_correlation_events": {
        "description": "Get recent correlation events — new entity sightings, shared infrastructure, detection gaps, campaign matches, etc.",
        "params": {
            "limit": {"type": "int", "default": 30},
            "unread_only": {"type": "bool", "default": False},
        },
    },
    "get_analytics": {
        "description": "Get platform analytics: trending entities, intelligence velocity, detection coverage gaps, and overview stats.",
        "params": {
            "metric": {
                "type": "str",
                "required": True,
                "enum": ["overview", "trending", "detection_coverage", "velocity"],
            },
            "entity_type": {"type": "str", "default": None},
            "days": {"type": "int", "default": 30},
        },
    },
    "get_dashboard_stats": {
        "description": "Get system-wide statistics: total entries, feeds, entities by type, recent activity.",
        "params": {},
    },
    "get_enrichment_data": {
        "description": "Get enrichment results for an entity (EPSS scores, PoC availability, Malpedia data, etc.).",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["cve", "malware"],
            },
            "entity_id": {"type": "str", "required": True},
        },
    },
    "get_attack_layer": {
        "description": "Get MITRE ATT&CK Navigator layer JSON for the system or a specific entry.",
        "params": {
            "entry_id": {"type": "str", "default": None},
            "title": {"type": "str", "default": "IntelFeed ATT&CK Coverage"},
        },
    },
    "get_telemetry_sources": {
        "description": "List configured telemetry/log sources and their coverage. Useful for assessing detection feasibility.",
        "params": {},
    },
    # --- Campaigns ---
    "get_campaigns": {
        "description": "List campaigns with optional status filter.",
        "params": {
            "status": {
                "type": "str",
                "default": None,
                "enum": ["active", "monitoring", "closed", "historical"],
            },
            "limit": {"type": "int", "default": 30},
        },
    },
    "get_campaign_timeline": {
        "description": "Get chronological entries in a campaign, sorted by publication date.",
        "params": {"campaign_id": {"type": "str", "required": True}},
    },
    "get_campaign_attack_layer": {
        "description": "Get MITRE ATT&CK Navigator layer JSON for all TTPs linked to a campaign.",
        "params": {"campaign_id": {"type": "str", "required": True}},
    },
    "get_campaign_detection_gaps": {
        "description": "Find TTPs linked to a campaign that have no active detection rules.",
        "params": {"campaign_id": {"type": "str", "required": True}},
    },
    "suggest_campaign_entries": {
        "description": "Suggest entries that share entities with a campaign but aren't yet linked to it.",
        "params": {
            "campaign_id": {"type": "str", "required": True},
            "limit": {"type": "int", "default": 10},
        },
    },
    "export_campaign": {
        "description": "Export a complete campaign intel package with all linked entries, entities, and detection rules.",
        "params": {"campaign_id": {"type": "str", "required": True}},
    },
    # --- Automation ---
    "get_automation_rules": {
        "description": "List automation rules with optional label filter.",
        "params": {
            "label": {"type": "str", "default": None},
            "limit": {"type": "int", "default": 30},
        },
    },
    "get_automation_templates": {
        "description": "List pre-built automation rule templates with categories.",
        "params": {},
    },
    "get_automation_logs": {
        "description": "Get recent automation execution logs.",
        "params": {
            "rule_id": {"type": "str", "default": None},
            "limit": {"type": "int", "default": 30},
        },
    },
    # --- Analytics ---
    "get_trending_entities": {
        "description": "Get top entities by mention count over a time window.",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["threat_actor", "malware", "cve", "ttp"],
            },
            "days": {"type": "int", "default": 30},
            "limit": {"type": "int", "default": 10},
        },
    },
    "get_feed_value": {
        "description": "Get feed value scores — composite 0-100 intelligence contribution metric per feed.",
        "params": {"days": {"type": "int", "default": 30}},
    },
    "get_source_reliability": {
        "description": "Get feeds ranked by intelligence contribution (entity extraction, detection rules).",
        "params": {"limit": {"type": "int", "default": 20}},
    },
    "get_entry_insights": {
        "description": "Get actionable intelligence insights for a specific entry's entities.",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    "get_triage_queue": {
        "description": "Get priority-scored entry queue for analyst review.",
        "params": {
            "days": {"type": "int", "default": 7},
            "limit": {"type": "int", "default": 20},
        },
    },
    # --- Requirements ---
    "get_requirement_coverage": {
        "description": "Get intelligence requirements coverage summary — counts by status, priority, category, and staleness.",
        "params": {},
    },
    # --- Intelligence Extraction ---
    "extract_ttps": {
        "description": "Extract MITRE ATT&CK techniques (TTPs) from an entry. Maps content to technique IDs. Stores results.",
        "params": {
            "entry_id": {"type": "str", "required": True},
            "use_ai": {"type": "bool", "default": True},
        },
    },
    "extract_cves": {
        "description": "Extract CVE references from an entry and optionally enrich from NVD. Stores results.",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    "extract_threat_actors": {
        "description": "AI-identify threat actors mentioned in an entry. Creates or links to existing threat actor entities.",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    "extract_malware": {
        "description": "AI-identify malware families mentioned in an entry. Creates or links to existing malware entities.",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    "run_ai_task": {
        "description": "Run any registered AI task (summary, threat_assessment, detection_engineering_summary, etc.). Uses the AI task assignment system.",
        "params": {
            "task_name": {"type": "str", "required": True},
            "entry_id": {"type": "str", "required": True},
        },
    },
    # --- Correlation & Analysis ---
    "pivot_entity": {
        "description": "Find all entities related to a given entity via co-occurrence in entries. One-hop pivot.",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["ttp", "cve", "threat_actor", "malware", "country", "vendor", "product", "mitigation", "tool"],
            },
            "entity_id": {"type": "str", "required": True},
        },
    },
    "get_entity_graph": {
        "description": "Build a correlation graph centered on an entity. Shows nodes (entities) and edges (co-occurrence relationships).",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["ttp", "cve", "threat_actor", "malware", "country", "vendor", "product", "mitigation", "tool"],
            },
            "entity_id": {"type": "str", "required": True},
            "depth": {"type": "int", "default": 1},
        },
    },
    "get_entity_timeline": {
        "description": "Get chronological timeline of when an entity appeared in articles.",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["ttp", "cve", "threat_actor", "malware", "country", "vendor", "product", "mitigation", "tool"],
            },
            "entity_id": {"type": "str", "required": True},
        },
    },
    "check_detection_gaps": {
        "description": "Identify TTPs and CVEs that have been observed but lack detection rule coverage.",
        "params": {},
    },
    "check_requirement_match": {
        "description": "Check if a specific entry's content matches any active intelligence requirements. Returns matched requirements.",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    "check_telemetry_feasibility": {
        "description": "Check if detection rules are feasible given configured telemetry sources. Identifies what log sources are needed vs available.",
        "params": {
            "rule_id": {"type": "str", "default": None},
        },
    },
    "get_temporal_clusters": {
        "description": "Find entries sharing entities within time windows — useful for detecting emerging campaigns.",
        "params": {
            "days": {"type": "int", "default": 14},
            "window_hours": {"type": "int", "default": 72},
            "min_shared": {"type": "int", "default": 3},
            "limit": {"type": "int", "default": 10},
        },
    },
    "get_entry_graph": {
        "description": "Get relationship graph for all entities linked to a single entry.",
        "params": {"entry_id": {"type": "str", "required": True}},
    },
    # --- Detection Engineering ---
    "generate_detection_rules": {
        "description": "Generate detection rules from an entry's TTPs. Supports SIGMA, Splunk SPL, CrowdStrike QL, Elastic QL, KQL, YARA, Snort/Suricata.",
        "params": {
            "entry_id": {"type": "str", "required": True},
            "rule_types": {
                "type": "list[str]",
                "required": True,
                "enum": [
                    "sigma",
                    "splunk_spl",
                    "crowdstrike_ql",
                    "elastic_ql",
                    "kql",
                    "yara",
                    "snort_suricata",
                ],
            },
        },
    },
    "validate_detection_rule": {
        "description": "Validate detection rule syntax for any supported format. Returns validation errors, warnings, and suggestions.",
        "params": {
            "rule_type": {
                "type": "str",
                "required": True,
                "enum": [
                    "sigma",
                    "splunk_spl",
                    "crowdstrike_ql",
                    "elastic_ql",
                    "kql",
                    "yara",
                    "snort_suricata",
                ],
            },
            "rule_content": {"type": "str", "required": True},
        },
    },
    "build_detection_summary": {
        "description": "Full detection engineering analysis: gathers all intelligence context for entries and produces comprehensive attack chain analysis and detection gaps.",
        "params": {
            "entry_ids": {"type": "list[str]", "required": True},
            "rule_formats": {
                "type": "list[str]",
                "required": True,
                "enum": [
                    "sigma",
                    "splunk_spl",
                    "crowdstrike_ql",
                    "elastic_ql",
                    "kql",
                    "yara",
                    "snort_suricata",
                ],
            },
        },
    },
    # --- Write Operations ---
    "create_threat_actor": {
        "description": "Create a new threat actor entity.",
        "params": {
            "name": {"type": "str", "required": True},
            "aliases": {"type": "list[str]", "default": None},
            "description": {"type": "str", "default": None},
            "country": {"type": "str", "default": None},
            "motivation": {"type": "str", "default": None},
        },
    },
    "create_malware": {
        "description": "Create a new malware family entity.",
        "params": {
            "name": {"type": "str", "required": True},
            "aliases": {"type": "list[str]", "default": None},
            "description": {"type": "str", "default": None},
            "malware_type": {"type": "str", "default": None},
        },
    },
    "create_detection_rule": {
        "description": "Save a detection rule to the library.",
        "params": {
            "title": {"type": "str", "required": True},
            "rule_type": {
                "type": "str",
                "required": True,
                "enum": [
                    "sigma",
                    "splunk_spl",
                    "crowdstrike_ql",
                    "elastic_ql",
                    "kql",
                    "yara",
                    "snort_suricata",
                ],
            },
            "rule_content": {"type": "str", "required": True},
            "description": {"type": "str", "default": None},
            "severity": {
                "type": "str",
                "default": None,
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "entry_id": {"type": "str", "default": None},
        },
    },
    "create_campaign": {
        "description": "Create a new campaign to track a threat operation and link entities/entries to it.",
        "params": {
            "name": {"type": "str", "required": True},
            "description": {"type": "str", "default": None},
            "status": {
                "type": "str",
                "default": "active",
                "enum": ["active", "monitoring", "closed", "historical"],
            },
            "tlp_marking": {
                "type": "str",
                "default": "TLP:GREEN",
                "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
            },
        },
    },
    "create_feed": {
        "description": "Subscribe to a new RSS/Atom/YouTube/podcast feed.",
        "params": {
            "url": {"type": "str", "required": True},
            "title": {"type": "str", "default": None},
            "feed_type": {
                "type": "str",
                "default": "rss",
                "enum": ["rss", "atom", "youtube", "podcast"],
            },
            "category": {"type": "str", "default": None},
        },
    },
    "add_telegram_feed": {
        "description": (
            "Subscribe to a Telegram channel feed. Requires server-side Telegram setup. "
            "Auto-attribution (threat_actor_id / campaign_id) is the killer feature for "
            "ransomware leak channels and hacktivist channels that ARE the actor."
        ),
        "params": {
            "channel": {"type": "str", "required": True},
            "title": {"type": "str", "default": None},
            "include_media": {"type": "bool", "default": True},
            "extract_forwards": {"type": "bool", "default": True},
            "max_message_age_days": {"type": "int", "default": 30},
            "max_messages_per_fetch": {"type": "int", "default": 200},
            "fetch_interval_minutes": {"type": "int", "default": 30},
            "threat_actor_id": {"type": "str", "default": None},
            "campaign_id": {"type": "str", "default": None},
            "session_name": {"type": "str", "default": None},
            "category": {"type": "str", "default": None},
        },
    },
    "list_telegram_feeds": {
        "description": "List Telegram channel feeds with their adapter config.",
        "params": {"limit": {"type": "int", "default": 50}},
    },
    "discover_telegram_channels": {
        "description": (
            "List every Telegram channel the IntelFeed bootstrap account is joined to. "
            "is_subscribed flag shows which ones are already ingested as feeds. Use to find "
            "channels you joined in Telegram but haven't added to IntelFeed yet."
        ),
        "params": {
            "session_name": {"type": "str", "default": ""},
            "only_unsubscribed": {"type": "bool", "default": False},
        },
    },
    "create_note": {
        "description": "Add a note to an entry (supports markdown).",
        "params": {
            "entry_id": {"type": "str", "required": True},
            "content": {"type": "str", "required": True},
        },
    },
    "create_entity_note": {
        "description": "Add an analytical note to any intelligence entity (threat actor, malware, CVE, TTP, campaign).",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["threat_actor", "malware", "cve", "ttp", "campaign"],
            },
            "entity_id": {"type": "str", "required": True},
            "content": {"type": "str", "required": True},
        },
    },
    "add_tag": {
        "description": "Tag an entry with an existing or new tag.",
        "params": {
            "entry_id": {"type": "str", "required": True},
            "tag_name": {"type": "str", "required": True},
        },
    },
    "add_to_board": {
        "description": "Add an entry to a reading board.",
        "params": {
            "board_id": {"type": "str", "required": True},
            "entry_id": {"type": "str", "required": True},
            "note": {"type": "str", "default": None},
        },
    },
    "add_to_campaign": {
        "description": "Link an entry or entity to a campaign.",
        "params": {
            "campaign_id": {"type": "str", "required": True},
            "entry_id": {"type": "str", "default": None},
            "entity_type": {
                "type": "str",
                "default": None,
                "enum": ["ttp", "cve", "threat_actor", "malware"],
            },
            "entity_id": {"type": "str", "default": None},
            "role": {
                "type": "str",
                "default": "related",
                "enum": ["primary", "secondary", "related"],
            },
        },
    },
    "link_entities": {
        "description": "Create a relationship between two intelligence entities.",
        "params": {
            "source_type": {
                "type": "str",
                "required": True,
                "enum": ["ttp", "cve", "threat_actor", "malware", "campaign"],
            },
            "source_id": {"type": "str", "required": True},
            "target_type": {
                "type": "str",
                "required": True,
                "enum": ["ttp", "cve", "threat_actor", "malware", "campaign"],
            },
            "target_id": {"type": "str", "required": True},
            "relationship_type": {"type": "str", "required": True},
            "description": {"type": "str", "default": None},
        },
    },
    "create_automation_rule": {
        "description": "Set up an automation rule with trigger, conditions, and actions.",
        "params": {
            "name": {"type": "str", "required": True},
            "trigger_type": {
                "type": "str",
                "required": True,
                "enum": ["new_entry", "new_entity", "schedule", "manual"],
            },
            "actions": {"type": "list[dict]", "required": True},
            "description": {"type": "str", "default": None},
            "trigger_config": {"type": "dict", "default": None},
            "conditions": {"type": "dict", "default": None},
        },
    },
    "create_intel_report": {
        "description": "Create an intelligence report from a template with linked entities and entries.",
        "params": {
            "title": {"type": "str", "required": True},
            "template_type": {
                "type": "str",
                "required": True,
                "enum": [
                    "flash_alert",
                    "actor_profile",
                    "campaign_tracker",
                    "landscape_report",
                    "custom",
                ],
            },
            "entry_ids": {"type": "list[str]", "default": None},
            "entity_ids": {"type": "dict", "default": None},
            "tlp_marking": {
                "type": "str",
                "default": "TLP:GREEN",
                "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
            },
        },
    },
    "update_entity_profile": {
        "description": "Update any entity's profile (description, aliases, etc.).",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": ["threat_actor", "malware", "cve", "campaign"],
            },
            "entity_id": {"type": "str", "required": True},
            "updates": {"type": "dict", "required": True},
        },
    },
    "create_requirement": {
        "description": "Create a new Priority Intelligence Requirement (PIR).",
        "params": {
            "title": {"type": "str", "required": True},
            "keywords": {"type": "list[str]", "required": True},
            "description": {"type": "str", "default": None},
            "priority": {
                "type": "str",
                "default": "medium",
                "enum": ["critical", "high", "medium", "low"],
            },
            "category": {
                "type": "str",
                "default": None,
                "enum": ["strategic", "operational", "tactical", "technical"],
            },
            "auto_match": {"type": "bool", "default": True},
        },
    },
    "update_requirement": {
        "description": "Update an existing intelligence requirement (keywords, status, priority, etc.).",
        "params": {
            "requirement_id": {"type": "str", "required": True},
            "updates": {"type": "dict", "required": True},
        },
    },
    "test_automation_rule": {
        "description": "Dry-run an automation rule against an entry to see what would happen without executing actions.",
        "params": {
            "rule_id": {"type": "str", "required": True},
            "entry_id": {"type": "str", "required": True},
        },
    },
    "run_automation_rule": {
        "description": "Execute an automation rule immediately against recent entries.",
        "params": {
            "rule_id": {"type": "str", "required": True},
            "hours": {"type": "int", "default": 24},
        },
    },
    "publish_report": {
        "description": "Publish an intelligence report — saves current version and sets status to published.",
        "params": {"report_id": {"type": "str", "required": True}},
    },
    "generate_full_report": {
        "description": "Generate an AI-powered intelligence report from source entries.",
        "params": {
            "title": {"type": "str", "required": True},
            "template_type": {
                "type": "str",
                "required": True,
                "enum": [
                    "flash_alert",
                    "actor_profile",
                    "campaign_tracker",
                    "landscape_report",
                    "custom",
                ],
            },
            "entry_ids": {"type": "list[str]", "required": True},
            "focus": {"type": "str", "default": None},
            "tlp_marking": {
                "type": "str",
                "default": "TLP:GREEN",
                "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
            },
        },
    },
    "generate_campaign_report": {
        "description": "Generate an intelligence report from a campaign's linked entries and entities.",
        "params": {
            "campaign_id": {"type": "str", "required": True},
            "template_type": {
                "type": "str",
                "default": "campaign_tracker",
                "enum": [
                    "flash_alert",
                    "actor_profile",
                    "campaign_tracker",
                    "landscape_report",
                    "custom",
                ],
            },
            "title": {"type": "str", "default": None},
            "tlp_marking": {
                "type": "str",
                "default": "TLP:GREEN",
                "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
            },
        },
    },
    "export_report": {
        "description": "Export an intelligence report in markdown or HTML format.",
        "params": {
            "report_id": {"type": "str", "required": True},
            "format": {"type": "str", "required": True, "enum": ["markdown", "html"]},
        },
    },
    # --- Export ---
    "export_attack_layer": {
        "description": "Export MITRE ATT&CK Navigator layer JSON for visualization.",
        "params": {
            "entry_id": {"type": "str", "default": None},
            "title": {"type": "str", "default": "IntelFeed ATT&CK Layer"},
        },
    },
    # --- Delete ---
    "delete_entity": {
        "description": "Delete an entity. REQUIRES user confirmation. First call returns a confirmation prompt — present it to the user. Only call again with the confirmation_token after the user explicitly approves.",
        "params": {
            "entity_type": {
                "type": "str",
                "required": True,
                "enum": [
                    "feed",
                    "entry",
                    "note",
                    "detection_rule",
                    "board",
                    "campaign",
                    "automation_rule",
                    "intelligence_requirement",
                    "intel_report",
                    "ttp",
                    "threat_actor",
                    "malware",
                    "tag",
                ],
            },
            "entity_id": {"type": "str", "required": True},
            "confirmation_token": {"type": "str", "default": None},
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

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()

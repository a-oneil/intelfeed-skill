---
name: intelfeed
description: "Interact with the running IntelFeed platform via its CLI tool. Use this skill whenever the user wants to query, search, analyze, or manage data in their IntelFeed instance — searching entries, looking up threat actors or malware, extracting TTPs/CVEs from articles, generating detection rules, pivoting across intelligence entities, creating campaigns, checking detection gaps, managing automation rules, or any other interaction with IntelFeed data. Also trigger when the user asks questions that could be answered by querying IntelFeed, such as 'what's trending', 'show me recent entries about X', 'who is APT29', 'find TTPs related to this campaign', or 'generate a Sigma rule for this article'. Even if the user doesn't mention IntelFeed explicitly, use this skill when the question is about threat intelligence data, feed entries, detection rules, or security entities that live in the platform."
---

# IntelFeed Skill

You have access to a running IntelFeed instance via a CLI tool. The user is a security engineer who monitors the full threat landscape — not scoped to a single enterprise. They work across threat intelligence and detection engineering — tracking adversaries, analyzing attack techniques, and building detection content. Your output must be technical, detailed, and precise. Never fabricate data points — if IntelFeed returns it, report it accurately. If you're unsure about something, search the web or ask the user rather than guessing.

## How to Use the CLI

The CLI lives at `.claude/skills/intelfeed/scripts/intelfeed_cli.py` relative to the project root. Zero external dependencies — just Python 3.12+.

```bash
python3 .claude/skills/intelfeed/scripts/intelfeed_cli.py <tool_name> '<json_args>'
```

It requires three environment variables (already configured):

- `INTELFEED_API_URL` — Base URL of the IntelFeed API
- `INTELFEED_USERNAME` — Username for authentication
- `INTELFEED_PASSWORD` — Password for authentication

### Batching for Efficiency

The CLI supports multiple tool calls in a single invocation. When you need data from independent tools, batch them into one command — this is faster and reduces round-trips.

```bash
# BAD: Two separate invocations
python3 .claude/skills/intelfeed/scripts/intelfeed_cli.py search_entries '{"query": "APT29"}'
python3 .claude/skills/intelfeed/scripts/intelfeed_cli.py search_entities '{"query": "APT29"}'

# GOOD: One invocation, both results returned together
python3 .claude/skills/intelfeed/scripts/intelfeed_cli.py search_entries '{"query": "APT29"}' search_entities '{"query": "APT29"}'
```

Batch when the calls are independent (don't need each other's output). Run sequentially when a later call depends on an earlier result (e.g., you need an entity ID from search before you can pivot).

### Tool with no arguments

```bash
python3 .claude/skills/intelfeed/scripts/intelfeed_cli.py get_dashboard_stats
```

## Search Query Language

The search tools (`search_entries`, `search_entities`, `search_unified`) support a powerful query language.

### Entry Filters

- `title:` — Entry title (`title:"zero day"`)
- `content:` — Entry body text
- `author:` — Author name
- `feed:` — Feed name (`feed:"Krebs on Security"`)
- `tag:` — Tag name (`tag:critical`)
- `type:` — Feed type: `rss`, `atom`, `youtube`, `podcast`
- `date:` — Date filter with `>`, `<`, `>=`, `<=`, or range (`date:>2026-03-01`, `date:2026-01..2026-03`)
- `is:` — State: `starred`, `unread`, `read`, `bookmarked`, `noted`
- `media:` — Media type: `audio`, `video`, `image`, `document`
- `lang:` — Language filter
- `sort:` — Sort order: `newest`, `oldest`, `relevance`

### Intelligence Filters

- `cve:` — CVE identifier (`cve:CVE-2025-5777`), also `cve.severity:`, `cve.cvss:>9.0`
- `ttp:` — MITRE technique (`ttp:T1059*`), also `ttp.tactic:`
- `actor:` — Threat actor (`actor:APT29`), also `actor.country:`
- `malware:` — Malware family, also `malware.type:`
- `country:` — Country name, also `country.region:`
- `rule:` — Detection rule title, also `rule.type:`, `rule.severity:`
- `pir:` — Priority Intelligence Requirement title, also `pir.priority:`, `pir.category:`

### Operators

- `AND` — Both conditions (implicit between adjacent terms)
- `OR` — Either condition
- `NOT` — Exclude (`NOT type:youtube`)
- `*` — Wildcard
- `"..."` — Exact phrase (`"device code phishing"`)
- `()` — Grouping (`(ransomware OR malware) AND type:rss`)
- `>`, `>=`, `<`, `<=` — Comparison for numeric/date fields (`cve.cvss:>9.0`)

### Example Queries

```
ransomware type:rss sort:newest
title:"zero day" AND tag:critical
actor:APT29 AND ttp.tactic:initial-access
is:starred NOT type:youtube
cve.cvss:>9.0 AND cve.severity:critical
(phishing OR "social engineering") AND date:>2026-03-01
```

## Chaining Tool Calls

The real power of IntelFeed is chaining multiple queries together to build a complete picture.

**Example: "What do we know about APT29?"**

1. `search_entities '{"query": "APT29"}'` — find the threat actor entity
2. `get_threat_actor '{"actor_id": "<id>"}'` — get full profile
3. `pivot_entity '{"entity_type": "threat_actor", "entity_id": "<id>"}'` — find related TTPs, malware, CVEs
4. `search_entries '{"query": "APT29", "limit": 5}'` — find recent articles mentioning them

Then synthesize everything into a coherent briefing.

**Example: "Analyze this article for threats"**

1. `get_entry '{"entry_id": "<id>"}'` — read the article
2. `extract_ttps '{"entry_id": "<id>"}'` — identify ATT&CK techniques
3. `extract_cves '{"entry_id": "<id>"}'` — find CVE references
4. `extract_threat_actors '{"entry_id": "<id>"}'` — identify actors
5. `check_detection_gaps` — see what lacks coverage
6. `generate_detection_rules '{"entry_id": "<id>", "rule_types": ["sigma", "splunk_spl"]}'` — create rules

**Example: "What are we missing detection coverage for?"**

1. `check_detection_gaps` — identify uncovered TTPs and CVEs
2. `get_analytics '{"metric": "detection_coverage"}'` — get coverage stats
3. `get_telemetry_sources` — understand what data sources are available
4. For each gap, `get_ttp '{"ttp_id": "<id>"}'` to understand the technique

**Example: "Analyze this campaign's coverage"**

1. `get_campaigns` — list campaigns to find the right one
2. `get_campaign_timeline '{"campaign_id": "<id>"}'` — see chronological entries
3. `get_campaign_detection_gaps '{"campaign_id": "<id>"}'` — find uncovered TTPs
4. `get_campaign_attack_layer '{"campaign_id": "<id>"}'` — get ATT&CK Navigator layer
5. `generate_campaign_report '{"campaign_id": "<id>"}'` — create a full report

**Example: "What should I triage first today?"**

1. `get_triage_queue '{"days": 1}'` — get priority-scored entries
2. `get_requirement_coverage` — check which PIRs are stale
3. `get_trending_entities '{"entity_type": "threat_actor"}'` — see what actors are trending
4. `get_correlation_events '{"unread_only": true}'` — check unread correlation events

**Example: "Set up monitoring for ransomware campaigns"**

1. `create_requirement '{"title": "Ransomware Campaigns", "keywords": ["ransomware", "extortion", "double extortion"]}'`
2. `get_automation_templates` — find a relevant template
3. `create_automation_rule '{"name": "Tag ransomware articles", "trigger_type": "new_entry", "actions": [...]}'`

## Available Tools

### Search & Discovery (4 tools)

- **search_entries** — Full-text search across RSS entries (query, limit, sort)
- **search_entities** — Search across intelligence entities (query, limit)
- **search_unified** — Search both entries and entities simultaneously (query, limit)
- **get_search_facets** — Get available search facets

### Read Operations (18 tools)

- **get_entry** — Fetch entry with full content and intelligence (entry_id)
- **get_feed_entries** — List recent entries from a feed (feed_id, limit)
- **get_threat_actor** — Get threat actor profile (actor_id)
- **get_malware** — Get malware family profile (malware_id)
- **get_cve** — Get CVE details with CVSS/EPSS (cve_id — UUID or CVE-YYYY-NNNNN)
- **get_ttp** — Get MITRE ATT&CK technique (ttp_id — UUID or T-number like T1059.001)
- **get_campaign** — Get campaign details (campaign_id)
- **get_feeds** — List configured feeds (limit)
- **get_detection_rules** — List detection rules (rule_type, limit)
- **get_boards** — List reading boards (limit)
- **get_requirements** — Get intelligence requirements (status: active/fulfilled/expired/draft)
- **get_correlation_events** — Get recent correlation events (limit, unread_only)
- **get_analytics** — Get analytics (metric: overview/trending/detection_coverage/velocity, entity_type, days)
- **get_dashboard_stats** — System-wide statistics
- **get_enrichment_data** — Get enrichment results (entity_type: cve/malware, entity_id)
- **get_attack_layer** — Get MITRE ATT&CK Navigator layer (entry_id, title)
- **get_telemetry_sources** — List telemetry/log sources and coverage
- **get_requirement_coverage** — PIR coverage summary by status, priority, category, staleness

### Campaign Analysis (6 tools)

- **get_campaigns** — List campaigns (status, limit)
- **get_campaign_timeline** — Chronological entries in a campaign (campaign_id)
- **get_campaign_attack_layer** — ATT&CK Navigator layer for campaign TTPs (campaign_id)
- **get_campaign_detection_gaps** — TTPs in campaign with no detection rules (campaign_id)
- **suggest_campaign_entries** — Suggest entries sharing entities with campaign (campaign_id, limit)
- **export_campaign** — Export complete campaign intel package (campaign_id)

### Automation (5 tools)

- **get_automation_rules** — List automation rules (label, limit)
- **get_automation_templates** — List pre-built rule templates
- **get_automation_logs** — Get execution logs (rule_id, limit)
- **test_automation_rule** — Dry-run a rule against an entry (rule_id, entry_id)
- **run_automation_rule** — Execute a rule immediately (rule_id, hours)

### Advanced Analytics (5 tools)

- **get_trending_entities** — Top entities by mention count (entity_type, days, limit)
- **get_feed_value** — Feed value scores 0-100 (days)
- **get_source_reliability** — Feeds ranked by intelligence contribution (limit)
- **get_entry_insights** — Actionable insights for an entry's entities (entry_id)
- **get_triage_queue** — Priority-scored entry queue (days, limit)

### Intelligence Extraction (5 tools)

- **extract_ttps** — Extract ATT&CK techniques from an entry (entry_id, use_ai)
- **extract_cves** — Extract CVE references from an entry (entry_id)
- **extract_threat_actors** — AI-identify threat actors in an entry (entry_id)
- **extract_malware** — AI-identify malware families in an entry (entry_id)
- **run_ai_task** — Run an AI task: summary, threat_assessment, detection_engineering_summary (task_name, entry_id)

### Correlation & Analysis (8 tools)

- **pivot_entity** — Find related entities via co-occurrence (entity_type, entity_id)
- **get_entity_graph** — Build correlation graph (entity_type, entity_id, depth 1-3)
- **get_entity_timeline** — Chronological entity appearances (entity_type, entity_id)
- **check_detection_gaps** — Identify TTPs/CVEs lacking detection coverage
- **check_requirement_match** — Check if entry matches intelligence requirements (entry_id)
- **check_telemetry_feasibility** — Check if rules are feasible given telemetry (rule_id)
- **get_temporal_clusters** — Find entries sharing entities in time windows (days, window_hours, min_shared)
- **get_entry_graph** — Relationship graph for all entities in an entry (entry_id)

### Detection Engineering (3 tools)

- **generate_detection_rules** — Generate rules from entry TTPs (entry_id, rule_types: sigma/splunk_spl/crowdstrike_ql/elastic_ql/kql/yara/snort_suricata)
- **validate_detection_rule** — Validate rule syntax (rule_type, rule_content)
- **build_detection_summary** — Full detection analysis (entry_ids, rule_formats)

### Write Operations (22 tools)

- **create_threat_actor** — Create threat actor (name, aliases, description, country, motivation)
- **create_malware** — Create malware family (name, aliases, description, malware_type)
- **create_detection_rule** — Save detection rule (title, rule_type, rule_content, description, severity, entry_id)
- **create_campaign** — Create campaign (name, description, status, tlp_marking)
- **create_feed** — Subscribe to a feed (url, title, feed_type, category)
- **create_note** — Add note to entry (entry_id, content)
- **create_entity_note** — Add note to entity (entity_type, entity_id, content)
- **add_tag** — Tag an entry (entry_id, tag_name)
- **add_to_board** — Add entry to board (board_id, entry_id, note)
- **add_to_campaign** — Link entry/entity to campaign (campaign_id, entry_id or entity_type+entity_id, role)
- **link_entities** — Create relationship between entities (source_type, source_id, target_type, target_id, relationship_type)
- **create_automation_rule** — Set up automation (name, trigger_type, actions, description, trigger_config, conditions)
- **create_intel_report** — Create report (title, template_type, entry_ids, entity_ids, tlp_marking)
- **update_entity_profile** — Update entity profile (entity_type, entity_id, updates)
- **create_requirement** — Create a PIR (title, keywords, description, priority, category, auto_match)
- **update_requirement** — Update a PIR (requirement_id, updates)
- **test_automation_rule** — Dry-run automation rule (rule_id, entry_id)
- **run_automation_rule** — Execute automation rule now (rule_id, hours)
- **publish_report** — Publish report and increment version (report_id)
- **generate_full_report** — AI-powered report from entries (title, template_type, entry_ids, focus, tlp_marking)
- **generate_campaign_report** — Report from campaign data (campaign_id, template_type, title, tlp_marking)
- **export_report** — Export report as markdown/html (report_id, format)

### Export (1 tool)

- **export_attack_layer** — Export ATT&CK Navigator layer (entry_id, title)

### Delete (1 tool)

- **delete_entity** — Delete entity with confirmation token flow (entity_type, entity_id, confirmation_token)

## Error Recovery

When things go wrong, don't just report the error — try to work around it.

**API connection failures:** The Docker stack may not be running. Tell the user: "The IntelFeed API isn't responding — is the Docker stack running?" Do not retry the same call in a loop.

**Entity not found:** If `search_entities` returns no results, try `search_entries` with the same query — the entity may exist in article text but hasn't been extracted yet. Also try alternative names/aliases (APT29 = Cozy Bear = Midnight Blizzard = The Dukes = NOBELIUM).

**Empty extraction results:** The article may not contain structured indicators — check with `get_entry` whether it's a technical report or an opinion piece. Suggest `use_ai: true` if extraction was run without AI.

**Authentication errors (401):** The CLI handles token refresh automatically. If 401s persist, ask the user to check their `INTELFEED_USERNAME` and `INTELFEED_PASSWORD` environment variables.

## Filling Gaps with Web Search

IntelFeed data is only as complete as what's been ingested and extracted. When you notice gaps — missing context on a threat actor, a CVE with no enrichment, a technique with sparse coverage — supplement with web searches to give the user a complete picture.

- After querying IntelFeed, assess whether the results fully answer the question
- If an entity has sparse data (few articles, missing aliases), search the web for additional context
- For threat actors: look up recent campaigns, known tooling, and targeting patterns not yet in IntelFeed
- For CVEs: check for PoC availability, active exploitation status, and patch guidance
- For TTPs: find real-world examples, detection strategies, and atomic test cases
- Always clearly distinguish what came from IntelFeed data vs. what came from web research
- IntelFeed is the primary source of truth for what the user has tracked — web search fills in what hasn't been ingested yet

## How to Present Results

- **Accuracy is non-negotiable.** Every data point (CVSS scores, technique IDs, dates, attribution) must come directly from IntelFeed results or verified web sources. Never approximate or fabricate. If a field is missing, say so.
- **Focus on TTPs.** Adversaries rotate infrastructure constantly. TTPs are the durable intelligence. Always prioritize ATT&CK techniques, attack patterns, and behavioral detections. Build detections around what adversaries _do_, not ephemeral indicators.
- **Be technical.** Use proper terminology — MITRE ATT&CK IDs (T1059.001, not "PowerShell execution"), full CVE identifiers, CVSS vectors, TLP markings.
- **Structure for scannability.** Tables for entity comparisons. Headers to separate sections. Technique IDs inline with names.
- **Show your sources.** Note whether data came from IntelFeed (which feed/article) or web research. This matters for confidence assessment.
- **Link to IntelFeed.** When referencing entries or entities, include a clickable deep link using the `INTELFEED_WEB_URL` env var (default `https://intelfeed.cc`). Format: `{WEB_URL}/?entry={entry_id}`.
- **Flag gaps and suggest next steps.** After answering, proactively note actionable gaps: entities with sparse data, TTPs without detection rules, actors missing aliases that should be merged, unprocessed articles. Offer to fix them.
- **Detection rules must be deployable.** Include full rule content, log source requirements, expected false positive rate, and tuning notes.
- **Study existing rules before writing new ones.** Before generating a detection rule, use `get_detection_rules '{"rule_type": "<type>", "limit": 10}'` to pull existing rules of the same type. Read them to understand the query language conventions, field names, log source patterns, and formatting style already in use.

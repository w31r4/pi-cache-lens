# pi-cache-lens

Zero-overhead Prefix KV Cache hit-rate status bar (`单次` / `会话`) and background cache-miss forensics for [`pi`](https://pi.dev) (`@earendil-works/pi-coding-agent`).

- **0 LLM Tools / 0 Wire Bytes**: Registers no tool schemas and never mutates outgoing requests.
- **Dual Hit-Rate Status Chip**: Tracks both the latest request (`单次` / `last`) and cumulative session (`会话` / `sess`) KV cache hit rates across `openai-responses`, `anthropic-messages`, and `openai-completions`.
- **Theme-Native Styling**: Uses `dim` labels, `accent` healthy numbers (`>= 70%`), `muted` non-anomalous warmup (`<= 3` calls), `warning` partial drops (`30%~69%`), and `error` anomaly drops (`< 30%`).
- **Credential-Safe Deterministic Attribution**: Fingerprints normalized `system`, `tools` (including inline `additional_tools`), provider effort markers, and logical conversation items in `before_provider_request`. Persists only hashes, byte lengths, and exact numeric diff offsets (`char@` / `byte@`) without writing raw prompt excerpts to disk.

## Install

```bash
pi install git:github.com/w31r4/pi-cache-lens
```

Update anytime with:

```bash
pi update
```

## Status Bar Integration

### With `pi-powerline-footer`

Add to `~/.pi/agent/settings.json`:

```json
{
  "powerline": {
    "preset": "default",
    "disabledSegments": ["cache_read"],
    "customItems": {
      "cache-stats": {
        "statusKey": "cache-stats",
        "position": "left",
        "selfColorize": true
      }
    }
  }
}
```

### With `pi-cc-extensions`

Add to `~/.pi/agent/pi-cc-extensions.json`:

```json
{
  "footerHiddenKeys": ["cache"],
  "footerLine1Keys": ["model", "context", "cache-stats", "rate", "cost", "pi-usage"],
  "footerLine2Keys": ["cwd", "git"]
}
```

### Built-in `pi` Footer

Works automatically via `ctx.ui.setStatus("cache-stats", ...)`.

## Root-Cause Tags & Diagnostics

| Tag | Diagnosis | Meaning |
|---|---|---|
| `(冷启)` / `(cold)` | `cold_start` | First request of a new session warming up the KV cache |
| `(<1k)` | `below_min_tokens` | Prompt below provider minimum cacheable token threshold (`1024`) |
| `(!tools)` | `tools_mutated` | Tool list or JSON schema changed and triggered a cache drop (`+added`, `-removed`, `~modified`) |
| `(!strict)` | `provider_strict_fallback` | Provider rejected strict tool grammar (`anthropic_strict_tools_fallback`) and retried with fallback schemas |
| `(!sys)` | `system_mutated` | System prompt mutated and triggered a cache drop (records exact `char@` / `byte@` offset, byte delta, and `sha12` hashes) |
| `(!hist)` | `history_rewritten` | Logical conversation history rewritten or compacted at `item #idx` |
| `(!ttl)` | `ttl_expired_likely` | Request dispatch exceeded the prior cache touch's verified retention TTL (`290s` short default when `cache_control` / `prompt_cache_key` is active, `1800s` for `30m` `prompt_cache_options.ttl`, `3600s` for `1h`, `86400s` for `24h`) |
| `(!model)` | `model_changed` | Effective model (`responseModel ?? model`) switched mid-session with a sharp hit-rate drop |
| `(!route)` | `provider_miss_or_routing` | Comparable wire prefix hashes intact, verified retention policy unchanged, and within TTL, yet `cacheRead = 0` (gateway node / account-pool drift) |
| `(!drop)` | `partial_hit` / `insufficient_evidence` | Sharp hit-rate drop (`>= 35%` or below `50%`), or drop where comparable wire, retention, or touch evidence is unavailable |
| *(none)* | `usage_unavailable` | Aborted/error completion without evaluable prompt token counters; excluded from hit-rate attribution |

### Slash Commands

- `/cache`: Show current session hit-rate summary and last 8 calls with `sys` / `tools` short hashes.
- `/cache anomalies`: Show the 10 most recent cache-drop anomalies across sessions (spanning `.1` rotation).
- `/cache path`: Print paths to the background forensics files.

### Background Forensics Files

Stored under `~/.pi/agent/cache-lens/` by default:

- `latest-report.md`: Atomically published Markdown summary table grouped by model + latest 25 cache-drop root causes.
- `events.jsonl`: Per-call telemetry and prefix hashes (coordinated cross-process lock, auto-rotates at 10 MB).
- `anomalies.jsonl`: Filtered log containing only demonstrated cache-drop anomalies.

## Optional Configuration (`~/.pi/agent/cache-lens.json`)

Locale auto-detects `~/.config/rpiv-i18n/locale.json` and `LANG` (`zh` / `en`). Override any field if needed:

```json
{
  "locale": "zh",
  "statusKey": "cache-stats",
  "icon": "\uf0e7",
  "healthyColor": "accent",
  "ttlThresholdSec": 290,
  "minCacheableTokens": 1024,
  "maxLogBytes": 10485760
}
```

## Development

```bash
npm test
```

## License

MIT

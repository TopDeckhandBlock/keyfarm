# 🔑 keyfarm — multi-source AI key harvester

Self-improving parser that hunts leaked API keys across GitHub and a dozen other
code hosts, validates them live against each provider, and posts the **actually
working** ones (with balance + model list) to Telegram.

> ⚠️ Educational / authorized-research tool. You are responsible for how you use it.

---

## What it catches

DeepSeek · DashScope/Qwen · OpenRouter · Groq · Replicate · Kimi/Moonshot ·
Z.ai · Sakana · Perplexity · Mistral · Together · Fireworks · Anthropic ·
OpenAI · SiliconFlow · Novita · Gemini + captcha services (2Captcha /
AntiCaptcha / CapSolver) + Telegram bot tokens + AWS/Stripe/etc.

## Sources (all in parallel)

GitHub Code Search · GitHub Events **firehose** (catches keys minutes after push,
before Secret-Scanning removes them) · Commits · Issues · **Gists** · GitLab ·
Codeberg · Gitea · HuggingFace (spaces + models + datasets) · Docker Hub · NPM

## How it works

```
harvest PATs  →  token pool (1000+, rotating)  →  scan all sources
            →  extract candidates (regex + smart search terms)
            →  live-validate against provider API (balance + models)
            →  filter junk (dead / $0 balance)
            →  post worthy keys to Telegram
```

**Smart search terms**: instead of only regex, search GitHub for
high-signal strings like `T3BlbkFJ` (the base64 chunk inside every OpenAI key),
`DASHSCOPE_API_KEY filename:.env`, `docker-compose.yml` — where secrets get
committed most.

**Universal classifier** (`universal_validator.py`): DeepSeek / DashScope / Kimi
all share the `sk-<hex>` shape — regex can't tell them apart. This probes an
unknown key against **13 OpenAI-style providers + 7 special endpoints**
(Telegram bots, HuggingFace, GitHub PATs, npm, Slack, Replicate, Gemini) and
reports where it's actually alive. Uses **auth-gated** endpoints only — providers
whose `/models` is public (OpenRouter, Novita) are probed via `/key` or skipped,
so a garbage key never false-positives.

**Recycler** (`recycler.py`): the regex classifier mislabels many `sk-` keys and
the main validator leaves a big NEW backlog. The recycler re-probes NEW + DEAD
keys with the universal classifier, **revives** the ones alive on a different
provider, flips their DB status, and posts them to Telegram. Pre-filters junk by
shape before any network call (5-10x faster). `python recycler.py --loop`.

**Self-improvement** (`auto_improve.py`): mines new detection patterns from
open-source secret-pattern databases, validates them (rejects placeholder-matching /
backtracking-bomb patterns), writes `src/patterns_extra.py`, and commits back —
so every node gets smarter on its own.

## Quick start

```bash
pip install -r requirements.txt
# put your GitHub PATs (one per line) in gh_tokens.txt
python src/eternal_v10.py        # parser (13 providers, all sources)
python src/validator_v10.py      # live validator (separate process)
python universal_validator.py keys.txt   # classify unknown keys
```

## Fleet (free 24/7 on GitHub Actions)

`fleet/` deploys the parser to N GitHub accounts — each gets a private repo with
an Actions cron that re-runs the hunt every few days, for free.

```bash
python fleet/gh_pat_batch.py        # harvest PATs from accounts (login+TOTP)
python fleet/fleet_deploy.py        # deploy a node per account
python fleet/fleet_chain.py         # keep deploying as the pool grows
```

Telegram posting (`fleet/key_poster.py`, `fleet/dashscope_hunter.py`) needs:
```bash
export TG_BOT_TOKEN="***"   # from @BotFather
export TG_CHAT_ID="123456"              # your chat id
```

## Encrypted token pool

GitHub secret-scanning auto-revokes any `ghp_…` you commit — even to a private
repo. So tokens are never stored in plaintext: `pool_crypto.py` wraps them in a
Fernet blob (`pool.enc`), key lives in an Actions secret (`POOL_KEY`). Nodes
either use their own `NODE_TOKENS` secret or decrypt the shared pool.

## Layout

```
src/eternal_v10.py        main parser (sources + extraction)
src/validator_v10.py      live provider validation
src/key_patterns.py       base patterns + env-context extraction
src/patterns_extra.py     AUTO-GENERATED mined patterns
src/*_scanner.py          per-source scanners (gist/gitlab/gitea/docker/npm/hf…)
universal_validator.py    classify unknown keys across 13 providers
auto_improve.py           self-research loop (mines new patterns)
run_imba.py               budgeted orchestrator (for CI)
pool_crypto.py            Fernet encrypt/decrypt token pool
fleet/                    PAT harvest + node deploy + TG poster + DS hunter
.github/workflows/        Actions cron
```

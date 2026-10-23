# Agentic Risk Review (optional)

The report's figures come from a deterministic model: the same scan always gives the same score,
estimate and areas of focus. The **Agentic Risk Review** (the AI review) adds a second opinion from a
large reasoning model on how entrenched the estate is, what the exit will cost and take, and where the
project should focus. It is off until you ask for it, and it never changes the report's own figures.

## One journey

1. Once: **Settings, AI configuration** to choose the provider, model and key (below).
2. **New scan**, step 4: tick **Add an Agentic Risk Review to the report**. The review starts by itself
   when the scan finishes, on the report as the console shows it (the account filter and Exit model
   answers at the time), and the choice is remembered for the next scan. It needs a deep scan, so
   ticking it switches Scan depth to a dependency scan (choosing Quick unticks it): on billing alone
   the model would see spend, not the resources and integrations that make an account hard to move.
3. Read the report while it runs. It lands in **section 2, Agentic Risk Review**, right after the
   executive summary; the **Agentic Risk Review** button above the report jumps there and shows a dot
   while it runs.

Section 2 opens with the **overall AI summary** (the headline and the 5 to 8 points that matter most
across the whole report), the AI's entrenchment, effort, time and cost against the model, then the
**accounts to focus on** (the most entrenched, with why each is hard and how to tackle it), what will
decide the exit, programme risks, sequencing, quick wins and questions for owners. For a scan made
without it, section 2 has a **Run Agentic Risk Review** button for the open report; on a quick scan it
warns that the view will be thin.

## Providers

| Provider | Recommended model | Credentials |
|---|---|---|
| Amazon Bedrock | Claude Opus 5.5 (Fable 5.1 needs Bedrock data retention enabled) | An AWS profile, or a Bedrock API key. The summary stays in your AWS account. |
| Claude Enterprise / Claude API | Claude Fable 5.1, or Opus 5.5 | An API key from your organisation's Claude Console (`ANTHROPIC_API_KEY`) |
| Together AI | GLM 5.3 | `TOGETHER_API_KEY` |
| OpenRouter | Claude Fable 5.1, Opus 5.5 or GLM 5.3 | `OPENROUTER_API_KEY` |
| AI gateway (Portkey, LiteLLM or your own) | Whatever the gateway routes to | Base URL, a key (`EXITRISK_AI_GATEWAY_KEY`) and optional extra headers |

**AI gateway** calls any OpenAI-compatible endpoint (`<base URL>/chat/completions`, `/models`), so a
firm that routes model traffic through Portkey, LiteLLM or its own gateway can use the same guardrails,
logging and billing it already has. Set the base URL (https only), choose how the key is sent
(`Authorization: Bearer` for LiteLLM and most gateways, `x-portkey-api-key` for Portkey, or `api-key` /
`x-api-key`), and add any routing headers one per line as `Name: value`, for example
`x-portkey-config: pc-...` or `x-portkey-provider: @bedrock-prod`. The model id is whatever the gateway
expects (for Portkey's model catalog, `@provider/model`). Header values are stored like keys and never
sent to the browser; only their names are shown. Where the summary ends up depends on where the
gateway routes it, so the dialog treats it as a third party.

Any other model the provider offers can be picked from the list (read from the provider with your key)
or typed in as a custom model. Each call asks for deep reasoning: adaptive thinking at high effort for
Claude, a high reasoning effort elsewhere; a model that refuses the option runs without it.

In **AI configuration**, **Test connection** asks the chosen model a small reasoning
question that must come back as valid JSON with the right answer, so a bad key, an unknown model or a
model that cannot follow the format fails in seconds. **Test all providers** does the same for every
provider with a key. Once the AI review is set up, **Check access** runs the same test as its last,
optional step.

## How it works

1. **Account analysis.** Every account with spend (up to 400, largest effort first), in batches of 12,
   eight at a time: entrenchment, the model's own effort range against the deterministic one, risks,
   how to tackle the account and in which phase, confidence and evidence gaps. Accounts the model
   skips are asked for again.
2. **Estate view.** One pass over the estate facts and every account analysis: headline, entrenchment,
   effort, duration and cost ranges with the reasons they differ from the model, areas of focus naming
   the accounts, programme risks, sequencing, quick wins, questions for owners and evidence to collect.
3. **Review.** Automated checks run on the draft (ranges valid; far from the model only with a reason;
   effort, duration and team size consistent; every account named exists; phases valid). The draft,
   the facts, the analyses and those findings go back to the model as an independent reviewer, which
   corrects what is wrong and lists each change. The checks run again; anything still open is shown.

**Nothing fails silently.** Every call is logged with its tokens in and out and the provider's stop
reason. A reply cut off at its output limit is asked again with twice the room (up to 64,000 tokens),
and a reply that is not valid JSON once more; if it is still cut off or unreadable the run fails with
the reason and nothing is saved, so a truncated answer is never used. Accounts the model skips twice,
a dropped reasoning setting, a review that returned no corrected view, and accounts beyond the 400
analysed one by one are listed under "How the run went" on the result. OpenRouter is told not to
compress long prompts. Each account carries every service it uses (up to 40), not just the largest.

**Cost.** The top of the result shows the approximate cost of the review: its tokens in and out at the
model's list price (Together AI's own price list; for other providers OpenRouter's public list price
for the same model). Negotiated rates, prompt caching and batch discounts are not known, so treat it
as an order of magnitude. A real Prod OU of 164 accounts on GLM 5.3 used about 150k tokens in and
100k out: about $0.66, in 7.5 minutes.

A demo estate of 48 accounts takes about 6 minutes on GLM 5.3; a large estate 20 to 40 minutes.
The result is stored with the scan (`~/.exitrisk/ai/<scan>.json`), appears in section 2,
and is included in the PDF.

## What is sent

A summary of the report as filtered: per account its name, OU path, spend, services and tiers, the
model's effort, data size, counts of integrations, critical flag and owner tag; and the estate totals,
estimate, answers and assumptions. Never resource names, ARNs, configuration or AWS credentials.

**Hide account names and owners** (on by default for third-party providers) swaps every account id,
name and owner for a code, everywhere in the text sent, and restores them in the answer. The model then
judges accounts by their services alone, so its insight is a little thinner.

Check that the provider is approved for this data before using a third-party provider. Bedrock keeps
it in your AWS account.

## Keys

Keys are saved in `~/.exitrisk/ai.json`, created readable only by you, or read from the environment
variables above. The browser sees whether a key is set and its last four characters, and the whole key
only when you click **Show** beside it (the console listens on this computer only, and that request
needs the console's own header, so another web page cannot read it).

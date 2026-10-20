# Presenting the report to an executive committee

The report is built to be read in five minutes and defended for an hour. This guide is for the person
presenting it.

## The one-page story (report section 1)

Section 1 opens with a written brief you can read out as-is: the **bottom line**, **what we found**,
**what leaving would take**, **what we recommend** and a **confidence** rating that says why the numbers
might move (for example, the delivery questions in section 5 not yet answered). The key figures follow.

Figures below are from the synthetic demo organisation filtered to `prod`.

1. **The scores** — "Our production estate scores 43/100 by spend and 45/100 by number of accounts:
   Elevated exit risk either way." Each is the difficulty of moving every workload off AWS, from 10
   (everything on commodity infrastructure) to 95 (everything on services that exist only on AWS). If
   the spend score is much higher, risk sits in a few big accounts; if the account score is higher, it
   is spread across many small ones.
2. **How much is locked in** — "32% of production spend, $2.4m a year, runs on services we would have to
   re-engineer, not just move."

   **How many accounts** — "7 of 12 production accounts are portable; 5 are High or Critical and hold
   43% of spend." Few high-risk accounts with a lot of spend is a concentration to plan for, not an
   estate-wide problem.
3. **Where** — "Three accounts carry 63% of that risk: the data platform (Redshift and Glue), card
   processing (DynamoDB and Lambda) and the contact centre (Amazon Connect)."
4. **What leaving would take** — "About 28 months and $7.1m (range $5.3m–$10.6m), with our current team
   and delivery maturity."

## Questions to expect, and where the answer is

| Question | Answer in the report |
|---|---|
| "Is this number reliable?" | Section 6 lists every gap in the data; the methodology appendix shows every formula. The score comes straight from our bill. |
| "Why is a small account red but the score fine?" | Section 3: inherent risk vs contribution. Small high-risk accounts are visible but do not dominate. |
| "Is lock-in growing?" | Section 2 trend chart: spend by tier per month. |
| "What would reduce the risk cheapest?" | Section 4 and Appendix A: the top tier 4–5 services and their recommended migration paths. Standardising pipelines and bringing Terraform up to date lowers the estimate directly — change the questionnaire answers live to show it. |
| "Why not just stop using Lambda/DynamoDB?" | Exit risk is a trade-off with speed and cost today. The decision is how much risk to hold, documented and reviewed — not zero. |
| "Does the regulator accept this?" | It evidences the *assessment* part of an exit plan (dependency mapping, feasibility, cost and time). A full plan also needs triggers, governance, testing and a stressed-exit scenario. |

## Decisions the committee can take

- **Risk appetite**: a ceiling for the OU score or for % of production spend on tier 4–5, reviewed quarterly.
- **Guardrails**: new workloads on tier 5 services need architecture sign-off with an exit path.
- **Portability investment**: fund the cheapest risk reducers first — IaC currency, a standard
  pipeline, Kafka-API streaming instead of Kinesis, Temporal instead of Step Functions for new work.
- **Exit plan**: adopt the estimate as the planning baseline for the regulatory exit plan, with a
  workload-level discovery for the top three accounts.

## Using the live console in the meeting

Filter by name (`prod`), toggle the questionnaire (e.g. "Terraform current" vs "with drift") and the
estimate updates in under a second. Export the PDF afterwards so the minutes reference a fixed version:
the footer carries the scan id, catalog version and generation time.

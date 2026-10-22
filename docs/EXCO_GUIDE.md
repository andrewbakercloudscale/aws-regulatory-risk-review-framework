# Presenting the report to an executive committee

The report is built to be read in five minutes and defended for an hour. This guide is for the person
presenting it.

## The one-page story (report section 1)

Section 1 opens with a written brief you can read out as-is: the **bottom line**, **what we found**,
**what leaving would take**, **what we recommend** and a **confidence** rating that says why the numbers
might move (for example, the delivery questions under Exit model not yet answered). The key figures follow.

Figures below are from the synthetic demo organisation (made-up numbers, 12 months) filtered to `prod`.

1. **The scores**: "Our production estate scores 38/100 by spend and 28/100 by number of accounts:
   Moderate exit risk, concentrated in a few large accounts." Each is the difficulty of moving every workload off AWS, from 10
   (everything on commodity infrastructure) to 95 (everything on services that exist only on AWS). If
   the spend score is much higher, risk sits in a few big accounts; if the account score is higher, it
   is spread across many small ones.
2. **How much is locked in**: "27% of production spend, $2.7m a year, runs on services we would have to
   re-engineer, not just move."

   **How many accounts**: "34 of 40 production accounts are portable; 6 are High or Critical and hold
   36% of spend." Few high-risk accounts with a lot of spend is a concentration to plan for, not an
   estate-wide problem.
3. **Where**: "Three accounts carry 57% of the spend at risk (spend × risk): the data platform (Redshift and Glue), card
   processing (DynamoDB and Lambda) and the contact centre (Amazon Connect)."
4. **Where the work is**: the spend score is exposure. Technical portability, exit effort in
   engineer-days and the five dimensions measure difficulty: "Our production estate costs $754k a month, but the
   hard part of leaving is not the portable compute; it is 2 critical accounts that are hard to move,
   613 AWS-specific integrations and 2,549 TB of data." Say which scan depth the figures rest on: a
   quick scan sizes effort from spend and cannot claim the confidence of a dependency scan.
5. **What leaving would take**: "Roughly 2.5 to 5 years and $7m to $16m, with our current team and
   delivery maturity." The report gives ranges, never a single figure: at this stage a point
   estimate would claim precision it does not have. Cost and time appear only once the delivery questions under Exit model are
   answered; until then they are marked provisional.

## Questions to expect, and where the answer is

| Question | Answer in the report |
|---|---|
| "Is this number reliable?" | Section 6 lists every gap in the data; the methodology appendix shows every formula. The score comes straight from our bill. |
| "How do we raise the confidence?" | Under the confidence rating in section 1, **To raise confidence** lists one step per reason, with a button for each: answer the delivery questions under Exit model, and deploy the read-only `ExitRiskReadOnly` role to every member account (one CloudFormation StackSet, see [IAM_PERMISSIONS.md](IAM_PERMISSIONS.md#2-deep-scan-member-accounts)) then run a deep scan. Both done gives High, provided the scan finished without errors, the deep scan reached accounts holding at least 90% of spend, and services missing from the catalog are under 2% of spend. Services you leave out under Exclusions do not lower confidence. |
| "Why is a small account red but the score fine?" | Section 3: inherent risk vs contribution. Small high-risk accounts are visible but do not dominate. |
| "Is lock-in growing?" | Section 2 trend chart: spend by tier per month. |
| "What would reduce the risk cheapest?" | Section 4 and Appendix A: the top tier 4 to 5 services and their recommended migration paths. Standardising pipelines and bringing Terraform up to date lowers the estimate directly, change the questionnaire answers live to show it. |
| "Why not just stop using Lambda/DynamoDB?" | Exit risk is a trade-off with speed and cost today. The decision is how much risk to hold, documented and reviewed, not zero. |
| "What would we still owe AWS if we left?" | Section 1 key figure **Commitments written off**, and section 5's chart: Savings Plans, reservations and any EDP still running once the exit finishes. A planned exit lets them run off; buy new terms that end inside the window. |
| "How long to copy the data, and does it touch production?" | Section 6, **Links for the migration**: Cheap, Medium and Urgent options for new Direct Connect links used only for the copy, with time and cost. Data out per GB is the same for every option; the links buy speed. |
| "Does the regulator accept this?" | It evidences the *assessment* part of an exit plan (dependency mapping, feasibility, cost and time). A full plan also needs triggers, governance, testing and a stressed-exit scenario. |

## Decisions the committee can take

- **Risk appetite**: a ceiling for the OU score or for % of production spend on tier 4 to 5, reviewed quarterly.
- **Guardrails**: new workloads on tier 5 services need architecture sign-off with an exit path.
- **Portability investment**: fund the cheapest risk reducers first: IaC currency, a standard
  pipeline, Kafka-API streaming instead of Kinesis, Temporal instead of Step Functions for new work.
- **Exit plan**: adopt the estimate as the planning baseline for the regulatory exit plan, with a
  workload-level discovery for the top three accounts.

## Using the live console in the meeting

Filter by name (`prod`), toggle the questionnaire (e.g. "Terraform current" vs "with drift") and the
estimate updates in under a second. Export the PDF afterwards so the minutes reference a fixed version:
the footer carries the scan id, catalog version and generation time.

For the board pack cover or a pre-read, **Export PDF → One-page summary** prints the summary on a single A4 page
(`exitrisk pdf <scan-id> --onepage` from the command line). The full report stays the reference.

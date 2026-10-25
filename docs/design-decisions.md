# Design decisions

Notes on why the analyzer works the way it does, including what went wrong in the
first version and how it was fixed.

## Rules decide, the LLM explains

The verdict comes from deterministic checks. The local LLM gets the verdict, the top
findings and the score breakdown, and is told the verdict is final. If Ollama is down or
returns something unparseable, the report says so (`status: unavailable / unparseable`)
and the analysis still completes.

Reasons: results are repeatable, every point in the score can be traced to a finding,
and a 4B model running on a laptop is not reliable enough to be the judge.

## A failed check is unknown, not evidence

The first version gave +15 when a WHOIS lookup failed and +10 to +30 when DNS had no MX
record. On a slow connection every email picked up these points, and the "three signals →
Phishing" rule then fired on almost everything. It flagged about 90% of legitimate mail.

Now a lookup that fails is reported as `unavailable`, adds 0 points, lowers the confidence
of a Benign verdict, and is listed in the report so "no finding" isn't read as "safe".
WHOIS and DNS also run on the registered domain (`example.com`), not the full hostname,
because subdomains rarely have their own MX records.

## Scores are capped, not summed

Summing every link meant a newsletter with 80 links scored over 400 for URLs alone.
Now:

| Component | Cap |
| --- | --- |
| URL (worst link + 5 per extra suspicious link, max +15) | 40 |
| Header | 40 |
| Content | 40 |
| Brand | 50 |
| WHOIS | 30 |
| DNS | 20 |
| VirusTotal | 40 |

A link counts as suspicious at 15 points or more, so plain `http://` (5 points) is not
enough on its own.

## Independent signals

`count_signals()` decides what counts as independent evidence: a suspicious link, any brand
finding, other header findings ≥ 20, failed sender authentication, content ≥ 20, VirusTotal
≥ 20, a domain under 30 days old, or a link domain that doesn't exist. Each signal after the first adds 10 (max 20); three or
more raise the score to at least 70. The evidence builder and the verdict engine both call
the same function, so they can't disagree.

## Two cases that are Suspicious on their own

- **A claimed brand.** If the display name or subject says "PayPal" or "Binance" and the sender
  domain doesn't belong to that brand, the score is at least 45 even without other evidence.
  A newsletter that only mentions a brand in its name doesn't count.
- **Failed authentication plus something else.** SPF, DKIM or DMARC failures alone stay Low Risk,
  because forwarded and badly configured legitimate mail fails them too. A failure is its own
  signal, separate from other header findings, and together with any other finding worth 10
  points or more the score is at least 45.

## Mailing lists are not spoofing

Lists set Reply-To to the list address. Comparing full domains flagged every list email.
Reply-To is now compared by registered domain, and mail with `List-Id`,
`List-Unsubscribe` or `Precedence: list` is exempt. Bulk-mail wording is only scored for
non-list mail.

## Brand impersonation needs a claim

Matching words like "office" or "meta" anywhere in the body flagged tech newsletters as
Microsoft or Facebook impersonation. Now the strong case is the display name or subject
claiming a brand while the sender domain belongs to someone else. A brand mentioned only in
the body, with links elsewhere, counts only when the email also asks for credentials or
threatens the account. Brand names are compared after folding look-alike characters
(`lCIoud` → `icloud`, Cyrillic `а` → `a`).

## Spending VirusTotal lookups

The free API allows 4 requests a minute, so each email gets at most 4 lookups, in this
order: sender domain, Reply-To domain, public IP addresses, then link domains from most to
least suspicious. Free webmail and well-known domains are skipped. A domain counts as
malicious only when at least two vendors flag it; a single flag (a common false positive,
seen with pypi.org) adds 10 points and is shown as weak evidence. Requests are paced, a
429 pauses lookups for two minutes, and only successful answers are cached.

## The dashboard shows attacker-controlled text

Subjects, addresses and URLs come from the email, so everything is escaped before it is
inserted into the page, and URLs are shown defanged (`hxxp://evil[.]xyz`) and never
clickable. Uploaded file names go through `os.path.basename()` so they can't escape the
uploads folder.

## Evaluating honestly

- Rules were tuned on a dev split only. Each test set was run once, after the rules were
  frozen.
- The main metric is binary (Phishing or Suspicious = flagged). Strict and lenient views are
  reported too, because the middle verdicts are judgement calls.
- Duplicates are detected by SHA-256.
- The AI report is skipped during evaluation because it never changes the verdict.

The first evaluation used 2002 SpamAssassin spam as the "phishing" class. Most of it is
marketing spam, not credential theft, so it was replaced with real phishing from Phishing Pot.

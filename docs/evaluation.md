# Evaluation

Unless a section says otherwise, numbers were measured with online checks off (`--offline`),
so they reflect the offline rules only. "Flagged" means a Phishing or Suspicious verdict.

## Fresh set (600 emails, run once)

Built after the last rule change (24 October 2026) and run a single time, so nothing was tuned
on it. This is the number to quote.

- **Phishing:** 300 Phishing Pot samples picked at random from the whole collection
  (sample-26 to sample-11950), excluding every sample used before. Checked by number and SHA-256.
- **Legitimate:** 300 posts from 10 Apache lists that were not used before, April to June 2026:
  users@activemq, users@camel, users@solr, dev@commons, dev@tomcat, user@cassandra, user@hive,
  user@zookeeper, users@groovy, users@nifi.

| View | Accuracy | Precision | Recall | False-positive rate |
| --- | --- | --- | --- | --- |
| Binary (Phishing or Suspicious) | 72.5% | 99.3% | 45.3% | 0.3% |
| Strict (Phishing only) | 62.0% | 100% | 24.0% | 0.0% |
| Lenient (anything but Benign) | 86.8% | 97.4% | 75.7% | 2.0% |

With the rules from before the change, the same set gave 41.0% recall and the same single
false positive (a link whose long, hyphenated domain looks generated).

Of the 164 missed phishing emails, 52 triggered no rule at all, often because they are mostly
images or not in English, and 71 had exactly one signal.

## Rule changes of 24 October 2026

Tuned on the dev split only (200 phishing + 100 legitimate):

1. A sender name or subject claiming a brand the sender doesn't own is at least Suspicious.
2. A failed SPF/DKIM/DMARC check counts as its own signal, and together with any other finding
   worth 10+ points the email is at least Suspicious. Plain HTTP (5 points) does not count.
3. VirusTotal needs two vendors before a domain counts as malicious; one vendor adds 10 points.

Dev recall went from 45.0% to 50.5% with no false positives. Rule 3 can't be measured offline.

## 2026 set (600 emails)

These and the held-out numbers below were first measured before the rule changes and then
re-run afterwards, so they are no longer blind. Both are shown.

- **Phishing:** the 300 newest samples from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot)
  (sample-11969 to sample-12274), excluding any used during development.
- **Legitimate:** 300 posts from 8 [Apache mailing lists](https://lists.apache.org/), July to
  September 2026: announce, dev@airflow, dev@httpd, user@flink, user@spark, users@kafka,
  users@maven, users@tomcat. Random sample per list, at most 40 each (54 from Tomcat).

| View | Accuracy | Precision | Recall | False-positive rate |
| --- | --- | --- | --- | --- |
| Binary, before the changes | 86.5% | 100% | 73.0% | 0.0% |
| Binary, after the changes | 87.2% | 100% | 74.3% | 0.0% |
| Strict, before | 75.5% | 100% | 51.0% | 0.0% |
| Lenient, before and after | 89.5% | 89.9% | 89.0% | 10.0% |

Before the changes, the phishing half got 153 Phishing, 66 Suspicious, 48 Low Risk and 33 Benign
verdicts; the legitimate half got 270 Benign and 30 Low Risk.

Caveats:

- The newest Phishing Pot samples are dominated by a few campaigns (casino and free-spins
  scams from throwaway Microsoft 365 tenants), so recall here mostly reflects those.
- All legitimate emails are mailing-list posts. The analyzer treats list mail more leniently,
  so this is an easy set for false positives.

## Held-out set (400 emails)

- **Phishing:** 200 Phishing Pot samples.
- **Legitimate:** 200 SpamAssassin easy_ham and hard_ham messages (2002-03).
- A separate dev split (200 + 100) was used for tuning.

| View | Accuracy | Precision | Recall | False-positive rate |
| --- | --- | --- | --- | --- |
| Binary, before the changes | 70.3% | 94.5% | 43.0% | 2.5% |
| Binary, after the changes | 73.5% | 95.2% | 49.5% | 2.5% |
| Strict, before | 61.0% | 97.8% | 22.5% | 0.5% |
| Lenient, before and after | 84.3% | 86.6% | 81.0% | 12.5% |

For comparison, the first version of the analyzer scored 38.3% accuracy with an 87%
false-positive rate on this set, mostly because failed lookups were counted as evidence.

The legitimate mail is 20+ years older than the phishing, which makes the two classes easier
to tell apart than in real life.

## With online checks on

2026 set, run on 24-25 October 2026 with WHOIS, DNS and VirusTotal (free API key) after the
rule changes:

| View | Accuracy | Precision | Recall | False-positive rate |
| --- | --- | --- | --- | --- |
| Binary (Phishing or Suspicious) | 92.3% | 99.2% | 85.3% | 0.7% |
| Strict (Phishing only) | 88.0% | 99.1% | 76.7% | 0.7% |
| Lenient (anything but Benign) | 91.3% | 88.0% | 95.7% | 13.0% |

- Online checks raise recall from 74.3% to 85.3%. VirusTotal confirmed a malicious domain
  (2+ vendors) in 135 of the 300 phishing emails, and DNS found a non-existent link domain
  in 70.
- Before the two-vendor rule, a dashboard run of the same legitimate emails flagged 19 of
  them (6.3%), mostly because one vendor flagged pypi.org. Now 2 are flagged.
- One of those two, `apache-announce-021.eml`, is not legitimate: it is a "missed voicemail"
  phishing email that was posted to announce@apache.org, with a link that 11 vendors flag.
  The analyzer was right and the label is wrong. Offline, it scored too low to be flagged.
- The remaining false positive links to cybersecuritynews.com, which three VirusTotal vendors
  flag as malicious. A reputation service is only as good as its vendors.

## Reproducing

1. Download the data:
   - Phishing Pot: `git clone https://github.com/rf-peixoto/phishing_pot`
   - Apache lists, one month per request:
     `https://lists.apache.org/api/mbox.lua?list=users@tomcat.apache.org&date=2026-09`
2. Split mbox files into `.eml` files:
   `python scripts/mbox_to_eml.py <file.mbox> ../datasets/public_2026/benign --max 40`
3. Put phishing emails in `datasets/public_2026/phishing/` and run, from `backend/`:

```bash
python -m tests.evaluate_dataset --dataset ../datasets/public_2026 --offline --csv results.csv
```

The CSV has one row per email with the score from each component, which is the quickest way
to see why an email was missed.

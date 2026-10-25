# Sample emails

Small emails for trying the dashboard. Upload one at http://127.0.0.1:8000/dashboard.

| File | What it is | Verdict (offline) |
| --- | --- | --- |
| `benign.eml` | Ordinary account summary | Benign |
| `sus_legit.eml` | Security-themed but legitimate wording | Benign |
| `leg_phishing.eml` | Real Microsoft-style notice from microsoft.com | Benign |
| `phishing_to.eml` | Fake Microsoft "verify your account" | Phishing |
| `mal_infra.eml` | Urgent verification request with a malicious-looking link | Phishing |
| `sample-10.eml` | Real phishing: fake Microsoft sign-in alert | Phishing |
| `sample-100.eml` | Real spam/phishing: solar-panel offer | Low Risk |
| `sample-1.eml` | Real phishing in Portuguese (bank points scam) | Benign (missed) |

The five short samples were written for this project. The three `sample-*.eml` files are
from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) by rf-peixoto, licensed
[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/). They are real phishing
emails: don't open their links.

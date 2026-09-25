# Local Phish Alert: Outlook add-in (static files)

The static files of the Outlook add-in from CSIT998 Project 12, *Privacy-First On-Device Phishing and BEC
Detection*, served by GitHub Pages because Outlook loads add-in pages over HTTPS.

Only code and icons are hosted here. The add-in runs inside Outlook on the user's computer and sends
email content only to a local model (Ollama on `localhost`). No email content is sent to this site.

Current stage: an early spike that checks the add-in loads, can read the open message, and can reach
Ollama on the same computer.

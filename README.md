# Local Phish Alert: Outlook add-in (static files)

The static files of the Outlook add-in from CSIT998 Project 12, *Privacy-First On-Device Phishing and BEC
Detection*, served by GitHub Pages because Outlook loads add-in pages over HTTPS.

Only code and icons are hosted here. The add-in runs inside Outlook on the user's computer and sends
email content only to a local model (Ollama on `localhost`). No email content is sent to this site.

Current stage: step 3 of the MVP. The add-in checks the open email with the detection core and the local
model, and shows the verdict above the message and in a pinnable pane. `app-<hash>/` holds the code;
`build.json` names the current folder.

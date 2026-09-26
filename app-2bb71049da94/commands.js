// The one-click toolbar command (D17): checks the open message without opening the pane
// and shows the verdict only in the message's notification bar. Used where the pane
// cannot be pinned (Outlook.com, R5).

import { checkItem, showBar, CheckError } from "./check.js";

export async function checkMessage(event) {
  const item = Office.context.mailbox.item;
  try {
    await showBar(item, { alert: { kind: "checking" } });
    await showBar(item, await checkItem(item));
  } catch (err) {
    await showBar(item, err instanceof CheckError ? err : new CheckError("failed", String(err && err.message)));
  } finally {
    event.completed();
  }
}

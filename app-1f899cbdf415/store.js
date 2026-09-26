// Settings and the trust list (R6, decision D21). They are kept in Office roaming
// settings: a per-add-in store in the user's own mailbox that only this add-in can read
// through Office.js, shared by the pane and Quick check, and available on the user's
// other devices. Only sender keys are stored, never email content.
//
// Removing the add-in does not delete roaming settings, so the settings view offers
// "Remove all my data" (NFR-9, D10).

const TRUSTED = "trustedSenders";
const MAX_TRUSTED = 500;   // roaming settings hold at most 32 KB per add-in

const settings = () => Office.context.roamingSettings;

function save() {
  return new Promise((resolve, reject) => settings().saveAsync((r) => {
    if (r.status === Office.AsyncResultStatus.Succeeded) resolve();
    else reject(new Error(r.error ? r.error.message : "could not save settings"));
  }));
}

/** The trusted sender keys (registrable domains, or addresses at free-mail providers). */
export function trusted() {
  const v = settings().get(TRUSTED);
  return new Set(Array.isArray(v) ? v : []);
}

export async function trust(key) {
  const s = trusted();
  if (s.size >= MAX_TRUSTED) throw new Error(`The trust list is full (${MAX_TRUSTED} senders).`);
  s.add(key);
  settings().set(TRUSTED, [...s].sort());
  await save();
}

export async function untrust(key) {
  const s = trusted();
  s.delete(key);
  settings().set(TRUSTED, [...s].sort());
  await save();
}

/** Delete everything this add-in stored. */
export async function removeAll() {
  settings().remove(TRUSTED);
  await save();
}

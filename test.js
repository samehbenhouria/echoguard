"use strict";
/* EchoGuard v1 — Node test suite (PREP_DEPOT.md: green suite required before submission) */
const E = require("./engine.js");
let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log("PASS  " + name); }
  else { fail++; console.log("FAIL  " + name + (extra ? " — " + extra : "")); }
}
function ids(r) { return r.signals.map(s => s.id); }

const bank = E.analyze(E.SAMPLES.bank_scam.text);
check("bank_scam score 100", bank.score === 100, "got " + bank.score);
check("bank_scam HIGH", bank.levelCode === "HIGH");
check("bank_scam has credential_request", ids(bank).includes("credential_request"));

const gp = E.analyze(E.SAMPLES.grandparent_scam.text);
check("grandparent_scam HIGH", gp.levelCode === "HIGH", "score " + gp.score);
check("grandparent_scam score 75 (100 was the old double-count bug)", gp.score === 75, "got " + gp.score);
// The v1 fix: "read me the numbers" must be payment, NOT credential
check("overlap fix: grandparent has payment_request", ids(gp).includes("payment_request"));
check("overlap fix: grandparent has NO credential_request", !ids(gp).includes("credential_request"), ids(gp).join(","));
const numbersOnly = E.analyze("Please buy gift cards and read me the numbers.");
check("overlap fix: numbers-only classified payment", ids(numbersOnly).includes("payment_request") && !ids(numbersOnly).includes("credential_request"), ids(numbersOnly).join(","));
const codeOnly = E.analyze("Please read me the verification code we sent you.");
check("credential still works for real codes", ids(codeOnly).includes("credential_request"));

const cra = E.analyze(E.SAMPLES.cra_scam.text);
check("cra_scam (new sample) HIGH", cra.levelCode === "HIGH", "score " + cra.score);
check("cra_scam has authority_threat", ids(cra).includes("authority_threat"));

const clinic = E.analyze(E.SAMPLES.legit_reminder.text);
check("legit_reminder 0 LOW", clinic.score === 0 && clinic.levelCode === "LOW", "score " + clinic.score + " " + ids(clinic).join(","));

const pharm = E.analyze(E.SAMPLES.legit_pharmacy.text);
check("legit_pharmacy (new sample) LOW <20", pharm.score < 20 && pharm.levelCode === "LOW", "score " + pharm.score + " " + ids(pharm).join(","));

const empty = E.analyze("");
check("empty 0 LOW", empty.score === 0 && empty.levelCode === "LOW");

// Family code word
const gpNoCode = E.analyze(E.SAMPLES.grandparent_scam.text, { familyCodeWord: "maple-syrup" });
check("family code missing flagged +25 path", ids(gpNoCode).includes("family_code_missing") && gpNoCode.familyCodeCheck === "failed");
check("family code missing brings grandparent to 100", gpNoCode.score === 100, "got " + gpNoCode.score);
const gpWithCode = E.analyze(E.SAMPLES.grandparent_scam.text + " The code word is maple-syrup.", { familyCodeWord: "maple-syrup" });
check("family code given passes", !ids(gpWithCode).includes("family_code_missing") && gpWithCode.familyCodeCheck === "passed");
const bankCodeNA = E.analyze(E.SAMPLES.bank_scam.text, { familyCodeWord: "maple-syrup" });
check("family code N/A on non-family call", !ids(bankCodeNA).includes("family_code_missing"));

// Paraphrase robustness (jury correction): scammers who avoid the classic wording
const paraEn = E.analyze("Go to the store and get prepaid cards for the amount. Do not hang up, stay by the phone, and give me the six digit code when it arrives.");
check("paraphrase EN scam HIGH (prepaid + don't hang up + six-digit code)", paraEn.levelCode === "HIGH" && ids(paraEn).includes("payment_request") && ids(paraEn).includes("credential_request") && ids(paraEn).includes("secrecy"), "score " + paraEn.score + " " + ids(paraEn).join(","));
const paraFr = E.analyze("Achetez des cartes prépayées au magasin. Ne raccrochez pas et donnez-moi le code à six chiffres dès que vous le recevez.", { lang: "fr" });
check("paraphrase FR scam HIGH", paraFr.levelCode === "HIGH" && ids(paraFr).includes("payment_request") && ids(paraFr).includes("credential_request"), "score " + paraFr.score + " " + ids(paraFr).join(","));

// FR
const bankFr = E.analyze(E.SAMPLES.bank_scam.text, { lang: "fr" });
check("FR verdict RISQUE ÉLEVÉ", bankFr.level === "RISQUE ÉLEVÉ", bankFr.level);
check("FR signal label present", bankFr.signals.length > 0 && /Paiement|Codes|Secret|Urgence|Autorité/.test(bankFr.signals[0].label));

console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);

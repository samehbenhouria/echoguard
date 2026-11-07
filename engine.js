/*
 * EchoGuard — scam-call risk engine (v1, SLAY HACKS 2026 submission build, 2026-11-07)
 *
 * Transparent, explainable detection of social-engineering patterns in a
 * call transcript. Every point of the score is tied to a named signal and
 * the exact phrase that triggered it — no black-box verdict.
 * Works in the browser (window.EchoGuard) and in Node (module.exports).
 * v1 changes vs baseline v0.1 (PREP_DEPOT.md closed scope):
 *  - Fixed credential/payment overlap: "read me the numbers" (gift-card
 *    numbers) is a PAYMENT signal, not a credential request.
 *  - Family code-word check (+25 when a caller claiming to be family in
 *    an emergency cannot give the family secret word).
 *  - 2 new samples: CRA / revenue-agency scam, legitimate pharmacy call.
 *  - Bilingual EN/FR labels, advice and verdicts.
 */
(function (global) {
  "use strict";

  var SIGNALS = [
    {
      id: "payment_request",
      label: "Payment requested in an unusual way",
      label_fr: "Paiement demandé d'une façon inhabituelle",
      weight: 30,
      patterns: [
        /gift cards?/i, /wire (transfer|the money)/i, /send (money|funds|payment)/i,
        /e-?transfer/i, /bitcoin|crypto(currency)?/i, /cash .{0,20}(mail|courier|pick ?up)/i,
        /buy .{0,20}cards?/i, /transfer .{0,30}(now|today|immediately)/i,
        /read (me )?(the )?numbers/i, /pay (now|immediately|today) (by|with|via)/i,
        /prepaid cards?/i, /cartes? prépayées?/i, /steam cards?|itunes cards?|google play cards?/i,
        /money ?gram|western union/i, /cartes? (cadeaux?|d'achat)/i
      ],
      advice: "A real bank, police service or agency never asks to be paid in gift cards, crypto or a rushed transfer.",
      advice_fr: "Une vraie banque, un vrai service de police ou un vrai organisme ne demande jamais d'être payé en cartes-cadeaux, en crypto ou par un virement précipité."
    },
    {
      id: "credential_request",
      label: "Personal codes or credentials requested",
      label_fr: "Codes personnels ou identifiants demandés",
      weight: 30,
      patterns: [
        /verification code/i, /one-time (code|password)/i, /your password/i,
        /social insurance/i, /\bSIN\b/, /banking (details|password|PIN)/i,
        /read (me )?(the )?(verification )?code/i, /account number/i,
        /code de vérification/i, /mot de passe/i, /numéro d'assurance sociale/i,
        /six[- ]digit code/i, /code à (six|\d+) chiffres/i, /code (de|à) \d+ chiffres/i,
        /the \d+[- ]digit code/i, /donnez?[- ]moi le code/i, /give me the code/i
      ],
      advice: "Never share a password, PIN or one-time code. The real institution already has your information.",
      advice_fr: "Ne partagez jamais un mot de passe, un NIP ou un code à usage unique. La vraie institution a déjà vos renseignements."
    },
    {
      id: "secrecy",
      label: "Secrecy demanded",
      label_fr: "Secret exigé",
      weight: 25,
      patterns: [
        /don'?t tell (anyone|your|them)/i, /do not tell/i, /keep (this|it) (secret|between us)/i,
        /don'?t (call|contact) (your )?(bank|family)/i, /stay on the (line|phone)/i,
        /tell (no one|nobody)/i, /ne (le )?dites? à personne/i, /gardez? (cela|ça) secret/i, /restez? en ligne/i,
        /don'?t hang up/i, /ne raccrochez pas/i, /stay (near|by|with) (the )?phone/i,
        /keep (your )?(phone|device) (near|with you|close)/i, /gardez? (l'appareil|le téléphone) (près de vous|avec vous)/i
      ],
      advice: "Secrecy is the scammer's main tool. A legitimate caller will always let you hang up and verify.",
      advice_fr: "Le secret est l'outil principal de l'arnaqueur. Un appelant légitime vous laissera toujours raccrocher et vérifier."
    },
    {
      id: "urgency",
      label: "Artificial urgency / pressure",
      label_fr: "Urgence artificielle / pression",
      weight: 20,
      patterns: [
        /immediately/i, /right now/i, /within (the next )?\d+ (minutes?|hours?)/i,
        /before it'?s too late/i, /act (now|fast|quickly)/i, /urgent(ly)?/i,
        /today or (else|your)/i, /expires? (today|now)/i,
        /immédiatement/i, /tout de suite/i, /avant qu'il (ne )?soit trop tard/i
      ],
      advice: "Pressure is designed to stop you from thinking. Real deadlines survive a night's sleep.",
      advice_fr: "La pression vise à vous empêcher de réfléchir. Les vraies échéances survivent à une nuit de sommeil."
    },
    {
      id: "authority_threat",
      label: "Authority claimed + threat made",
      label_fr: "Autorité invoquée + menace proférée",
      weight: 20,
      patterns: [
        /(police|officer|detective) .{0,40}(arrest|warrant)/i, /you will be arrested/i,
        /warrant/i, /account (will be |is )?(frozen|closed|suspended)/i,
        /legal action/i, /fraud department/i, /suspicious activity/i,
        /(son|daughter|grandson|granddaughter) .{0,40}(jail|arrested|accident|hospital)/i,
        /canada revenue agency|agence du revenu/i, /mandat d'arrêt/i, /compte (sera |est )?(gelé|fermé|suspendu)/i
      ],
      advice: "Police and banks do not arrest by phone or freeze accounts over a call. Hang up and call the official number yourself.",
      advice_fr: "La police et les banques n'arrêtent personne par téléphone et ne gèlent pas un compte au téléphone. Raccrochez et composez vous-même le numéro officiel."
    },
    {
      id: "remote_access",
      label: "Remote access or app install requested",
      label_fr: "Accès à distance ou installation d'application demandée",
      weight: 25,
      patterns: [
        /install (this|the|an?) (app|software)/i, /anydesk|teamviewer/i,
        /remote access/i, /share your screen/i, /download .{0,20}(app|software)/i,
        /installez? (cette |l')?application/i, /partagez? votre écran/i, /accès à distance/i
      ],
      advice: "Never install software or share your screen at a caller's request — that hands them your device.",
      advice_fr: "N'installez jamais un logiciel et ne partagez jamais votre écran à la demande d'un appelant — c'est lui remettre votre appareil."
    }
  ];

  var FAMILY_CLAIM = /(grandson|granddaughter|my son|my daughter|it's me,|c'est moi|petit-fils|petite-fille|mon fils|ma fille|grandma|grandpa|mamie|papi)/i;
  var FAMILY_EMERGENCY = /(accident|jail|arrested|hospital|emergency|bail|prison|hôpital|urgence)/i;

  function analyze(transcript, opts) {
    opts = opts || {};
    var lang = opts.lang === "fr" ? "fr" : "en";
    var text = String(transcript || "");
    var hits = [];
    var score = 0;
    SIGNALS.forEach(function (sig) {
      var matched = null;
      for (var i = 0; i < sig.patterns.length; i++) {
        var m = text.match(sig.patterns[i]);
        if (m) { matched = m[0]; break; }
      }
      if (matched) {
        hits.push({
          id: sig.id,
          label: lang === "fr" ? sig.label_fr : sig.label,
          label_en: sig.label, label_fr: sig.label_fr,
          weight: sig.weight, evidence: matched,
          advice: lang === "fr" ? sig.advice_fr : sig.advice
        });
        score += sig.weight;
      }
    });

    // Family code-word check (v1)
    var familyCode = String(opts.familyCodeWord || opts.familyCode || "").trim();
    var familyCodeCheck = "not_configured";
    if (familyCode) {
      var claimsFamily = FAMILY_CLAIM.test(text) && FAMILY_EMERGENCY.test(text);
      if (claimsFamily) {
        if (text.toLowerCase().indexOf(familyCode.toLowerCase()) !== -1) {
          familyCodeCheck = "passed";
        } else {
          familyCodeCheck = "failed";
          hits.push({
            id: "family_code_missing",
            label: lang === "fr" ? "Mot secret de famille absent" : "Family code word missing",
            label_en: "Family code word missing", label_fr: "Mot secret de famille absent",
            weight: 25, evidence: lang === "fr" ? "proche en urgence, mot secret non donné" : "family emergency claim, code word not given",
            advice: lang === "fr"
              ? "Demandez le mot secret convenu en famille. Un proche le connaît ; un arnaqueur ne peut pas le deviner. S'il ne peut pas le donner, raccrochez et rappelez votre proche à son numéro habituel."
              : "Ask for the family code word you agreed on. A real relative knows it; a scammer cannot guess it. If they cannot give it, hang up and call your relative back on their usual number."
          });
          score += 25;
        }
      } else {
        familyCodeCheck = "not_applicable";
      }
    }

    score = Math.min(score, 100);
    var level, levelCode, action;
    if (score >= 50) {
      levelCode = "HIGH";
      level = lang === "fr" ? "RISQUE ÉLEVÉ" : "HIGH RISK";
      action = lang === "fr"
        ? "PAUSE. Raccrochez. N'envoyez rien. Rappelez l'institution au numéro imprimé sur sa carte ou son site officiel, et parlez à un membre de votre famille avant de faire quoi que ce soit d'autre."
        : "PAUSE. Hang up. Do not send anything. Call the institution back on the number printed on its official card or website, and talk to a family member before doing anything else.";
    } else if (score >= 20) {
      levelCode = "CAUTION";
      level = lang === "fr" ? "PRUDENCE" : "CAUTION";
      action = lang === "fr"
        ? "Ralentissez. Demandez le nom de l'appelant, son service et un numéro de dossier, puis raccrochez et vérifiez par un canal officiel avant d'agir."
        : "Slow down. Ask for the caller's name, service and a case number, then hang up and verify through an official channel before acting.";
    } else {
      levelCode = "LOW";
      level = lang === "fr" ? "RISQUE FAIBLE" : "LOW RISK";
      action = lang === "fr"
        ? "Aucun schéma d'arnaque classique détecté dans ce texte. Restez prudent : ne partagez jamais de codes ni de mots de passe au téléphone, qui que ce soit qui les demande."
        : "No classic scam pattern detected in this text. Stay prudent: never share codes or passwords on any call, whoever asks.";
    }
    return { score: score, level: level, levelCode: levelCode, action: action, signals: hits, familyCodeCheck: familyCodeCheck };
  }

  var SAMPLES = {
    bank_scam: {
      title: "Simulated call — 'bank fraud department'",
      title_fr: "Appel simulé — « service des fraudes » de la banque",
      text: "This is Officer Martin from your bank's fraud department. We detected suspicious activity and your account will be frozen today. A warrant will be issued and you will be arrested unless you act immediately. Do not tell anyone and don't call your branch, they are part of the investigation. Stay on the line and transfer the money now to a safe account, and read me the verification code we just sent you."
    },
    grandparent_scam: {
      title: "Simulated call — 'grandparent emergency'",
      title_fr: "Appel simulé — « urgence du petit-fils »",
      text: "Grandma, it's me, please don't tell anyone. I was in an accident and I'm in jail right now. I need you to send money immediately for bail. Please buy gift cards and read me the numbers, and keep this secret between us until I'm out."
    },
    cra_scam: {
      title: "Simulated call — 'Canada Revenue Agency'",
      title_fr: "Appel simulé — « Agence du revenu du Canada »",
      text: "This is Officer Daniel Roy from the Canada Revenue Agency. Our audit found unpaid taxes and a warrant will be issued for your arrest today. You will be arrested unless you pay immediately by e-transfer or bitcoin. Do not tell anyone about this case and do not contact your bank. Stay on the line and read me the verification code from the text message we sent to confirm your identity."
    },
    legit_reminder: {
      title: "Simulated call — clinic appointment reminder",
      title_fr: "Appel simulé — rappel de rendez-vous à la clinique",
      text: "Hello, this is the clinic calling to confirm your appointment on Tuesday at 10 a.m. If you need to reschedule, you can call us back at the number on your appointment card during opening hours. Have a good day."
    },
    legit_pharmacy: {
      title: "Simulated call — pharmacy prescription ready",
      title_fr: "Appel simulé — pharmacie, ordonnance prête",
      text: "Hello, this is Marie from your pharmacy on Main Street. Your prescription refill is ready for pickup at the counter. We are open until 9 p.m. today and tomorrow. Please bring your health card when you come in. If you have questions about your medication, our pharmacist will be glad to help you in person. Thank you and take care."
    }
  };

  var api = { analyze: analyze, SIGNALS: SIGNALS, SAMPLES: SAMPLES };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.EchoGuard = api;
})(typeof window !== "undefined" ? window : globalThis);

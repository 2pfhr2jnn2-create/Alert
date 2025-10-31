import express from "express";
import axios from "axios";
import crypto from "crypto";
import helmet from "helmet";
import morgan from "morgan";

const app = express();
app.use(express.json({ limit: "512kb" }));
app.use(helmet());
app.use(morgan("tiny"));

const {
  TELEGRAM_BOT_TOKEN,
  DEFAULT_CHAT_ID,
  ABSOLUTE_SILENCE = "true",
  HMAC_SECRET,
  ALLOW_CHAT_IDS,
  DEBUG_LOG,
} = process.env;

const tgBase = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const allowSet = new Set((ALLOW_CHAT_IDS || "").split(",").filter(Boolean));
const seen = new Set();

// --- Sécurité HMAC ---
function verifyHmac(req) {
  if (!HMAC_SECRET) return true; // tu peux laisser vide pour tester
  const sig = req.get("X-Signature") || "";
  const body = JSON.stringify(req.body || {});
  const h = crypto.createHmac("sha256", HMAC_SECRET).update(body).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(h));
  } catch {
    return false;
  }
}

// --- Formatter tolérant Whale Alert (REST/WebSocket, wrappers, tableaux) ---
function formatWhaleAlert(payload) {
  // 1) retrouver l'objet transaction, peu importe l'enrobage
  let root = payload && (payload.transaction || payload.payload || payload);
  if (root && root.exemples && Array.isArray(root.exemples)) root = root.exemples[0];
  else if (root && root.data && Array.isArray(root.data.transactions)) root = root.data.transactions[0];
  else if (root && root.transactions && Array.isArray(root.transactions)) root = root.transactions[0];
  const base = Array.isArray(root) ? (root[0] || {}) : (root || {});

  // 2) champs principaux
  const chain =
    base.blockchain ||
    base.network ||
    (base.currency && base.currency.blockchain) ||
    "unknown";

  const ts = Number(base.timestamp || base.time || Date.now() / 1000);
  const dt = new Date(ts * 1000).toISOString();

  // 3) sous-transactions (si déjà présentes)
  let subs = Array.isArray(base.sub_transactions) ? base.sub_transactions : [];

  // 4) sinon, reconstruire depuis symbol/amount/amount_usd + from/to
  if (!subs.length) {
    const symbol = (base.symbol || base.currency || base.ticker || "").toLowerCase();
    const amount = Number(base.amount || base.volume || 0);
    const amountUsd = Number(base.amount_usd || base.value_usd || base.usd || 0);
    const unit_price_usd = amount ? amountUsd / amount : undefined;

    const fromOwner =
      base.from?.owner ||
      base.from_owner ||
      base.from?.address ||
      base.inputs?.[0]?.owner ||
      base.inputs?.[0]?.address ||
      "unknown";

    const toOwner =
      base.to?.owner ||
      base.to_owner ||
      base.to?.address ||
      base.outputs?.[0]?.owner ||
      base.outputs?.[0]?.address ||
      "unknown";

    if (symbol || amount) {
      subs = [
        {
          symbol,
          amount,
          unit_price_usd,
          inputs: [{ owner: fromOwner }],
          outputs: [{ owner: toOwner }],
        },
      ];
    }
  }

  // 5) valeur USD approx + champs lisibles
  const valueUSD =
    subs.reduce((acc, s) => acc + (Number(s.unit_price_usd || 0) * Number(s.amount || 0)), 0) ||
    Number(base.amount_usd || base.value_usd || 0) || 0;

  const amountsLine = subs.length
    ? subs.map((s) => `${(s.symbol || "").toUpperCase()} ${s.amount ?? "?"}`).join(", ")
    : "?";

  const from =
    subs?.[0]?.inputs?.[0]?.owner ||
    base.from?.owner ||
    base.from_owner ||
    base.from?.address ||
    "unknown";

  const to =
    subs?.[0]?.outputs?.[0]?.owner ||
    base.to?.owner ||
    base.to_owner ||
    base.to?.address ||
    "unknown";

  const title = `*🐋 Whale Alert*`;
  const body = `• Réseau: ${chain}
• De → À: ${from} → ${to}
• Montants: ${amountsLine}
• Valeur ~$${valueUSD ? Math.round(valueUSD).toLocaleString("en-US") : "?"}
• Date: ${dt}`;

  return { title, body };
}

// --- Endpoint d’ingestion (crypto uniquement) ---
app.post("/ingest", async (req, res) => {
  try {
    if (DEBUG_LOG === "true") console.log("INGEST BODY:", JSON.stringify(req.body).slice(0, 500));

    if (!verifyHmac(req)) return res.status(401).json({ ok: false, error: "bad signature" });

    const { type = "whale", chat_id, idempotency_key, payload } = req.body || {};

    // anti-duplication 5 minutes
    const key = idempotency_key || crypto.createHash("md5").update(JSON.stringify(req.body)).digest("hex");
    if (seen.has(key)) return res.json({ ok: true, dedup: true });
    seen.add(key);
    setTimeout(() => seen.delete(key), 5 * 60 * 1000);

    const targetChat = String(chat_id || DEFAULT_CHAT_ID);
    if (allowSet.size && !allowSet.has(targetChat)) {
      return res.status(403).json({ ok: false, error: "chat not allowed" });
    }

    let msg = "Nouvelle alerte.";
    if (type === "whale") {
      const { title, body } = formatWhaleAlert(payload || {});
      msg = `${title}\n${body}`;
    }

    // envoi silencieux
    await axios.post(`${tgBase}/sendMessage`, {
      chat_id: targetChat,
      text: msg,
      parse_mode: "Markdown",
      disable_web_page_preview: true,
      disable_notification: String(ABSOLUTE_SILENCE).toLowerCase() === "true",
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erreur /ingest:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Healthcheck simple
app.get("/", (_req, res) => res.send("OK"));

const port = process.env.PORT || 10000; // Render définit PORT automatiquement
app.listen(port, () => console.log(`relay up on ${port}`));

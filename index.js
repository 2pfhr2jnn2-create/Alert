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
} = process.env;

const tgBase = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const allowSet = new Set((ALLOW_CHAT_IDS || "").split(",").filter(Boolean));
const seen = new Set();

function verifyHmac(req) {
  if (!HMAC_SECRET) return true; // désactivé si pas de clé
  const sig = req.get("X-Signature") || "";
  const body = JSON.stringify(req.body || {});
  const h = crypto.createHmac("sha256", HMAC_SECRET).update(body).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(h));
  } catch {
    return false;
  }
}

function formatWhaleAlert(payload) {
  // — Tolérant à toutes les structures de Whale Alert —
  let root = payload && (payload.transaction || payload.payload || payload);
  if (root && root.exemples && Array.isArray(root.exemples)) root = root.exemples[0];
  else if (root && root.data && Array.isArray(root.data.transactions))
    root = root.data.transactions[0];
  else if (root && root.transactions && Array.isArray(root.transactions))
    root = root.transactions[0];
  const base = Array.isArray(root) ? root[0] : root || {};

  const chain =
    base.blockchain ||
    base.network ||
    (base.currency && base.currency.blockchain) ||
    "unknown";

  const ts = Number(base.timestamp || base.time || Date.now() / 1000);
  const dt = new Date(ts * 1000).toISOString();

  let subs = Array.isArray(base.sub_transactions) ? base.sub_transactions : [];

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

  const valueUSD =
    subs.reduce(
      (acc, s) => acc + (Number(s.unit_price_usd || 0) * Number(s.amount || 0)),
      0
    ) || Number(base.amount_usd || base.value_usd || 0) || 0;

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

  const title = `🐋 Whale Alert`;
  const body = `• Réseau: ${chain}
• De → À: ${from} → ${to}
• Montants: ${amountsLine}
• Valeur ~$${valueUSD ? Math.round(valueUSD).toLocaleString("en-US") : "?"}
• Date: ${dt}`;

  return { title, body };
}

app.post("/ingest", async (req, res) => {
  try {
    if (!verifyHmac(req))
      return res.status(401).json({ ok: false, error: "bad signature" });

    const { source = "unknown", type = "whale", chat_id, payload } = req.body || {};

    const key =
      crypto.createHash("md5").update(JSON.stringify(req.body)).digest("hex");
    if (seen.has(key)) return res.json({ ok: true, dedup: true });
    seen.add(key);
    setTimeout(() => seen.delete(key), 5 * 60 * 1000);

    const targetChat = String(chat_id || DEFAULT_CHAT_ID);
    if (allowSet.size && !allowSet.has(targetChat)) {
      return res.status(403).json({ ok: false, error: "chat not allowed" });
    }

    let msg = "";
    if (type === "whale") {
      const { title, body } = formatWhaleAlert(payload || {});
      msg = `${title}\n${body}`;
    } else if (type === "xauusd") {
      const { price, change, source_name } = payload || {};
      msg = `🪙 Gold Alert\nPrix: $${price}\nChangement: ${change}%\nSource: ${source_name}`;
    } else {
      msg = "Nouvelle alerte.";
    }

    if (ABSOLUTE_SILENCE === "true") {
      await axios.post(`${tgBase}/sendMessage`, {
        chat_id: targetChat,
        text: msg,
        disable_notification: true,
      });
    } else {
      await axios.post(`${tgBase}/sendMessage`, {
        chat_id: targetChat,
        text: msg,
      });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Erreur /ingest:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`⚡ WhaleAlert bot actif sur port ${port}`);
});

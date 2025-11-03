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
  DEBUG_LOG = "false",
  DEBUG_ECHO = "false",
} = process.env;

const tgBase = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const allowSet = new Set((ALLOW_CHAT_IDS || "").split(",").map(s => s.trim()).filter(Boolean));
const seen = new Set();

// HMAC
function verifyHmac(req) {
  if (!HMAC_SECRET) return true;
  const sig = req.get("X-Signature") || "";
  const body = JSON.stringify(req.body || {});
  const h = crypto.createHmac("sha256", HMAC_SECRET).update(body).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(h)); }
  catch { return false; }
}

// utils
const short = s => (!s ? "unknown" : String(s).length > 16 ? `${String(s).slice(0,6)}…${String(s).slice(-6)}` : String(s));
const niceN = (n, maxFrac=6) => Number(n ?? 0).toLocaleString("en-US", { maximumFractionDigits: maxFrac });

// formatter whale alert
function formatWhaleAlert(payload) {
  const pickOwner = (side) => {
    if (!side) return "unknown";
    const own = side.owner || side.owner_type;
    if (own && String(own).toLowerCase() !== "unknown") return String(own);
    if (side.address) return short(side.address);
    return "unknown";
  };

  let root = payload && (payload.transaction || payload.payload || payload);
  if (root && root.exemples && Array.isArray(root.exemples)) root = root.exemples[0];
  else if (root && root.data && Array.isArray(root.data.transactions)) root = root.data.transactions[0];
  else if (root && root.transactions && Array.isArray(root.transactions)) root = root.transactions[0];
  const base = Array.isArray(root) ? (root[0] || {}) : (root || {});

  const chain =
    base.blockchain || base.network ||
    (base.currency && base.currency.blockchain) || "unknown";

  const ts = Number(base.timestamp || base.time || Date.now()/1000);
  const dt = new Date(ts * 1000).toISOString();

  let subs = Array.isArray(base.sub_transactions) ? base.sub_transactions : [];
  if (!subs.length) {
    const symbol = (base.symbol || base.currency || base.coin || base.asset || base.ticker || "").toUpperCase();
    const amount = Number(base.amount ?? base.quantity ?? base.volume ?? base.size ??
                 (Array.isArray(base.amounts) && base.amounts[0]?.amount) ?? 0);
    const valueUSD = Number(base.amount_usd ?? base.value_usd ?? base.usd_value ?? base.fiat_value_usd ?? base.usd ?? 0);
    const fromOwner = (base.from && (base.from.owner || base.from.address)) ? (base.from.owner || short(base.from.address)) : "unknown";
    const toOwner   = (base.to   && (base.to.owner   || base.to.address))   ? (base.to.owner   || short(base.to.address))   : "unknown";
    if (symbol || amount) {
      const unit_price_usd = amount ? (valueUSD / amount) : undefined;
      subs = [{ symbol, amount, unit_price_usd, inputs:[{ owner: fromOwner }], outputs:[{ owner: toOwner }] }];
    }
  }

  const valueUSD =
    subs.reduce((acc, s) => acc + (Number(s.unit_price_usd || 0) * Number(s.amount || 0)), 0) ||
    Number(base.amount_usd || base.value_usd || 0) || 0;

  const amountsLine = subs.length
    ? subs.map(s => `${(s.symbol || "").toUpperCase()} ${niceN(s.amount)}`).join(", ")
    : "?";

  const from =
    subs?.[0]?.inputs?.[0]?.owner ||
    (base.from && (base.from.owner || short(base.from.address))) || "unknown";

  const to =
    subs?.[0]?.outputs?.[0]?.owner ||
    (base.to && (base.to.owner || short(base.to.address))) || "unknown";

  const title = `🐋 Whale Alert`;
  const body = `• Réseau: ${chain}
• De → À: ${from} → ${to}
• Montants: ${amountsLine}
• Valeur ~$${valueUSD ? Math.round(valueUSD).toLocaleString("en-US") : "?"}
• Date: ${dt}`;

  return { title, body };
}

// healthchecks
app.get("/", (_req, res) => res.send("OK"));
app.get("/ingest", (_req, res) => res.send("Ingest OK — utilisez POST pour envoyer une alerte."));

// ingestion
app.post("/ingest", async (req, res) => {
  try {
    if (DEBUG_LOG === "true") console.log("INGEST BODY:", JSON.stringify(req.body).slice(0,800));
    if (!verifyHmac(req)) return res.status(401).json({ ok:false, error:"bad signature" });

    const { type = "whale", chat_id, idempotency_key, payload, text } = req.body || {};

    // anti-dup 5 min
    const key = idempotency_key || crypto.createHash("md5").update(JSON.stringify(req.body)).digest("hex");
    if (seen.has(key)) return res.json({ ok:true, dedup:true });
    seen.add(key); setTimeout(() => seen.delete(key), 5*60*1000);

    const targetChat = String(chat_id || DEFAULT_CHAT_ID || "");
    if (!targetChat) return res.status(400).json({ ok:false, error:"missing chat id" });
    if (allowSet.size && !allowSet.has(targetChat)) return res.status(403).json({ ok:false, error:"chat not allowed" });

    let msg = "Nouvelle alerte.";
    if (type === "whale") {
      const { title, body } = formatWhaleAlert(payload || {});
      msg = `${title}\n${body}`;
    } else if (type === "digest") {
      // message déjà formatté côté Pipedream (texte libre)
      msg = text || "Résumé quotidien";
    }

    if (DEBUG_ECHO === "true") {
      const preview = JSON.stringify(payload || {}, null, 2).slice(0, 700);
      await axios.post(`${tgBase}/sendMessage`, {
        chat_id: targetChat,
        text: `🔎 DEBUG_ECHO\n${preview}`,
        disable_web_page_preview: true,
        disable_notification: String(ABSOLUTE_SILENCE).toLowerCase() === "true",
      });
    }

    await axios.post(`${tgBase}/sendMessage`, {
      chat_id: targetChat,
      text: msg,
      parse_mode: "Markdown",
      disable_web_page_preview: true,
      disable_notification: String(ABSOLUTE_SILENCE).toLowerCase() === "true",
    });

    res.json({ ok:true });
  } catch (err) {
    console.error("Erreur /ingest:", err?.stack || err?.message || err);
    res.status(500).json({ ok:false, error: err?.message || "server error" });
  }
});

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`relay up on ${port}`));

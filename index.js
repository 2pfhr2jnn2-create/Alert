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
function formatWhaleAlert(tx) {
  const safe = (s) => (!s ? "unknown" :
    s.length > 16 ? `${s.slice(0,6)}…${s.slice(-6)}` : s);

  const pick = (side={}) => {
    if (side.owner && side.owner.toLowerCase() !== "unknown") return side.owner;
    const cands = [
      side.address, side.addr, side.account,
      side?.inputs?.[0]?.address,
      side?.outputs?.[0]?.address,
    ].filter(Boolean);
    return cands.length ? safe(cands[0]) : "unknown";
  };

  const from = pick(tx.from);
  const to = pick(tx.to);
  const coin = (tx.symbol || tx.currency || "?").toUpperCase();
  const amount = Number(tx.amount_usd || tx.value_usd || 0);
  const value = amount ? `$${Math.round(amount).toLocaleString()}` : "?";

  return {
    title: "🐋 Whale Alert",
    body: `• Coin: ${coin}\n• From → To: ${from} → ${to}\n• Value: ${value}`,
  };
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

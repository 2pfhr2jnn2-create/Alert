import express from "express";
import crypto from "crypto";
import axios from "axios";
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
  ALLOW_CHAT_IDS
} = process.env;

const tgBase = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const allowSet = new Set((ALLOW_CHAT_IDS || "").split(",").filter(Boolean));
const seen = new Set();

function verifyHmac(req) {
  if (!HMAC_SECRET) return true; // si non défini, on laisse passer (pour tests)
  const sig = req.get("X-Signature") || "";
  const body = JSON.stringify(req.body || {});
  const h = crypto.createHmac("sha256", HMAC_SECRET).update(body).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(h)); }
  catch { return false; }
}

function formatWhaleAlert(payload) {
  const p = payload.transaction || payload;
  const chain = p.blockchain || payload.blockchain || "blockchain";
  const ts = p.timestamp || payload.timestamp;
  const dt = ts ? new Date(ts * 1000).toISOString() : new Date().toISOString();
  const sub = p.sub_transactions || [];
  const amounts = sub.map(s => `${(s.symbol||"").toUpperCase()} ${s.amount||"?"}`).join(", ");
  const from = sub?.[0]?.inputs?.[0]?.owner || payload.from || "unknown";
  const to = sub?.[0]?.outputs?.[0]?.owner || payload.to || "unknown";
  const valueUSD = sub.reduce((acc, s) => acc + (Number(s.unit_price_usd||0) * Number(s.amount||0)), 0) || payload.min_value_usd;

  return {
    title: `🐋 Whale Alert`,
    body:
`• Réseau: ${chain}
• De → À: ${from} → ${to}
• Montants: ${amounts||"?"}
• Valeur ~$${valueUSD ? Math.round(valueUSD).toLocaleString("en-US") : "?"}
• Date: ${dt}`
  };
}

app.post("/ingest", async (req, res) => {
  try {
    if (!verifyHmac(req)) return res.status(401).json({ ok: false, error: "bad signature" });

    const { source = "unknown", type = "whale", chat_id, idempotency_key, payload } = req.body || {};

    const key = idempotency_key || crypto.createHash("md5").update(JSON.stringify(req.body)).digest("hex");
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
      msg = `*${title}*\n${body}`;
    } else if (type === "xau") {
      const { price, change, source_name } = payload || {};
      msg = `🪙 XAU/USD: *${price}* (${change >= 0 ? "▲" : "▼"} ${change}%)\n_source: ${source_name || "feed"}_`;
    } else {
      msg = "Nouvelle alerte.";
    }

    const disableNotif = String(ABSOLUTE_SILENCE).toLowerCase() === "true";

    const r = await axios.post(`${tgBase}/sendMessage`, {
      chat_id: targetChat,
      text: msg,
      parse_mode: "Markdown",
      disable_web_page_preview: true,
      disable_notification: disableNotif
    });

    return res.json({ ok: true, telegram: r.data });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/", (_req, res) => res.send("OK"));
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("relay up on", port));

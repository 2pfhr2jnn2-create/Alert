// index.js — Render Web Service (Node 20+)
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import crypto from "crypto";

/* =========================
   Config & boot
========================= */
const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(helmet());
app.use(morgan("tiny"));

const {
  TELEGRAM_BOT_TOKEN,
  DEFAULT_CHAT_ID,
  ABSOLUTE_SILENCE = "true",
  HMAC_SECRET,
  ALLOW_CHAT_IDS,            // ex: "12345,67890"
  DEBUG_LOG = "false",       // "true" pour voir les logs request
  DEBUG_ECHO = "false",      // "true" pour envoyer l'écho JSON
  PORT = 10000,
} = process.env;

const tgBase = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const allowSet = new Set((ALLOW_CHAT_IDS || "").split(",").map(s => s.trim()).filter(Boolean));
const seen = new Set();

/* =========================
   Utils
========================= */
const escapeHtml = (str = "") =>
  String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

const shortAddr = (s) => {
  if (!s) return "unknown";
  const ss = String(s);
  return ss.length > 16 ? `${ss.slice(0, 6)}…${ss.slice(-6)}` : ss;
};

const EX_LABELS = [
  { rx: /(okx|okex)/i,         label: "OKX" },
  { rx: /binance/i,            label: "Binance" },
  { rx: /coinbase/i,           label: "Coinbase" },
  { rx: /kraken/i,             label: "Kraken" },
  { rx: /bitfinex/i,           label: "Bitfinex" },
  { rx: /bybit/i,              label: "Bybit" },
  { rx: /huobi|htx/i,          label: "HTX" },
  { rx: /kucoin/i,             label: "KuCoin" },
  { rx: /bitstamp/i,           label: "Bitstamp" },
  { rx: /mexc/i,               label: "MEXC" },
  { rx: /gate(\.io)?/i,        label: "Gate.io" },
  { rx: /gemini/i,             label: "Gemini" },
  { rx: /poloniex/i,           label: "Poloniex" },
  { rx: /bitget/i,             label: "Bitget" },
];

const normalizeExchange = (str) => {
  if (!str) return null;
  for (const { rx, label } of EX_LABELS) if (rx.test(String(str))) return label;
  return null;
};

const pickSideLabel = (side = {}) => {
  const owner = side.owner || side.owner_type;
  if (owner && String(owner).toLowerCase() !== "unknown") {
    return normalizeExchange(owner) || String(owner);
  }
  const candidates = [
    side.address, side.addr, side.account,
    side?.inputs?.[0]?.address,
    side?.outputs?.[0]?.address,
  ].filter(Boolean);
  return candidates.length ? shortAddr(candidates[0]) : "unknown";
};

function verifyHmac(req) {
  if (!HMAC_SECRET) return true; // HMAC optionnel (utile pour tests)
  const sig = req.get("X-Signature") || "";
  const body = JSON.stringify(req.body || {});
  try {
    const h = crypto.createHmac("sha256", HMAC_SECRET).update(body).digest("hex");
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(h));
  } catch {
    return false;
  }
}

async function sendTelegram(chat_id, text) {
  if (!TELEGRAM_BOT_TOKEN) return;
  const payload = {
    chat_id,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    disable_notification: (ABSOLUTE_SILENCE || "true").toLowerCase() === "true",
  };
  const res = await fetch(`${tgBase}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const t = await res.text();
    if (DEBUG_LOG === "true") console.error("TG error:", t);
  }
}

/* =========================
   Whale Alert → Bold & Clean
========================= */
function formatWhaleAlert(tx = {}) {
  const coin =
    (tx.symbol || tx.currency || tx.asset || tx.ticker || "?").toUpperCase();
  const network =
    tx.blockchain || tx.network || (tx.currency && tx.currency.blockchain) || "unknown";

  const ts = Number(tx.timestamp || tx.time || Date.now() / 1000);
  const dtIso = new Date(ts * 1000).toISOString();

  // Valeur USD si fournie, sinon essaie (amount * unit_price_usd)
  let valueUSD = Number(tx.amount_usd || tx.value_usd || tx.usd_value || 0);
  if (!valueUSD) {
    const amt = Number(
      tx.amount ?? tx.quantity ?? tx.volume ?? tx.size ??
      (Array.isArray(tx.amounts) && tx.amounts[0]?.amount) ?? 0
    );
    const unit = Number(tx.unit_price_usd || 0);
    if (amt && unit) valueUSD = unit * amt;
  }

  // Montant coin si dispo
  const amountCoin = Number(
    tx.amount ?? tx.quantity ?? tx.volume ?? tx.size ??
    (Array.isArray(tx.amounts) && tx.amounts[0]?.amount) ?? 0
  );
  const amountLine = amountCoin
    ? `${coin} ${amountCoin.toLocaleString("en-US", { maximumFractionDigits: 6 })}`
    : "?";

  const fromLabel = pickSideLabel(tx.from);
  const toLabel   = pickSideLabel(tx.to);
  const fromEx = normalizeExchange(fromLabel);
  const toEx   = normalizeExchange(toLabel);
  const isInternal = fromEx && toEx && fromEx === toEx;

  const valueLine = valueUSD
    ? `~$${Math.round(valueUSD).toLocaleString("en-US")}`
    : "~$?";

  // ——— Message TELEGRAM “Bold & Clean” (HTML) ———
  const title = `🐋 <b>${escapeHtml(coin)} Whale</b>`;
  const body =
    `💵 <b>Valeur</b> : ${escapeHtml(valueLine)}${isInternal ? " <i>(interne)</i>" : ""}\n` +
    `🔗 <b>Réseau</b> : ${escapeHtml(network)}\n` +
    `🏦 <b>De → À</b> : ${escapeHtml(fromLabel)} → ${escapeHtml(toLabel)}\n` +
    `📊 <b>Montant</b> : ${escapeHtml(amountLine)}\n` +
    `🕒 <b>Date</b> : ${escapeHtml(dtIso)}`;

  return { title, body };
}
// Helper pour formater le digest quotidien joliment
function formatDigestHTML(items = [], dateIso = new Date().toISOString()) {
  const day = dateIso.slice(0, 10);
  const header = `📊 <b>Digest quotidien — ${day}</b>\n`;

  const top = [...items]
    .sort((a,b) => (b.total_usd||0) - (a.total_usd||0))
    .slice(0, 10);

  const lines = top.map((x, i) => {
    const name = x.entity || "Multiple Addresses";
    const total = Math.round(x.total_usd||0).toLocaleString("en-US");
    const txs = x.tx_count || 0;
    const coins = (x.by_coin||[])
      .sort((a,b)=>(b.total_usd||0)-(a.total_usd||0))
      .slice(0,3)
      .map(c => `${c.coin} ${Math.round(c.total_usd||0).toLocaleString("en-US")}`)
      .join(" · ");
    return `${i+1}) <b>${name}</b> — $${total} <i>(${txs} tx)</i>\n   └ ${coins}`;
  });

  if (!lines.length) {
    return `${header}\n<i>Aucune alerte au-dessus des seuils aujourd’hui.</i>`;
  }

  return `${header}\n${lines.join("\n")}`;
}
/* =========================
   Routes
========================= */
app.get("/", (_req, res) => res.send("OK"));
app.get("/ingest", (_req, res) =>
  res.send("Ingest OK – utilisez POST pour envoyer une alerte.")
);

app.post("/ingest", async (req, res) => {
  try {
    if (DEBUG_LOG === "true") {
      console.log("INGEST BODY:", JSON.stringify(req.body).slice(0, 1200));
    }
    if (!verifyHmac(req)) return res.status(401).json({ ok: false, error: "bad signature" });

    const { type = "whale", chat_id, idempotency_key, payload, text } = req.body || {};

    // anti-doublon 5 min
    const key = idempotency_key || crypto.createHash("md5").update(JSON.stringify(req.body)).digest("hex");
    if (seen.has(key)) return res.json({ ok: true, dedup: true });
    seen.add(key);
    setTimeout(() => seen.delete(key), 5 * 60 * 1000);

    // chat autorisé
    const targetChat = String(chat_id || DEFAULT_CHAT_ID || "");
    if (!targetChat) return res.status(400).json({ ok:false, error:"missing chat id" });
    if (allowSet.size && !allowSet.has(targetChat)) {
      return res.status(403).json({ ok:false, error:"chat not allowed" });
    }

    // composition du message
    let msg = "";
    if (type === "whale") {
      const { title, body } = formatWhaleAlert(payload || {});
      msg = `${title}\n${body}`;
    } else if (type === "digest") {
  // Si le message contient déjà du HTML prêt, on l'utilise.
  const { html, items, date } = req.body || {};
  if (html) {
    msg = String(html);
  } else {
    msg = formatDigestHTML(items || [], date || new Date().toISOString());
  }
} else {
      msg = escapeHtml(text || "Nouvelle alerte.");
    }

    // envoi Telegram
    await sendTelegram(targetChat, msg);

    // (optionnel) écho debug
    if ((DEBUG_ECHO || "").toLowerCase() === "true" && type === "whale") {
      const pretty = "<code>" + escapeHtml(JSON.stringify(payload || {}, null, 2)).slice(0, 3800) + "</code>";
      await sendTelegram(targetChat, `🔎 <b>DEBUG_ECHO</b>\n${pretty}`);
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("INGEST error:", err?.message || err);
    return res.status(500).json({ ok:false, error: String(err?.message || err) });
  }
});

/* =========================
   Start
========================= */
app.listen(PORT, () => {
  console.log(`▶ Service up on ${PORT}`);
});

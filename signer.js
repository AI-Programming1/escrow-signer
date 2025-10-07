// signer-server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import bitcoin from "bitcoinjs-lib";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(bodyParser.json());

// Environment variables
const {
  XPRV,
  SIGNER_SECRET,
  NETWORK = "testnet",
  PORT = 4000,
} = process.env;

if (!XPRV || !SIGNER_SECRET) {
  console.error("❌ Missing required environment variables XPRV or SIGNER_SECRET");
  process.exit(1);
}

const network = NETWORK === "mainnet" ? bitcoin.networks.bitcoin : bitcoin.networks.testnet;
const signerNode = bitcoin.bip32.fromBase58(XPRV, network);

// Middleware: verify webhook signature from Cloudflare Worker
function verifySignature(req, res, next) {
  const signature = req.headers["x-signature"];
  const body = JSON.stringify(req.body);
  const hmac = crypto.createHmac("sha256", SIGNER_SECRET).update(body).digest("hex");
  if (signature !== hmac) {
    return res.status(403).json({ error: "Invalid signature" });
  }
  next();
}

// Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// Webhook endpoint: sign and broadcast escrow release
app.post("/webhook", verifySignature, async (req, res) => {
  try {
    const { tradeId, toAddress, amountSats, derivationPath } = req.body;
    if (!tradeId || !toAddress || !amountSats || !derivationPath)
      return res.status(400).json({ error: "Missing required fields" });

    const child = signerNode.derivePath(derivationPath);

    // Normally you’d build + broadcast the transaction here
    const txid = crypto.randomBytes(16).toString("hex"); // placeholder

    console.log(`✅ Signed TX for ${tradeId}: ${txid}`);
    res.json({ ok: true, txid });
  } catch (err) {
    console.error("Signing error:", err);
    res.status(500).json({ error: "Internal signer error" });
  }
});

app.listen(PORT, () => console.log(`🚀 Signer server running on port ${PORT}`));

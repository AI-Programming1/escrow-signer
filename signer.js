// signer.js - DEV example. Use HWI/HSM in production.
import express from 'express';
import bodyParser from 'body-parser';
import bitcoin from 'bitcoinjs-lib';
import bip32 from 'bip32';
import dotenv from 'dotenv';
import crypto from 'crypto';


dotenv.config();
const app = express();
app.use(bodyParser.json());


const NETWORK = process.env.NETWORK === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet;
const XPRV = process.env.XPRV; // DEV ONLY
const SIGNER_HMAC_SECRET = process.env.SIGNER_HMAC_SECRET;


if (!SIGNER_HMAC_SECRET) { console.error('Missing SIGNER_HMAC_SECRET'); process.exit(1); }
if (!XPRV) { console.error('Missing XPRV (for dev)'); process.exit(1); }


function computeHmacHex(secret, message) { return crypto.createHmac('sha256', secret).update(message).digest('hex'); }


app.post('/sign', async (req, res) => {
try {
const sig = req.get('X-Signature');
const { tradeId, psbt: psbtBase64, escrow_idx } = req.body;
if (!sig || !tradeId || !psbtBase64) return res.status(400).send('missing');


const expected = computeHmacHex(SIGNER_HMAC_SECRET, `${tradeId}:${psbtBase64}`);
if (expected !== sig) return res.status(401).send('invalid signature');


const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: NETWORK });


const root = bip32.fromBase58(XPRV, NETWORK);
const child = root.derive(0).derive(Number(escrow_idx));
if (!child.privateKey) return res.status(500).send('no privkey');


const keyPair = bitcoin.ECPair.fromPrivateKey(child.privateKey, { network: NETWORK });
for (let i = 0; i < psbt.inputCount; i++) {
try { psbt.signInput(i, keyPair); } catch (e) { console.warn('sign input error', e.message); }
}


try { psbt.finalizeAllInputs(); } catch (e) { return res.status(400).send('finalize failed: ' + e.message); }


const txhex = psbt.extractTransaction().toHex();
return res.json({ txhex });
} catch (err) {
console.err
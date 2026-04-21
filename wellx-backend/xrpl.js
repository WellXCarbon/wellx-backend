const xrpl = require("xrpl");
const { setKv, getKv } = require("./db");

const XRPL_CLIENT_URL = process.env.XRPL_CLIENT_URL || "wss://s.altnet.rippletest.net:51233";
const XRPL_EXPLORER_BASE = process.env.XRPL_EXPLORER_BASE || "https://testnet.xrpl.org/transactions/";
const XRPL_WALLET_SEED = process.env.XRPL_WALLET_SEED || "";
const XRPL_WALLET_ADDRESS = process.env.XRPL_WALLET_ADDRESS || "";
const AUTO_FUND_TESTNET = (process.env.AUTO_FUND_TESTNET || "true").toLowerCase() === "true";

async function getClient() {
  const client = new xrpl.Client(XRPL_CLIENT_URL);
  await client.connect();
  return client;
}

async function loadOrCreateWallet() {
  if (XRPL_WALLET_SEED) {
    return { wallet: xrpl.Wallet.fromSeed(XRPL_WALLET_SEED), source: "env" };
  }

  const storedSeed = await getKv("xrpl_wallet_seed");
  if (storedSeed) {
    return { wallet: xrpl.Wallet.fromSeed(storedSeed), source: "db" };
  }

  if (!AUTO_FUND_TESTNET) {
    throw new Error("No XRPL wallet configured. Set XRPL_WALLET_SEED or enable AUTO_FUND_TESTNET.");
  }

  const client = await getClient();
  try {
    const funded = await client.fundWallet();
    await setKv("xrpl_wallet_seed", funded.wallet.seed);
    await setKv("xrpl_wallet_address", funded.wallet.classicAddress);
    return { wallet: funded.wallet, source: "faucet" };
  } finally {
    await client.disconnect();
  }
}

async function getWalletStatus() {
  const client = await getClient();
  try {
    const { wallet, source } = await loadOrCreateWallet();
    const accountInfo = await client.request({
      command: "account_info",
      account: wallet.classicAddress,
      ledger_index: "validated"
    });
    return {
      address: wallet.classicAddress,
      source,
      funded: true,
      balance_drops: accountInfo.result.account_data.Balance,
      sequence: accountInfo.result.account_data.Sequence
    };
  } catch (err) {
    return {
      address: XRPL_WALLET_ADDRESS || null,
      source: XRPL_WALLET_SEED ? "env" : "unknown",
      funded: false,
      error: err.message
    };
  } finally {
    await client.disconnect();
  }
}

async function anchorToXRPL(payloadObject) {
  console.log("XRPL anchor version check", new Date().toISOString(), payloadObject);
  const client = await getClient();

  try {
    const { wallet } = await loadOrCreateWallet();

    const uniquePayload = {
      ...payloadObject,
      nonce: `${Date.now()}-${Math.floor(Math.random() * 1000000)}`,
      anchored_at_utc: new Date().toISOString(),
    };

    const memoString = JSON.stringify(uniquePayload);

    const prepared = await client.autofill({
      TransactionType: "Payment",
      Account: wallet.classicAddress,
      Destination: wallet.classicAddress,
      Amount: "1",
      SourceTag: Math.floor(Math.random() * 4294967295),
      Memos: [
        {
          Memo: {
            MemoType: Buffer.from("wellx-proof", "utf8").toString("hex"),
            MemoFormat: Buffer.from("application/json", "utf8").toString("hex"),
            MemoData: Buffer.from(memoString, "utf8").toString("hex"),
          },
        },
      ],
    });

    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    return {
      txHash: result.result.hash,
      explorerUrl: `${XRPL_EXPLORER_BASE}${result.result.hash}`,
      walletAddress: wallet.classicAddress,
      memo_payload: uniquePayload,
    };
  } finally {
    await client.disconnect();
  }
}

module.exports = { anchorToXRPL, getWalletStatus, loadOrCreateWallet };

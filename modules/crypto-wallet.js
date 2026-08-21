/**
 * NVME Native Crypto Wallet
 * Ethereum HD wallet - per-user deposit addresses via BIP-44
 * Alchemy API for balance + transaction monitoring
 */
const { ethers } = require('ethers');
const axios = require('axios');

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
if (!ALCHEMY_API_KEY) {
  throw new Error(
    'crypto-wallet: ALCHEMY_API_KEY env var is required (no hardcoded fallback — get a key from alchemy.com)'
  );
}
const ALCHEMY_URL = `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;

const EMPIRE_WALLET = process.env.EMPIRE_ETH_WALLET;
if (!EMPIRE_WALLET) {
  throw new Error(
    'crypto-wallet: EMPIRE_ETH_WALLET env var is required (no hardcoded fallback)'
  );
}

// Derive deterministic wallet for a user using their user index
// Requires NVME_WALLET_SEED (or JWT_SECRET) from env — never a
// hardcoded seed, which would let anyone derive every user wallet.
function getUserWalletAddress(userIndex) {
  try {
    const seed = process.env.NVME_WALLET_SEED || process.env.JWT_SECRET;
    if (!seed) {
      throw new Error('NVME_WALLET_SEED (or JWT_SECRET) env var is required');
    }
    const seedHash = ethers.id(seed + '-nvme-hd-wallet-v1');
    const hdNode = ethers.HDNodeWallet.fromSeed(ethers.getBytes(seedHash));
    const child = hdNode.derivePath(`m/44'/60'/0'/0/${userIndex}`);
    return child.address;
  } catch(e) {
    console.error('Wallet derive error:', e.message);
    return null;
  }
}

// Get ETH balance for an address via Alchemy
async function getEthBalance(address) {
  try {
    const resp = await axios.post(ALCHEMY_URL, {
      jsonrpc: '2.0', id: 1, method: 'eth_getBalance',
      params: [address, 'latest']
    }, { timeout: 8000 });
    const balWei = BigInt(resp.data.result || '0x0');
    const balEth = Number(balWei) / 1e18;
    return { wei: balWei.toString(), eth: balEth.toFixed(6) };
  } catch(e) {
    return { wei: '0', eth: '0.000000', error: e.message };
  }
}

// Get recent transactions for an address via Alchemy
async function getRecentTxs(address, limit = 10) {
  try {
    const resp = await axios.post(ALCHEMY_URL, {
      jsonrpc: '2.0', id: 2,
      method: 'alchemy_getAssetTransfers',
      params: [{
        toAddress: address,
        category: ['external', 'erc20'],
        maxCount: `0x${limit.toString(16)}`,
        order: 'desc'
      }]
    }, { timeout: 8000 });
    return resp.data.result?.transfers || [];
  } catch(e) {
    return [];
  }
}

// Get ETH price in USD via CoinGecko (free)
async function getEthPrice() {
  try {
    const resp = await axios.get(
      'https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd',
      { timeout: 5000 }
    );
    return resp.data?.ethereum?.usd || 0;
  } catch(e) {
    return 0;
  }
}

// Convert ETH amount to NVME coins (1 USD = 100 coins)
async function ethToCoins(ethAmount) {
  const price = await getEthPrice();
  const usd = ethAmount * price;
  return Math.floor(usd * 100); // 100 coins per USD
}

module.exports = {
  getUserWalletAddress,
  getEthBalance,
  getRecentTxs,
  getEthPrice,
  ethToCoins,
  EMPIRE_WALLET
};

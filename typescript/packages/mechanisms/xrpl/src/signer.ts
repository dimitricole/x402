import { authorizeChannel, type SubmittableTransaction, type Wallet } from "xrpl";
import type { ClientXrplSigner, UptoClientXrplSigner } from "./types";

/**
 * Creates a client signer adapter from an xrpl.js Wallet.
 *
 * @param wallet - XRPL wallet
 * @returns x402 XRPL client signer
 */
export function createXrplWalletSigner(wallet: Wallet): ClientXrplSigner {
  return {
    classicAddress: wallet.classicAddress,
    sign: (transaction: SubmittableTransaction) => {
      const signed = wallet.sign(transaction);
      return {
        signedTxBlob: signed.tx_blob,
        hash: signed.hash,
      };
    },
  };
}

/**
 * Creates an upto client signer adapter from an xrpl.js Wallet.
 *
 * @param wallet - XRPL wallet
 * @returns x402 XRPL upto client signer
 */
export function createUptoXrplWalletSigner(wallet: Wallet): UptoClientXrplSigner {
  return {
    ...createXrplWalletSigner(wallet),
    publicKey: wallet.publicKey,
    signClaim: (channelId: string, amountDrops: string) =>
      authorizeChannel(wallet, channelId, amountDrops),
  };
}

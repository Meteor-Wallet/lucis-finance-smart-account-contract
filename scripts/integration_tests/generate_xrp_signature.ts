import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import AppXrp from "@ledgerhq/hw-app-xrp";
import { encodeForSigning } from "ripple-binary-codec";
import inquirer from "inquirer";

async function connectLedger(): Promise<AppXrp> {
  const transport = await TransportNodeHid.create();
  return new AppXrp(transport);
}

interface TxJSON {
  TransactionType: string;
  Account: string;
  Memos?: Array<{ Memo: { MemoData: string } }>;
}

async function buildTransaction(account: string, message: string): Promise<TxJSON> {
  // Wrap message in Memo, using hex format
  const memoHex = Buffer.from(message, "utf8").toString("hex");
  return {
    TransactionType: "AccountSet",
    Account: account,
    Memos: [{ Memo: { MemoData: memoHex } }],
  };
}

async function signTransaction(
  xrpApp: AppXrp,
  path: string,
  txJSON: TxJSON
): Promise<{ signature: string }> {
  // Serialize transaction
  const rawTxHex = encodeForSigning(txJSON);
  // Prompt device to sign
  const result = await xrpApp.signTransaction(path, rawTxHex);
  return { signature: result.signature };  
}

async function main() {
  console.log("▶ Connecting to Ledger device...");
  const xrpApp = await connectLedger();
  console.log("✔ Ledger connected.");

  // Gather user input
  const answers = await inquirer.prompt([
    {
      name: "bipPath",
      type: "input",
      message: "Enter BIP32 path for XRP account (e.g. 44'/144'/0'/0/0):",
      default: "44'/144'/0'/0/0",
    },
    {
      name: "account",
      type: "input",
      message: "Enter your XRP Account address:",
    },
    {
      name: "message",
      type: "input",
      message: "Enter the message you want to sign:",
    },
  ]);

  const txJSON = await buildTransaction(answers.account, answers.message);
  console.log("▶ Preparing transaction for signing...");
  console.log(JSON.stringify(txJSON, null, 2));

  console.log("▶ Please confirm and sign on your Ledger device...");
  const { signature } = await signTransaction(
    xrpApp,
    answers.bipPath,
    txJSON
  );

  console.log("✔ Signature received:", signature);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
import { test, expect } from '@playwright/test';
import globalSetup from '../global-setup.js';
import { upsertEnvVar } from '../env-editor.js';
import * as nearAPI from 'near-api-js';
import bitcoin from 'bitcoinjs-lib';
import bitcoinMessage from 'bitcoinjs-message';
import bs58 from 'bs58';
import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

const ECPair = ECPairFactory(ecc);
const ZCASH_MESSAGE_PREFIX = '\x18Zcash Signed Message:\n';
const ZCASH_TRANSPARENT_P2PKH_PREFIX = Buffer.from([0x1c, 0xb8]);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function hash160(bytes) {
    const sha = createHash('sha256').update(bytes).digest();
    return createHash('ripemd160').update(sha).digest();
}

function doubleSha256(bytes) {
    return createHash('sha256')
        .update(createHash('sha256').update(bytes).digest())
        .digest();
}

function zcashTransparentP2pkhAddress(publicKey) {
    const payload = Buffer.concat([
        ZCASH_TRANSPARENT_P2PKH_PREFIX,
        hash160(Buffer.from(publicKey)),
    ]);
    const checksum = doubleSha256(payload).subarray(0, 4);
    return bs58.encode(Buffer.concat([payload, checksum]));
}

async function createV2FactoryAccount(factoryOwner) {
    const randomSuffix = `zec-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const factoryContractId = `${randomSuffix}.${factoryOwner.accountId}`;

    const accountWasm = fs.readFileSync(
        path.join(
            __dirname,
            '../../target/near/dew_abstract_account_v2/dew_abstract_account_v2.wasm'
        )
    );

    const latestCodeHash = createHash('sha256')
        .update(accountWasm)
        .digest()
        .toString('base64');

    try {
        await factoryOwner.deployGlobalContract(accountWasm, 'codeHash');
    } catch (e) {
        console.log(e);
    }

    const factoryWasm = fs.readFileSync(
        path.join(
            __dirname,
            '../../target/near/dew_abstract_account_factory_v2/dew_abstract_account_factory_v2.wasm'
        )
    );

    await factoryOwner.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: factoryContractId,
        actions: [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(
                nearAPI.utils.format.parseNearAmount('10')
            ),
            nearAPI.transactions.deployContract(factoryWasm),
            nearAPI.transactions.functionCall(
                'new',
                {
                    owner_id: factoryOwner.accountId,
                    latest_code_hash: latestCodeHash,
                },
                150n * 10n ** 12n,
                0n
            ),
        ],
    });

    return factoryContractId;
}

test('onboard new zec user', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const factoryContractId = await createV2FactoryAccount(factoryOwner);
    upsertEnvVar('ZEC_FACTORY_ACCOUNT_ID', factoryContractId);

    const blockchainId = 'zec';
    const aliceKeypair = ECPair.makeRandom({
        network: bitcoin.networks.bitcoin,
    });
    const aliceBlockchainAddress = zcashTransparentP2pkhAddress(
        aliceKeypair.publicKey
    );

    expect(aliceBlockchainAddress.startsWith('t1')).toBe(true);

    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const aliceAccountExists = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExists).toBe(false);

    const aliceMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const sigBytes = bitcoinMessage.sign(
        aliceMessageForCreateAccount,
        aliceKeypair.privateKey,
        aliceKeypair.compressed,
        ZCASH_MESSAGE_PREFIX
    );
    const aliceCreateAccountSignature = sigBytes.toString('base64');
    const deadline = BigInt(JSON.parse(aliceMessageForCreateAccount).deadline);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'create_account',
        args: {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
            signature: aliceCreateAccountSignature,
            deadline: deadline.toString(),
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n,
    });

    const aliceAccountExistsAfter = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExistsAfter).toBe(true);

    upsertEnvVar('ZEC_KEY', aliceKeypair.toWIF());
});

test('sign transaction with zec access key', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const factoryContractId = process.env.ZEC_FACTORY_ACCOUNT_ID;
    const blockchainId = 'zec';
    const aliceKeypair = ECPair.fromWIF(
        process.env.ZEC_KEY,
        bitcoin.networks.bitcoin
    );
    const aliceBlockchainAddress = zcashTransparentP2pkhAddress(
        aliceKeypair.publicKey
    );

    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const aliceAccountExists = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExists).toBe(true);

    const transaction = {
        receiverId: factoryOwner.accountId,
        actions: [
            {
                type: 'Transfer',
                params: {
                    deposit: '1',
                },
            },
        ],
    };

    const aliceMessageForSignTransaction =
        await nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'blind_message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: aliceBlockchainAddress,
                transaction,
            }
        );

    const sigBytes = bitcoinMessage.sign(
        aliceMessageForSignTransaction,
        aliceKeypair.privateKey,
        aliceKeypair.compressed,
        ZCASH_MESSAGE_PREFIX
    );
    const aliceSignTransactionSignature = sigBytes.toString('base64');

    await gasSponsor.signAndSendTransaction({
        receiverId: aliceAccountId,
        actions: [
            nearAPI.transactions.transfer(10n ** 23n),
            nearAPI.transactions.functionCall(
                'sign_transaction',
                {
                    blockchain_id: blockchainId,
                    blockchain_address: aliceBlockchainAddress,
                    transaction,
                    signature: aliceSignTransactionSignature,
                    blind_message: true,
                },
                200n * 10n ** 12n,
                0n
            ),
        ],
        waitUntil: 'FINAL',
    });
});

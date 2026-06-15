import { test, expect } from '@playwright/test';
import globalSetup from '../global-setup.js';
import bs58 from 'bs58';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';
import * as nearAPI from 'near-api-js';
import * as ecc from 'tiny-secp256k1';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ZCASH_MAINNET_TRANSPARENT_P2PKH_PREFIX = Buffer.from([0x1c, 0xb8]);
const NOIR_MESSAGE_PREFIX = Buffer.from('Zcash Signed Message:\n', 'utf8');

async function createV2FactoryAccount(factoryOwner) {
    const randomSuffix = `noir-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
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

function encodeCompactSize(size) {
    if (size < 253) {
        return Buffer.from([size]);
    }
    if (size <= 0xffff) {
        const encoded = Buffer.alloc(3);
        encoded[0] = 253;
        encoded.writeUInt16LE(size, 1);
        return encoded;
    }
    if (size <= 0xffffffff) {
        const encoded = Buffer.alloc(5);
        encoded[0] = 254;
        encoded.writeUInt32LE(size, 1);
        return encoded;
    }

    throw new Error('Message too long');
}

function doubleSha256(bytes) {
    const firstHash = createHash('sha256').update(bytes).digest();
    return createHash('sha256').update(firstHash).digest();
}

function hash160(bytes) {
    const sha = createHash('sha256').update(bytes).digest();
    return createHash('ripemd160').update(sha).digest();
}

function createNoirWallet() {
    let privateKey;

    do {
        privateKey = randomBytes(32);
    } while (!ecc.isPrivate(privateKey));

    const publicKey = Buffer.from(ecc.pointFromScalar(privateKey, true));
    const payload = Buffer.concat([
        ZCASH_MAINNET_TRANSPARENT_P2PKH_PREFIX,
        hash160(publicKey),
    ]);
    const checksum = doubleSha256(payload).subarray(0, 4);
    const address = bs58.encode(Buffer.concat([payload, checksum]));

    return { privateKey, publicKey, address };
}

function noirMessageHash(message) {
    const messageBytes = Buffer.from(message, 'utf8');
    return doubleSha256(
        Buffer.concat([
            encodeCompactSize(NOIR_MESSAGE_PREFIX.length),
            NOIR_MESSAGE_PREFIX,
            encodeCompactSize(messageBytes.length),
            messageBytes,
        ])
    );
}

function signNoirMessage(message, privateKey) {
    const { signature, recoveryId } = ecc.signRecoverable(
        noirMessageHash(message),
        privateKey
    );
    const compressedHeader = 31 + recoveryId;

    return Buffer.concat([
        Buffer.from([compressedHeader]),
        Buffer.from(signature),
    ]).toString('hex');
}

test('creates and uses a Noir Wallet abstract account', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const factoryContractId = await createV2FactoryAccount(factoryOwner);
    const blockchainId = 'noirzec';
    const aliceWallet = createNoirWallet();
    const aliceBlockchainAddress = aliceWallet.address;

    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    await expect(
        nearJsonRpcProvider.viewAccount(aliceAccountId)
    ).rejects.toThrow();

    const aliceMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const aliceCreateAccountSignature = signNoirMessage(
        aliceMessageForCreateAccount,
        aliceWallet.privateKey
    );
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

    await expect(
        nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'contract_source_metadata',
            {}
        )
    ).resolves.toMatchObject({ version: '2.0.0' });

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
            'message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: aliceBlockchainAddress,
                transaction,
            }
        );

    const aliceSignTransactionSignature = signNoirMessage(
        aliceMessageForSignTransaction,
        aliceWallet.privateKey
    );

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
                },
                200n * 10n ** 12n,
                0n
            ),
        ],
        waitUntil: 'FINAL',
    });
});

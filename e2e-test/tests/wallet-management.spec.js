import { test, expect } from '@playwright/test';
import globalSetup from '../global-setup.js';
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';
import * as nearAPI from 'near-api-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function createV2FactoryAccount(factoryOwner) {
    const randomSuffix = `wallet-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const factoryContractId = `${randomSuffix}.${factoryOwner.accountId}`;
    const factoryKeyPair = nearAPI.KeyPair.fromRandom('ed25519');
    const factorySigner = new nearAPI.KeyPairSigner(factoryKeyPair);
    const factoryAccount = new nearAPI.Account(
        factoryContractId,
        factoryOwner.provider,
        factorySigner
    );

    const wasmV2 = fs.readFileSync(
        path.join(
            __dirname,
            '../../target/near/dew_abstract_account_v2/dew_abstract_account_v2.wasm'
        )
    );

    const latestCodeHash = createHash('sha256')
        .update(wasmV2)
        .digest()
        .toString('base64');

    try {
        await factoryOwner.deployGlobalContract(wasmV2, 'codeHash');
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
            nearAPI.transactions.addKey(
                factoryKeyPair.getPublicKey(),
                nearAPI.transactions.fullAccessKey()
            ),
        ],
    });

    await factoryAccount.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: factoryContractId,
        actions: [
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

async function createEthereumSmartAccount({
    factoryContractId,
    gasSponsor,
    nearJsonRpcProvider,
    wallet,
}) {
    const blockchainId = 'ethereum';
    const blockchainAddress = wallet.address;
    const accountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
        }
    );

    const message = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
        }
    );

    const signature = await wallet.signMessage(message);
    const deadline = BigInt(JSON.parse(message).deadline);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'create_account',
        args: {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
            signature,
            deadline: deadline.toString(),
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n,
    });

    return accountId;
}

test('ethereum wallet can add and remove another wallet from a v2 smart account', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const factoryContractId = await createV2FactoryAccount(factoryOwner);

    const aliceWallet = ethers.Wallet.createRandom();
    const bobWallet = ethers.Wallet.createRandom();
    const blockchainId = 'ethereum';

    const aliceAccountId = await createEthereumSmartAccount({
        factoryContractId,
        gasSponsor,
        nearJsonRpcProvider,
        wallet: aliceWallet,
    });

    await expect(
        nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: bobWallet.address,
                transaction: {
                    receiverId: factoryOwner.accountId,
                    actions: [
                        {
                            type: 'Transfer',
                            params: {
                                deposit: '1',
                            },
                        },
                    ],
                },
            }
        )
    ).rejects.toThrow(/E008: unauthorized cross-chain access key/);

    const addWalletMessage = await nearJsonRpcProvider.callFunction(
        aliceAccountId,
        'message_for_add_wallet',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceWallet.address,
            new_wallet_blockchain_id: blockchainId,
            new_wallet_blockchain_address: bobWallet.address,
        }
    );

    const addWalletSignature = await aliceWallet.signMessage(addWalletMessage);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: aliceAccountId,
        methodName: 'add_wallet',
        args: {
            blockchain_id: blockchainId,
            blockchain_address: aliceWallet.address,
            new_wallet_blockchain_id: blockchainId,
            new_wallet_blockchain_address: bobWallet.address,
            signature: addWalletSignature,
        },
        gas: 100n * 10n ** 12n,
        deposit: 0n,
    });

    const walletsAfterAdd = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'list_wallets_for_account_id',
        {
            account_id: aliceAccountId,
        }
    );
    expect(walletsAfterAdd).toContainEqual([
        blockchainId,
        aliceWallet.address.toLowerCase(),
    ]);
    expect(walletsAfterAdd).toContainEqual([
        blockchainId,
        bobWallet.address.toLowerCase(),
    ]);

    const accountIdsForBob = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'list_account_ids_for_wallet',
        {
            blockchain_id: blockchainId,
            blockchain_address: bobWallet.address,
        }
    );
    expect(accountIdsForBob).toContain(aliceAccountId);

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

    const bobMessageForSignTransaction =
        await nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: bobWallet.address,
                transaction,
            }
        );

    const bobSignTransactionSignature = await bobWallet.signMessage(
        bobMessageForSignTransaction
    );

    await gasSponsor.signAndSendTransaction({
        receiverId: aliceAccountId,
        actions: [
            nearAPI.transactions.transfer(10n ** 23n),
            nearAPI.transactions.functionCall(
                'sign_transaction',
                {
                    blockchain_id: blockchainId,
                    blockchain_address: bobWallet.address,
                    transaction,
                    signature: bobSignTransactionSignature,
                },
                200n * 10n ** 12n,
                0n
            ),
        ],
        waitUntil: 'FINAL',
    });

    const removeWalletMessage = await nearJsonRpcProvider.callFunction(
        aliceAccountId,
        'message_for_remove_wallet',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceWallet.address,
            wallet_blockchain_id_to_be_removed: blockchainId,
            wallet_blockchain_address_to_be_removed: bobWallet.address,
        }
    );

    const removeWalletSignature =
        await aliceWallet.signMessage(removeWalletMessage);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: aliceAccountId,
        methodName: 'remove_wallet',
        args: {
            blockchain_id: blockchainId,
            blockchain_address: aliceWallet.address,
            wallet_blockchain_id_to_be_removed: blockchainId,
            wallet_blockchain_address_to_be_removed: bobWallet.address,
            signature: removeWalletSignature,
        },
        gas: 100n * 10n ** 12n,
        deposit: 0n,
    });

    const walletsAfterRemove = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'list_wallets_for_account_id',
        {
            account_id: aliceAccountId,
        }
    );
    expect(walletsAfterRemove).toContainEqual([
        blockchainId,
        aliceWallet.address.toLowerCase(),
    ]);
    expect(walletsAfterRemove).not.toContainEqual([
        blockchainId,
        bobWallet.address.toLowerCase(),
    ]);

    const accountIdsForBobAfterRemove = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'list_account_ids_for_wallet',
        {
            blockchain_id: blockchainId,
            blockchain_address: bobWallet.address,
        }
    );
    expect(accountIdsForBobAfterRemove).not.toContain(aliceAccountId);

    await expect(
        nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: bobWallet.address,
                transaction,
            }
        )
    ).rejects.toThrow(/E008: unauthorized cross-chain access key/);
});

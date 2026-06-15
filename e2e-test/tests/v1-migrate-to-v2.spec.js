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

function readWasm(relativePath) {
    return fs.readFileSync(path.join(__dirname, relativePath));
}

function codeHashBase64(wasm) {
    return createHash('sha256').update(wasm).digest().toString('base64');
}

async function deployGlobalContract(account, wasm) {
    try {
        await account.deployGlobalContract(wasm, 'codeHash');
    } catch (e) {
        console.log(e);
    }
}

async function createSmartAccount({
    factoryContractId,
    gasSponsor,
    nearJsonRpcProvider,
    wallet,
    blockchainId = 'ethereum',
    extraArgs = {},
}) {
    const blockchainAddress = wallet.address;
    const previewAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
            brand: extraArgs.brand ?? null,
            account_id: extraArgs.account_id ?? null,
        }
    );

    const message = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
            brand: extraArgs.brand ?? null,
            account_id: extraArgs.account_id ?? null,
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
            ...extraArgs,
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n,
    });

    return extraArgs.account_id
        ? `${extraArgs.account_id}.${factoryContractId}`
        : previewAccountId;
}

test('v1 migrate to v2', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const v1AccountWasm = readWasm(
        '../../target/near/dew_abstract_account_v1/dew_abstract_account_v1.wasm'
    );
    const v1FactoryWasm = readWasm(
        '../../target/near/dew_abstract_account_factory/dew_abstract_account_factory.wasm'
    );
    const v2AccountWasm = readWasm(
        '../../target/near/dew_abstract_account_v2/dew_abstract_account_v2.wasm'
    );
    const v2FactoryWasm = readWasm(
        '../../target/near/dew_abstract_account_factory_v2/dew_abstract_account_factory_v2.wasm'
    );

    const v1AccountCodeHash = codeHashBase64(v1AccountWasm);
    const v2AccountCodeHash = codeHashBase64(v2AccountWasm);

    await deployGlobalContract(factoryOwner, v1AccountWasm);

    const randomSuffix = `migrate-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const factoryContractId = `${randomSuffix}.${factoryOwner.accountId}`;
    const factoryKeyPair = nearAPI.KeyPair.fromString(process.env.NEAR_MASTER_KEY);
    const factoryAccount = new nearAPI.Account(
        factoryContractId,
        nearJsonRpcProvider,
        new nearAPI.KeyPairSigner(factoryKeyPair)
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
            nearAPI.transactions.deployContract(v1FactoryWasm),
            nearAPI.transactions.functionCall(
                'new',
                {
                    owner_id: factoryOwner.accountId,
                    latest_code_hash: v1AccountCodeHash,
                },
                150n * 10n ** 12n,
                0n
            ),
        ],
    });

    const aliceWallet = ethers.Wallet.createRandom();
    const aliceAccountId = await createSmartAccount({
        factoryContractId,
        gasSponsor,
        nearJsonRpcProvider,
        wallet: aliceWallet,
    });

    const aliceVersionBeforeFactoryMigration = await nearJsonRpcProvider
        .callFunction(aliceAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);
    expect(aliceVersionBeforeFactoryMigration).toBe('1.0.0');

    const factoryLatestHashBeforeMigration =
        await nearJsonRpcProvider.callFunction(
            factoryContractId,
            'get_latest_code_hash',
            {}
        );
    expect(Buffer.from(factoryLatestHashBeforeMigration).toString('base64')).toBe(
        v1AccountCodeHash
    );

    /*
     * ====================================================================================================
     * ====================================================================================================
     * Everything above this divider represents the current mainnet-shaped state:
     * a v1 factory is already deployed, and that v1 factory creates smart accounts from the v1 global
     * account contract hash.
     * ====================================================================================================
     * ====================================================================================================
     */

    await factoryAccount.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: factoryContractId,
        actions: [
            nearAPI.transactions.deployContract(v2FactoryWasm),
            nearAPI.transactions.functionCall('migrate', {}, 150n * 10n ** 12n, 0n),
        ],
    });

    const factoryLatestHashAfterFactoryMigration =
        await nearJsonRpcProvider.callFunction(
            factoryContractId,
            'get_latest_code_hash',
            {}
        );
    expect(
        Buffer.from(factoryLatestHashAfterFactoryMigration).toString('base64')
    ).toBe(v1AccountCodeHash);

    await deployGlobalContract(factoryOwner, v2AccountWasm);

    await factoryOwner.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'update_latest_code_hash',
        args: {
            new_code_hash: v2AccountCodeHash,
        },
        gas: 100n * 10n ** 12n,
        deposit: 0n,
    });

    const factoryLatestHashAfterCodeHashUpdate =
        await nearJsonRpcProvider.callFunction(
            factoryContractId,
            'get_latest_code_hash',
            {}
        );
    expect(
        Buffer.from(factoryLatestHashAfterCodeHashUpdate).toString('base64')
    ).toBe(v2AccountCodeHash);

    const upgradeTarget = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'get_code_hash_upgrade_target',
        {
            code_hash: Array.from(Buffer.from(v1AccountCodeHash, 'base64')),
        }
    );
    expect(Buffer.from(upgradeTarget).toString('base64')).toBe(
        v2AccountCodeHash
    );

    const aliceMessageForUpgrade = await nearJsonRpcProvider.callFunction(
        aliceAccountId,
        'message_for_upgrade',
        {
            blockchain_id: 'ethereum',
            blockchain_address: aliceWallet.address,
        }
    );
    const aliceUpgradeSignature =
        await aliceWallet.signMessage(aliceMessageForUpgrade);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: aliceAccountId,
        methodName: 'upgrade',
        args: {
            blockchain_id: 'ethereum',
            blockchain_address: aliceWallet.address,
            signature: aliceUpgradeSignature,
        },
        gas: 300n * 10n ** 12n,
        deposit: 0n,
    });

    const aliceVersionAfterAccountUpgrade = await nearJsonRpcProvider
        .callFunction(aliceAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);
    expect(aliceVersionAfterAccountUpgrade).toBe('2.0.0');

    const bobWallet = ethers.Wallet.createRandom();
    const bobAccountId = await createSmartAccount({
        factoryContractId,
        gasSponsor,
        nearJsonRpcProvider,
        wallet: bobWallet,
        extraArgs: {
            account_id: `bob${Date.now().toString(36)}`,
        },
    });

    const bobVersion = await nearJsonRpcProvider
        .callFunction(bobAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);
    expect(bobVersion).toBe('2.0.0');

    const bobWallets = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'list_wallets_for_account_id',
        {
            account_id: bobAccountId,
        }
    );
    expect(bobWallets).toEqual([['ethereum', bobWallet.address]]);

    const bobAccountIds = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'list_account_ids_for_wallet',
        {
            blockchain_id: 'ethereum',
            blockchain_address: bobWallet.address,
        }
    );
    expect(bobAccountIds).toContain(bobAccountId);
});

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
    const randomSuffix = `discovery-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
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

async function createEthereumSmartAccount({
    factoryContractId,
    gasSponsor,
    nearJsonRpcProvider,
    wallet,
    extraArgs = {},
}) {
    const blockchainId = 'ethereum';
    const blockchainAddress = wallet.address;

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
}

test('factory creates named and branded accounts and exposes wallet/account lookups', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const factoryContractId = await createV2FactoryAccount(factoryOwner);
    const brand = `brand${Date.now().toString(36)}`;

    await expect(
        nearJsonRpcProvider.callFunction(
            factoryContractId,
            'list_wallets_for_account_id',
            {
                account_id: `missing.${factoryContractId}`,
            }
        )
    ).resolves.toEqual([]);

    await expect(
        nearJsonRpcProvider.callFunction(
            factoryContractId,
            'list_account_ids_for_wallet',
            {
                blockchain_id: 'ethereum',
                blockchain_address: ethers.Wallet.createRandom().address,
            }
        )
    ).resolves.toEqual([]);

    await factoryOwner.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'add_brand',
        args: {
            brand,
        },
        gas: 50n * 10n ** 12n,
        deposit: 0n,
    });

    const namedWallet = ethers.Wallet.createRandom();
    const namedAccountSegment = `named${Date.now().toString(36)}`;
    const namedAccountId = `${namedAccountSegment}.${factoryContractId}`;

    await createEthereumSmartAccount({
        factoryContractId,
        gasSponsor,
        nearJsonRpcProvider,
        wallet: namedWallet,
        extraArgs: {
            account_id: namedAccountSegment,
        },
    });

    const firstBrandedWallet = ethers.Wallet.createRandom();
    const firstBrandedAccountId = `${brand}-1.${factoryContractId}`;

    await createEthereumSmartAccount({
        factoryContractId,
        gasSponsor,
        nearJsonRpcProvider,
        wallet: firstBrandedWallet,
        extraArgs: {
            brand,
        },
    });

    const secondBrandedWallet = ethers.Wallet.createRandom();
    const secondBrandedAccountId = `${brand}-2.${factoryContractId}`;

    await createEthereumSmartAccount({
        factoryContractId,
        gasSponsor,
        nearJsonRpcProvider,
        wallet: secondBrandedWallet,
        extraArgs: {
            brand,
        },
    });

    await expect(
        nearJsonRpcProvider.callFunction(namedAccountId, 'contract_source_metadata', {})
    ).resolves.toMatchObject({ version: '2.0.0' });
    await expect(
        nearJsonRpcProvider.callFunction(
            firstBrandedAccountId,
            'contract_source_metadata',
            {}
        )
    ).resolves.toMatchObject({ version: '2.0.0' });
    await expect(
        nearJsonRpcProvider.callFunction(
            secondBrandedAccountId,
            'contract_source_metadata',
            {}
        )
    ).resolves.toMatchObject({ version: '2.0.0' });

    await expect(
        nearJsonRpcProvider.callFunction(
            factoryContractId,
            'list_wallets_for_account_id',
            {
                account_id: namedAccountId,
            }
        )
    ).resolves.toEqual([['ethereum', namedWallet.address]]);

    await expect(
        nearJsonRpcProvider.callFunction(
            factoryContractId,
            'list_wallets_for_account_id',
            {
                account_id: firstBrandedAccountId,
            }
        )
    ).resolves.toEqual([['ethereum', firstBrandedWallet.address]]);

    await expect(
        nearJsonRpcProvider.callFunction(
            factoryContractId,
            'list_account_ids_for_wallet',
            {
                blockchain_id: 'ethereum',
                blockchain_address: namedWallet.address,
            }
        )
    ).resolves.toContain(namedAccountId);

    await expect(
        nearJsonRpcProvider.callFunction(
            factoryContractId,
            'list_account_ids_for_wallet',
            {
                blockchain_id: 'ethereum',
                blockchain_address: secondBrandedWallet.address,
            }
        )
    ).resolves.toContain(secondBrandedAccountId);
});

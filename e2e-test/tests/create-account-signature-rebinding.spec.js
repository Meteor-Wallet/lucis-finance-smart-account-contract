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
    const randomSuffix = `rebind-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
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

test('create_account rejects account_id not bound to the signed create message', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const factoryContractId = await createV2FactoryAccount(factoryOwner);
    const wallet = ethers.Wallet.createRandom();
    const blockchainId = 'ethereum';
    const blockchainAddress = wallet.address;

    const signedDefaultAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
        }
    );

    const createMessage = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
        }
    );

    const signature = await wallet.signMessage(createMessage);
    const deadline = BigInt(JSON.parse(createMessage).deadline);
    const attackerChosenAccountSegment = `hijack${Date.now().toString(36)}`;
    const attackerChosenAccountId = `${attackerChosenAccountSegment}.${factoryContractId}`;

    await expect(
        gasSponsor.callFunction({
            waitUntil: 'FINAL',
            contractId: factoryContractId,
            methodName: 'create_account',
            args: {
                blockchain_id: blockchainId,
                blockchain_address: blockchainAddress,
                signature,
                deadline: deadline.toString(),
                account_id: attackerChosenAccountSegment,
            },
            gas: 100n * 10n ** 12n,
            deposit: 1n * 10n ** 21n,
        })
    ).rejects.toThrow();

    await expect(
        nearJsonRpcProvider.viewAccount(attackerChosenAccountId)
    ).rejects.toThrow();
    await expect(
        nearJsonRpcProvider.viewAccount(signedDefaultAccountId)
    ).rejects.toThrow();
});

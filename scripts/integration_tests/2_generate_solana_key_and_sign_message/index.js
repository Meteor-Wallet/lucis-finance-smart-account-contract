import { Keypair } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

function main() {
    // Fixed secret key in base58 (64 bytes total)
    const base58Secret =
        '4jocLZUv8zKS3G8TezfxqSQByKwhx6XBCJtEBPVmjiFvi3wx79NWsEeVRmn9e8c5RBGaYTCfKyMsaedTKCMG2PQt';
    const secretKey = bs58.decode(base58Secret);

    // Create Keypair from secret key
    const keypair = Keypair.fromSecretKey(secretKey);

    // Message to sign
    const add_address_message = Buffer.from(
        'Link NEAR account bob.testnet to Solana address 7PM7AQpxaERCDDBTi65fkWRQmu4BEEnJwYB7YWatuiQp with nonce 1',
        'utf8'
    );

    // Sign the message
    const add_address_signature = nacl.sign.detached(
        add_address_message,
        keypair.secretKey
    );

    const recover_key_message = Buffer.from(
        'Recover NEAR account bob.testnet to new public key ed25519:C2CYqegHwc17kKP16qgzHcoZuREvudc9tSZ663fgV1BJ with nonce 2',
        'utf8'
    );

    const recover_key_signature = nacl.sign.detached(
        recover_key_message,
        keypair.secretKey
    );

    // Output
    console.log('🔑 Public Key:', keypair.publicKey.toBase58());
    console.log('📩 Message:', add_address_message.toString());
    console.log('✍️ Signature (base58):', bs58.encode(add_address_signature));
    console.log('📩 Recover Key Message:', recover_key_message.toString());
    console.log(
        '✍️ Recover Key Signature (base58):',
        bs58.encode(recover_key_signature)
    );
}

main();

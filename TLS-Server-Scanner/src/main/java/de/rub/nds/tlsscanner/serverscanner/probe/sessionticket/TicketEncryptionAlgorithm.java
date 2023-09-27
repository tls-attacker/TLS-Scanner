/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum TicketEncryptionAlgorithm {
    DES_ECB(8, 0, 8, "DES/ECB/NoPadding"),
    DES_CBC(8, 8, 8, "DES/CBC/NoPadding"),
    DES_EDE_ECB(24, 0, 8, "DESede/ECB/NoPadding"),
    DES_EDE_CBC(24, 8, 8, "DESede/CBC/NoPadding"),
    AES_128_ECB(16, 0, 16, "AES/ECB/NoPadding"),
    AES_256_ECB(32, 0, 16, "AES/ECB/NoPadding"),
    AES_128_CBC(16, 16, 16, "AES/CBC/NoPadding"),
    AES_256_CBC(32, 16, 16, "AES/CBC/NoPadding"),
    AES_128_CTR(16, 16, 1, "AES/CTR/NoPadding"),
    AES_256_CTR(32, 16, 1, "AES/CTR/NoPadding"),
    AES_128_CCM(16, 16, 1, "AES/CCM/NoPadding", "AES/CTR/NoPadding"),
    AES_256_CCM(32, 16, 1, "AES/CCM/NoPadding", "AES/CTR/NoPadding"),
    AES_128_GCM(16, 12, 1, "AES/GCM/NoPadding", "AES/CTR/NoPadding"),
    AES_256_GCM(32, 12, 1, "AES/GCM/NoPadding", "AES/CTR/NoPadding"),
    CHACHA20_POLY1305(32, 12, 1, "ChaCha20-Poly1305", "ChaCha20");

    private static final Logger LOGGER = LogManager.getLogger();
    public final int keySize;
    public final int ivNonceSize;
    public final int blockSize;
    public final String javaName;
    /*
     * javaNameForDecryption is the algorithm with which we actually try to decrypt the state. If we decrypt a ticket
     * that is for example encrypted with an AEAD cipher, we only decrypt the ticket with the underlying encryption
     * cipher since we do not need to verify the integrity
     */
    public final String javaNameForDecryption;
    public final String keySpecAlgorithm;

    private final ThreadLocal<Cipher> decryptionCipherInstance;

    private TicketEncryptionAlgorithm(
            int keySize,
            int ivNonceSize,
            int blockSize,
            String javaName,
            String javaNameForDecryption) {
        assert blockSize > 0 : "blockSize needs to be at least 1";
        this.keySize = keySize;
        this.ivNonceSize = ivNonceSize;
        this.javaName = javaName;
        this.blockSize = blockSize;
        int separator = javaNameForDecryption.indexOf('/');
        if (separator != -1) {
            this.keySpecAlgorithm = javaNameForDecryption.substring(0, separator);
        } else {
            this.keySpecAlgorithm = javaNameForDecryption;
        }
        this.javaNameForDecryption = javaNameForDecryption;

        decryptionCipherInstance = ThreadLocal.withInitial(() -> getCipherInstance(this));
    }

    private static Cipher getCipherInstance(TicketEncryptionAlgorithm algo) {
        try {
            return Cipher.getInstance(algo.javaNameForDecryption);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            LOGGER.warn(
                    "Could not initialize TicketEncryptionAlgorithm for {} (tried java name {})",
                    algo,
                    algo.javaNameForDecryption,
                    e);
            return null;
        }
    }

    private TicketEncryptionAlgorithm(
            int keySize, int ivNonceSize, int blockSize, String javaName) {
        this(keySize, ivNonceSize, blockSize, javaName, javaName);
    }

    public byte[] decryptIgnoringIntegrity(byte[] key, byte[] ivNonce, byte[] ciphertext) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, keySpecAlgorithm);
            if (this == CHACHA20_POLY1305) {
                // chacha checks for same IV/key on reinitialization
                // for now we just get a new instance
                decryptionCipherInstance.remove();
            }
            Cipher cipher = decryptionCipherInstance.get();

            // prepare IV
            switch (this) {
                case AES_128_GCM:
                case AES_256_GCM:
                    ivNonce = createCtr0ForGCM(ivNonce);
                    break;
                case AES_128_CCM:
                case AES_256_CCM:
                    ivNonce = createCtr0ForCCM(ivNonce);
                    break;
                default:
                    // nothing to do
            }

            // create IV spec
            AlgorithmParameterSpec ivSpec;
            switch (this) {
                case CHACHA20_POLY1305:
                    ivSpec = new ChaCha20ParameterSpec(ivNonce, 1);
                    break;
                case DES_ECB:
                case DES_EDE_ECB:
                case AES_128_ECB:
                case AES_256_ECB:
                    ivSpec = null;
                    break;
                default:
                    ivSpec = new IvParameterSpec(ivNonce);
            }

            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(ciphertext);
        } catch (InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            LOGGER.warn("Internal error while decrypting", e);
            return null;
        }
    }

    /**
     * we decrypt gcm using counter mode, therefore we have to generate correct initial counter
     * value counter_0 = nonce(12 bytes) || 0002
     *
     * @param nonce 12 byte nonce sent by server
     * @return counter_0
     */
    private static byte[] createCtr0ForGCM(byte[] nonce) {
        byte[] counterZero = new byte[16];
        System.arraycopy(nonce, 0, counterZero, 0, 12);
        counterZero[12] = 0;
        counterZero[13] = 0;
        counterZero[14] = 0;
        counterZero[15] = 2;
        return counterZero;
    }

    /**
     * the ccm decryption uses ctr mode, therefore we have to generate the correct initial counter
     * value Q= 15-1-nonce_length in our case nonce_length fixed to 12 -> Q=2 counter_0 = Q ||
     * nonce(12 bytes) || 001
     *
     * @param nonce
     * @return
     */
    private static byte[] createCtr0ForCCM(byte[] nonce) {
        byte[] counterZero = new byte[16];
        counterZero[0] = 2;
        System.arraycopy(nonce, 0, counterZero, 1, 12);
        counterZero[13] = 0;
        counterZero[14] = 0;
        counterZero[15] = 1;

        return counterZero;
    }
}

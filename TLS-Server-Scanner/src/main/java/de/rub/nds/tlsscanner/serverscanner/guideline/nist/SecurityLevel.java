/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.nist;

/**
 * Security Level according to NIST.SP.800-57pt1r5.
 *
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST.SP.800-57pt1r5</a>
 */
public class SecurityLevel {

    /**
     * Returns the security strength that the given symmetric-key algorithm can provide.
     *
     * @param  symmetricKeyAlgorithm
     *                               the symmetric-key algorithm.
     * @return                       the security strength.
     */
    public static int getSecurity(String symmetricKeyAlgorithm) {
        switch (symmetricKeyAlgorithm) {
            case "2TDEA":
                return 80;
            case "3TDEA":
                return 112;
            case "AES-128":
                return 128;
            case "AES-192":
                return 192;
            case "AES-256":
                return 256;
            default:
                throw new IllegalArgumentException("Unrated Algorithm.");
        }
    }

    /**
     * Indicates the minimum size of the parameters associated with the standards that use finite-field cryptography
     * (FFC). Examples of such algorithms include DSA, Diffie-Hellman (DH) and MQV key agreement.
     *
     * @param  publicKeySize
     *                        size of the public key.
     * @param  privateKeySize
     *                        size of the private key.
     * @return                the security level.
     */
    public static int getFFCSecurity(int publicKeySize, int privateKeySize) {
        if (publicKeySize >= 15360 && privateKeySize >= 512) {
            return 256;
        } else if (publicKeySize >= 7680 && privateKeySize >= 384) {
            return 192;
        } else if (publicKeySize >= 3072 && privateKeySize >= 256) {
            return 128;
        } else if (publicKeySize >= 2048 && privateKeySize >= 224) {
            return 112;
        } else if (publicKeySize >= 1024 && privateKeySize >= 160) {
            return 80;
        }
        return 0;
    }

    /**
     * Indicates the value for the size of the modulus n for algorithms based on integer-factorization cryptography
     * (IFC). The predominant algorithm of this type is the RSA algorithm. The modulus size is commonly considered to be
     * the key size.
     *
     * @param  modulusSize
     *                     the modulus size.
     * @return             the security strength.
     */
    public static int getIFCSecurity(int modulusSize) {
        if (modulusSize >= 15360) {
            return 256;
        } else if (modulusSize >= 7680) {
            return 192;
        } else if (modulusSize >= 3072) {
            return 128;
        } else if (modulusSize >= 2048) {
            return 112;
        } else if (modulusSize >= 1024) {
            return 80;
        }
        return 0;
    }

    /**
     * Indicates the range of f (the size of n, where n is the order of the base point G) for algorithms based on
     * elliptic-curve cryptography (ECC) that are specified for digital signatures in FIPS 186 and for key establishment
     * as specified in SP 800-56A. The value of f is commonly considered to be the key size.
     *
     * @param  sizeOfOrderOfBasePoint
     *                                the size of the order of the base point.
     * @return                        the security strength.
     */
    public static int getECCSecurity(int sizeOfOrderOfBasePoint) {
        if (sizeOfOrderOfBasePoint >= 512) {
            return 256;
        } else if (sizeOfOrderOfBasePoint >= 384) {
            return 192;
        } else if (sizeOfOrderOfBasePoint >= 256) {
            return 128;
        } else if (sizeOfOrderOfBasePoint >= 224) {
            return 112;
        } else if (sizeOfOrderOfBasePoint >= 160) {
            return 80;
        }
        return 0;
    }
}

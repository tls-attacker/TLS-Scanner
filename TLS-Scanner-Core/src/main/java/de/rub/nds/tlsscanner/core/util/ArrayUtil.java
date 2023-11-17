/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.util;

import java.util.Optional;

public class ArrayUtil {
    private ArrayUtil() {}

    /**
     * Check whether an array (haystack) contains the other array (needle)
     *
     * @param haystack Array to search through
     * @param needle Array to search for
     * @return Index at which needle starts in haystack. Empty Optional if not found.
     */
    public static Optional<Integer> findSubarray(byte[] haystack, byte[] needle) {
        for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            if (haystack[offset] == needle[0]) {

                boolean difference = false;
                // check if needle starts here
                for (int i = 0; i < needle.length; i++) {
                    if (haystack[offset + i] != needle[i]) {
                        difference = true;
                        break;
                    }
                }
                if (!difference) {
                    return Optional.of(offset);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * xor two byte arrays
     *
     * @param a first byte array
     * @param b second byte array
     * @return xor of both byte arrays. This has the length of the shorter array.
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length > b.length) {
            return xor(b, a); // NOSONAR S2234
        }

        assert a.length <= b.length;

        byte[] ret = new byte[a.length];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) (a[i] ^ b[i]);
        }
        return ret;
    }
}

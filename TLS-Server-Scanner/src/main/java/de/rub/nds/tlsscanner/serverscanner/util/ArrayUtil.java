/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.util;

public class ArrayUtil {
    private ArrayUtil() {
    }

    /**
     * Check whether an array (haystack) contains the other array (needle)
     * 
     * @param  haystack
     *                  Array to search through
     * @param  needle
     *                  Array to search for
     * @return          Index at which needle starts in haystack. Or -1 if not found.
     */
    public static int findSubarray(byte[] haystack, byte[] needle) {
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
                    return offset;
                }
            }
        }
        return -1;
    }
}

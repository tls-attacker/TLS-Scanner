/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.util;

import java.util.Random;

public class RandString {
    private static final Random random = new Random();
    public static final char[] ALPHABET_ALPHANUM = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();

    private RandString() {
        throw new UnsupportedOperationException("Utility Class");
    }

    public static String getRandomString(int length, char[] alphabet) {
        char[] retArr = new char[length];
        for (int i = 0; i < retArr.length; i++) {
            retArr[i] = alphabet[random.nextInt(alphabet.length)];
        }
        return new String(retArr);
    }

    public static String getRandomAlphaNumeric(int length) {
        return getRandomString(length, ALPHABET_ALPHANUM);
    }
}

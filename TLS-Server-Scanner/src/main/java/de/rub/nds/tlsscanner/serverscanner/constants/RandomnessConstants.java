/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.constants;

/**
 * * Constants used by the statistical tests employed by the TlsRngAfterProbe
 */
public class RandomnessConstants {

    // See NIST SP 800-22 2.4.4 (3)
    public final static int[][] LONGEST_RUN_VALUES = { { 8, 3, 16 }, { 128, 5, 49 }, { 10000, 6, 75 } };
    // See NIST SP 800-22 2.4.4 (2)
    public final static int[][] LONGEST_RUN_EXPECTATION =
        { { 1, 2, 3, 4 }, { 4, 5, 6, 7, 8, 9 }, { 10, 11, 12, 13, 14, 15, 16 } };
    // See NIST SP 800-22 3.4
    public final static double[][] LONGEST_RUN_PROBABILITIES =
        { { 0.2148, 0.3672, 0.2305, 0.1875 }, { 0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124 },
            { 0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727 } };
    // Directly taken from the NIST statistical test suite code
    // For version 2.1.2 this template was found under templates/template9
    public final static String[][] TEMPLATE_NINE = { { "000000001" }, { "000000011" }, { "000000101" }, { "000000111" },
        { "000001001" }, { "000001011" }, { "000001101" }, { "000001111" }, { "000010001" }, { "000010011" },
        { "000010101" }, { "000010111" }, { "000011001" }, { "000011011" }, { "000011101" }, { "000011111" },
        { "000100011" }, { "000100101" }, { "000100111" }, { "000101001" }, { "000101011" }, { "000101101" },
        { "000101111" }, { "000110011" }, { "000110101" }, { "000110111" }, { "000111001" }, { "000111011" },
        { "000111101" }, { "000111111" }, { "001000011" }, { "001000101" }, { "001000111" }, { "001001011" },
        { "001001101" }, { "001001111" }, { "001010011" }, { "001010101" }, { "001010111" }, { "001011011" },
        { "001011101" }, { "001011111" }, { "001100101" }, { "001100111" }, { "001101011" }, { "001101101" },
        { "001101111" }, { "001110101" }, { "001110111" }, { "001111011" }, { "001111101" }, { "001111111" },
        { "010000011" }, { "010000111" }, { "010001011" }, { "010001111" }, { "010010011" }, { "010010111" },
        { "010011011" }, { "010011111" }, { "010100011" }, { "010100111" }, { "010101011" }, { "010101111" },
        { "010110011" }, { "010110111" }, { "010111011" }, { "010111111" }, { "011000111" }, { "011001111" },
        { "011010111" }, { "011011111" }, { "011101111" }, { "011111111" }, { "100000000" }, { "100010000" },
        { "100100000" }, { "100101000" }, { "100110000" }, { "100111000" }, { "101000000" }, { "101000100" },
        { "101001000" }, { "101001100" }, { "101010000" }, { "101010100" }, { "101011000" }, { "101011100" },
        { "101100000" }, { "101100100" }, { "101101000" }, { "101101100" }, { "101110000" }, { "101110100" },
        { "101111000" }, { "101111100" }, { "110000000" }, { "110000010" }, { "110000100" }, { "110001000" },
        { "110001010" }, { "110010000" }, { "110010010" }, { "110010100" }, { "110011000" }, { "110011010" },
        { "110100000" }, { "110100010" }, { "110100100" }, { "110101000" }, { "110101010" }, { "110101100" },
        { "110110000" }, { "110110010" }, { "110110100" }, { "110111000" }, { "110111010" }, { "110111100" },
        { "111000000" }, { "111000010" }, { "111000100" }, { "111000110" }, { "111001000" }, { "111001010" },
        { "111001100" }, { "111010000" }, { "111010010" }, { "111010100" }, { "111010110" }, { "111011000" },
        { "111011010" }, { "111011100" }, { "111100000" }, { "111100010" }, { "111100100" }, { "111100110" },
        { "111101000" }, { "111101010" }, { "111101100" }, { "111101110" }, { "111110000" }, { "111110010" },
        { "111110100" }, { "111110110" }, { "111111000" }, { "111111010" }, { "111111100" }, { "111111110" } };

}

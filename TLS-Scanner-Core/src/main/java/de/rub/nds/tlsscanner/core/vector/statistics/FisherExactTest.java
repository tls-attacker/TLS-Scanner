/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

/**
 * Implements Fisher's exact test for the analysis of contingency tables. This test is used to
 * determine if there are nonrandom associations between two categorical variables.
 */
public class FisherExactTest {

    /**
     * Calculates the p-value for Fisher's exact test on a 2x2 contingency table.
     *
     * @param inputAOutput1 Count of observations with input A and output 1
     * @param inputBOutput1 Count of observations with input B and output 1
     * @param inputAOutput2 Count of observations with input A and output 2
     * @param inputBOutput2 Count of observations with input B and output 2
     * @return The p-value indicating the probability of observing the given distribution by chance
     */
    public static double getPValue(
            int inputAOutput1, int inputBOutput1, int inputAOutput2, int inputBOutput2) {
        return Math.pow(
                2,
                FisherExactTest.getLog2PValue(
                        inputAOutput1, inputBOutput1, inputAOutput2, inputBOutput2));
    }

    private static double getLog2PValue(
            int inputAOutput1, int inputBOutput1, int inputAOutput2, int inputBOutput2) {
        int a = inputAOutput1;
        int b = inputBOutput1;
        int c = inputAOutput2;
        int d = inputBOutput2;
        int n = a + b + c + d;
        double nominator =
                log2Factorial(a + b)
                        + log2Factorial(c + d)
                        + log2Factorial(a + c)
                        + log2Factorial(b + d);
        double denominator =
                log2Factorial(a)
                        + log2Factorial(b)
                        + log2Factorial(c)
                        + log2Factorial(d)
                        + log2Factorial(n);
        return nominator - denominator;
    }

    private static double log2Factorial(int k) {
        double res = 0;
        for (int i = 2; i <= k; i++) {
            res += log2(i);
        }
        return res;
    }

    private static double log2(int i) {
        return Math.log(i) / Math.log(2);
    }
}

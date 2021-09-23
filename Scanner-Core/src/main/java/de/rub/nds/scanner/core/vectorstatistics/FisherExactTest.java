/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.vectorstatistics;

public class FisherExactTest {

    public static double getPValue(int inputAOutput1, int inputBOutput1, int inputAOutput2, int inputBOutput2) {
        return Math.pow(2, FisherExactTest.getLog2PValue(inputAOutput1, inputBOutput1, inputAOutput2, inputBOutput2));
    }

    private static double getLog2PValue(int inputAOutput1, int inputBOutput1, int inputAOutput2, int inputBOutput2) {
        int a = inputAOutput1;
        int b = inputBOutput1;
        int c = inputAOutput2;
        int d = inputBOutput2;
        int n = a + b + c + d;
        double nominator = log2Factorial(a + b) + log2Factorial(c + d) + log2Factorial(a + c) + log2Factorial(b + d);
        double denominator =
            log2Factorial(a) + log2Factorial(b) + log2Factorial(c) + log2Factorial(d) + log2Factorial(n);
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

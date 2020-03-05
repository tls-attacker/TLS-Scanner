/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.util;

public class FisherExactTest {

    public static double getLog2PValue(int inputAOutput1, int inputBOutput1, int inputAoutput2, int inputBOutput2) {
        int a = inputAOutput1;
        int b = inputBOutput1;
        int c = inputAoutput2;
        int d = inputBOutput2;
        int n = a + b + c + d;
        double nominator = factorial(a + b) * factorial(c + d) * factorial(a + c) * factorial(b + d);
        double denominator = factorial(a) * factorial(b) * factorial(c) * factorial(d)
                * factorial(n);
        return nominator / denominator;
    }
    
    public static double factorial(int k)
    {
        double res = 1;
        for(int i = 1; i <= k; i ++)
        {
            res *= i;
        }
        return res;
        
    }

    public static double log2Factorial(int k) {
        double res = 0;
        for (int i = 2; i < k; i++) {
            res += log2(i);
        }
        return res;
    }

    private static double log2(int i) {
        return Math.log(i) / Math.log(2);
    }
}

/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.util;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ic0ns
 */
public class FisherExactTestTest {

    public FisherExactTestTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getLog2PValue method, of class FisherExactTest.
     */
    @Test
    public void testGetLog2PValue() {
        System.out.println("getLog2PValue");
        int inputAOutput1 = 2000;
        int inputBOutput1 = 3100;
        int inputAoutput2 = 3000;
        int inputBOutput2 = 1009;
        double result = FisherExactTest.getPValue(inputAOutput1, inputBOutput1, inputAoutput2, inputBOutput2);
        System.out.println(result);
    }
}

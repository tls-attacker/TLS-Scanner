/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

public class SessionTicketAfterProbeTest {

    @Test
    public void testIsAsciiWithSignedBytes() throws Exception {
        // Use reflection to test the private isAscii method
        Method isAsciiMethod =
                SessionTicketAfterProbe.class.getDeclaredMethod("isAscii", byte.class);
        isAsciiMethod.setAccessible(true);

        // Test normal ASCII range (0x20 to 0x7F)
        assertTrue((Boolean) isAsciiMethod.invoke(null, (byte) 0x20)); // space
        assertTrue((Boolean) isAsciiMethod.invoke(null, (byte) 0x41)); // 'A'
        assertTrue((Boolean) isAsciiMethod.invoke(null, (byte) 0x7F)); // DEL

        // Test below ASCII range
        assertFalse((Boolean) isAsciiMethod.invoke(null, (byte) 0x00)); // NUL
        assertFalse((Boolean) isAsciiMethod.invoke(null, (byte) 0x1F)); // US

        // Test above ASCII range - these bytes will be negative in Java's signed representation
        assertFalse((Boolean) isAsciiMethod.invoke(null, (byte) 0x80)); // -128 in signed
        assertFalse((Boolean) isAsciiMethod.invoke(null, (byte) 0xFF)); // -1 in signed

        // Test edge cases
        assertTrue((Boolean) isAsciiMethod.invoke(null, (byte) 0x20)); // minimum ASCII
        assertTrue((Boolean) isAsciiMethod.invoke(null, (byte) 0x7F)); // maximum ASCII
        assertFalse((Boolean) isAsciiMethod.invoke(null, (byte) 0x1F)); // just below minimum
        assertFalse((Boolean) isAsciiMethod.invoke(null, (byte) 0x80)); // just above maximum
    }
}

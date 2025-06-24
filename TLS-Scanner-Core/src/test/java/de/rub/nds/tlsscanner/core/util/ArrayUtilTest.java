/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class ArrayUtilTest {

    @Test
    void testFindSubarrayWithNullHaystack() {
        byte[] needle = new byte[] {1, 2, 3};
        Optional<Integer> result = ArrayUtil.findSubarray(null, needle);
        assertFalse(result.isPresent());
    }

    @Test
    void testFindSubarrayWithNullNeedle() {
        byte[] haystack = new byte[] {1, 2, 3, 4, 5};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, null);
        assertFalse(result.isPresent());
    }

    @Test
    void testFindSubarrayWithBothNull() {
        Optional<Integer> result = ArrayUtil.findSubarray(null, null);
        assertFalse(result.isPresent());
    }

    @Test
    void testFindSubarrayWithEmptyNeedle() {
        byte[] haystack = new byte[] {1, 2, 3, 4, 5};
        byte[] needle = new byte[] {};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, needle);
        assertFalse(result.isPresent());
    }

    @Test
    void testFindSubarrayWithNeedleLongerThanHaystack() {
        byte[] haystack = new byte[] {1, 2};
        byte[] needle = new byte[] {1, 2, 3};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, needle);
        assertFalse(result.isPresent());
    }

    @Test
    void testFindSubarrayNormalCase() {
        byte[] haystack = new byte[] {1, 2, 3, 4, 5};
        byte[] needle = new byte[] {3, 4};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, needle);
        assertTrue(result.isPresent());
        assertEquals(2, result.get());
    }

    @Test
    void testFindSubarrayAtBeginning() {
        byte[] haystack = new byte[] {1, 2, 3, 4, 5};
        byte[] needle = new byte[] {1, 2};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, needle);
        assertTrue(result.isPresent());
        assertEquals(0, result.get());
    }

    @Test
    void testFindSubarrayAtEnd() {
        byte[] haystack = new byte[] {1, 2, 3, 4, 5};
        byte[] needle = new byte[] {4, 5};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, needle);
        assertTrue(result.isPresent());
        assertEquals(3, result.get());
    }

    @Test
    void testFindSubarrayNotFound() {
        byte[] haystack = new byte[] {1, 2, 3, 4, 5};
        byte[] needle = new byte[] {6, 7};
        Optional<Integer> result = ArrayUtil.findSubarray(haystack, needle);
        assertFalse(result.isPresent());
    }
}

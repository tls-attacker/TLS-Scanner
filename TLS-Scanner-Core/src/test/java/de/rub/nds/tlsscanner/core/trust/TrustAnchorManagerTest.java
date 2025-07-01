/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.trust;

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.TrustAnchor;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TrustAnchorManagerTest {

    private TrustAnchorManager trustAnchorManager;

    @BeforeEach
    void setUp() {
        trustAnchorManager = TrustAnchorManager.getInstance();
    }

    @Test
    void testGetTrustPlatformListReturnsDefensiveCopy() {
        if (!trustAnchorManager.isInitialized()) {
            return;
        }

        List<TrustPlatform> list1 = trustAnchorManager.getTrustPlatformList();
        List<TrustPlatform> list2 = trustAnchorManager.getTrustPlatformList();

        assertNotNull(list1);
        assertNotNull(list2);
        assertNotSame(list1, list2, "getTrustPlatformList should return defensive copies");

        if (!list1.isEmpty()) {
            int originalSize = list1.size();
            list1.clear();
            List<TrustPlatform> list3 = trustAnchorManager.getTrustPlatformList();
            assertEquals(
                    originalSize,
                    list3.size(),
                    "Modifying returned list should not affect internal state");
        }
    }

    @Test
    void testGetTrustAnchorSetReturnsDefensiveCopy() {
        if (!trustAnchorManager.isInitialized()) {
            return;
        }

        Set<TrustAnchor> set1 = trustAnchorManager.getTrustAnchorSet();
        Set<TrustAnchor> set2 = trustAnchorManager.getTrustAnchorSet();

        assertNotNull(set1);
        assertNotNull(set2);
        assertNotSame(set1, set2, "getTrustAnchorSet should return defensive copies");

        if (!set1.isEmpty()) {
            int originalSize = set1.size();
            set1.clear();
            Set<TrustAnchor> set3 = trustAnchorManager.getTrustAnchorSet();
            assertEquals(
                    originalSize,
                    set3.size(),
                    "Modifying returned set should not affect internal state");
        }
    }

    @Test
    void testGetTrustPlatformListHandlesNull() {
        List<TrustPlatform> list = trustAnchorManager.getTrustPlatformList();
        if (!trustAnchorManager.isInitialized()) {
            assertNull(list, "Should return null when not initialized");
        }
    }

    @Test
    void testGetTrustAnchorSetHandlesNull() {
        Set<TrustAnchor> set = trustAnchorManager.getTrustAnchorSet();
        if (!trustAnchorManager.isInitialized()) {
            assertNull(set, "Should return null when not initialized");
        }
    }
}

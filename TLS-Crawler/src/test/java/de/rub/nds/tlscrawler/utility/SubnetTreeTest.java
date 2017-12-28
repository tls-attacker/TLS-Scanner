/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for SubnetTree.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SubnetTreeTest {

    @Test
    public void SubnetTreeSmokeTest() {
        SubnetTree tree = new SubnetTree();
        tree.addSubnet("1.1.1.112/29");

        assertFalse(tree.isInRange("1.1.1.99"));
        assertFalse(tree.isInRange("1.1.1.110"));
        assertFalse(tree.isInRange("1.1.1.111"));
        assertTrue(tree.isInRange("1.1.1.112"));
        assertTrue(tree.isInRange("1.1.1.113"));
        assertTrue(tree.isInRange("1.1.1.114"));
        assertTrue(tree.isInRange("1.1.1.115"));
        assertTrue(tree.isInRange("1.1.1.116"));
        assertTrue(tree.isInRange("1.1.1.117"));
        assertTrue(tree.isInRange("1.1.1.118"));
        assertTrue(tree.isInRange("1.1.1.119"));
        assertFalse(tree.isInRange("1.1.1.120"));
        assertFalse(tree.isInRange("1.1.1.121"));
        assertFalse(tree.isInRange("1.1.1.122"));

        tree.addSubnet("1.2.3.112/29");

        assertFalse(tree.isInRange("1.2.3.99"));
        assertFalse(tree.isInRange("1.2.3.110"));
        assertFalse(tree.isInRange("1.2.3.111"));
        assertTrue(tree.isInRange("1.2.3.112"));
        assertTrue(tree.isInRange("1.2.3.113"));
        assertTrue(tree.isInRange("1.2.3.114"));
        assertTrue(tree.isInRange("1.2.3.115"));
        assertTrue(tree.isInRange("1.2.3.116"));
        assertTrue(tree.isInRange("1.2.3.117"));
        assertTrue(tree.isInRange("1.2.3.118"));
        assertTrue(tree.isInRange("1.2.3.119"));
        assertFalse(tree.isInRange("1.2.3.120"));
        assertFalse(tree.isInRange("1.2.3.121"));
        assertFalse(tree.isInRange("1.2.3.122"));
    }

    @Test
    public void SubnetTreeUnconfiguredTest() {
        SubnetTree tree = new SubnetTree();

        assertFalse(tree.isInRange("1.2.3.4"));
        assertFalse(tree.isInRange("89.72.34.222"));
        assertFalse(tree.isInRange("255.255.255.255"));
        assertFalse(tree.isInRange("1.1.1.1"));
    }

    @Test
    public void SubnetTreeWhitelistTest() {
        SubnetTree tree = new SubnetTree();
        tree.addSubnet("0.0.0.0/0");

        assertTrue(tree.isInRange("1.2.3.4"));
        assertTrue(tree.isInRange("89.72.34.222"));
        assertTrue(tree.isInRange("255.255.255.255"));
        assertTrue(tree.isInRange("1.1.1.1"));
    }
}
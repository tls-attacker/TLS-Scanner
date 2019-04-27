/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 *
 * Adapted from https://stackoverflow.com/a/38998454
 */
package de.rub.nds.tlscrawler.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

/**
 * Utility class, helps to check whether IP address is part of the added subnets.
 * Builds a binary tree from the subnet entries, so checking is O(1), with a worst
 * case scenario of 32 lookups.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SubnetTree {
    private static Logger LOG = LoggerFactory.getLogger(SubnetTree.class);

    private SubnetTree one;
    private SubnetTree zero;
    private boolean terminating;

    /**
     * CAVE: No args check. // TODO
     *
     * @param cidr A string containing an IP-space in CIDR notation.
     */
    public void addSubnet(String cidr) {
        String[] cidrSplit = cidr.split("/");

        int net = this.addressToInt(cidrSplit[0]);
        int bits = Integer.parseInt(cidrSplit[1]);

        this.addSubnetBinary(net, bits);
    }

    public boolean isInRange(String ip) {
        return this.isInRangeBinary(this.addressToInt(ip));
    }

    private void addSubnetBinary(int net, int bits) {
        if (terminating) {
            // If this node is already terminating, then no need to add
            // subnets that are more specific
            return;
        }

        if (bits > 0) {
            boolean bit = ((net >>> 31) & 1) == 1;
            if (bit) {
                if (one == null) {
                    one = new SubnetTree();
                }
                one.addSubnetBinary(net << 1, bits - 1);
            } else {
                if (zero == null) {
                    zero = new SubnetTree();
                }
                zero.addSubnetBinary(net << 1, bits - 1);
            }
        } else {
            terminating = true;
        }
    }

    private boolean isInRangeBinary(int address) {
        if (terminating) {
            return true;
        }

        boolean bit = ((address >>> 31) & 1) == 1;

        if (bit) {
            if (one == null) {
                return false;
            } else {
                return one.isInRangeBinary(address << 1);
            }
        } else {
            if (zero == null) {
                return false;
            } else {
                return zero.isInRangeBinary(address << 1);
            }
        }
    }

    private int addressToInt(String ip) {
        String[] address = ip.split(Pattern.quote("."));
        int[] ipBytes = new int[4];

        for (int i = 0; i < 4; i++) {
            ipBytes[i] = Integer.parseInt(address[i]);
        }



        return ipBytes[0] << 24 | ipBytes[1] << 16 | ipBytes[2] << 8 | ipBytes[3];
    }
}



/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.List;

/**
 * Implements the IAddressGenerator interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
class AddressGenerator implements IAddressIterator {
    /*
        CAVE: This is a NAIVE implementation, as can be told from the
        usage of the private class below.
     */

    private static Logger LOG = LoggerFactory.getLogger(AddressGenerator.class);

    private SubnetTree blacklist;
    private SubnetTree whitelist;

    private FullRangeIterator it;

    private String next;

    /**
     * Package private, should be build through the factory.
     */
    AddressGenerator() {
        this.whitelist = null;
        this.blacklist = null;
    }

    @Override
    public boolean hasNext() {
        this.checkInit();

        return (this.next != null);
    }

    @Override
    public String next() {
        this.checkInit();

        if (!this.hasNext()) {
            throw new RuntimeException("No more items.");
        }

        String result = this.next;
        this.findNext();

        return result;
    }

    @Override
    public void remove() {
        throw new RuntimeException("Illegal Action.");
    }

    public void init(List<String> blacklist, List<String> whitelist) {
        SubnetTree bl = new SubnetTree();
        for (String s : blacklist) {
            bl.addSubnet(s);
        }

        this.blacklist = bl;

        SubnetTree wl = new SubnetTree();
        for (String s : whitelist) {
            wl.addSubnet(s);
        }

        this.whitelist = wl;

        this.next = null;

        this.it = new FullRangeIterator();

        this.findNext();
    }

    private void findNext() {
        while (this.it.hasNext()) {
            String ip = this.it.getNext();

            if (this.whitelist.isInRange(ip) && !this.blacklist.isInRange(ip)) {
                this.next = ip;
                break;
            }
        }
    }

    private void checkInit() {
        if (this.whitelist == null || this.blacklist == null) {
            throw new RuntimeException("AddressGenerator needs to be initialized.");
        }
    }

    @Override
    public Iterator<String> iterator() {
        return this;
    }

    /**
     * A class to continously generate all addresses in the ipv4 space.
     */
    private class FullRangeIterator {
        int a = 0;
        int b = 0;
        int c = 0;
        int d = 0;

        boolean hasNext = true;

        public String getNext() {
            if (!hasNext) {
                throw new RuntimeException("No more items.");
            }

            String result = String.format("%d.%d.%d.%d", a, b, c, d);

            if (++d > 255) {
                d = 0;

                if (++c > 255) {
                    c = 0;

                    if (++b > 255) {
                        b = 0;

                        if (++a > 255) {
                            hasNext = false;
                        }
                    }
                }
            }

            return result;
        }

        public boolean hasNext() {
            return this.hasNext;
        }
    }
}

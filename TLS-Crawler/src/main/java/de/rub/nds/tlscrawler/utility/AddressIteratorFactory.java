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

import java.net.ConnectException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Builds AddressIterators and provides their configuration options.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class AddressIteratorFactory {
    private static Logger LOG = LoggerFactory.getLogger(AddressIteratorFactory.class);

    private List<String> blacklist;
    private List<String> whitelist;

    private AddressIteratorFactory() {
    }

    public static AddressIteratorFactory getInstance() {
        AddressIteratorFactory result = new AddressIteratorFactory();

        result.reset();

        return result;
    }

    /**
     * Redis address source can't be configured as of now.
     *
     * @param redisConnString Connection string in format "ip:port/listkey"
     * @return Address iterator reading addresses from a redis queue
     */
    public static IAddressIterator getRedisAddressSource(String redisConnString) {
        RedisAddressSource result;
        String[] split = redisConnString.split(Pattern.quote("/"));
        String redisEndpoint = split[0];
        String redisListKey = split[1];

        LOG.debug(Arrays.deepToString(split));

        result = new RedisAddressSource(redisEndpoint, redisListKey);
        try {
            result.init();
        } catch (ConnectException e) {
            LOG.error("Failed to connect to redis (Address source)");
            return null;
        }

        return result;
    }

    public IAddressIterator build() {
        AddressGenerator result = new AddressGenerator();

        result.init(this.blacklist, this.whitelist);

        return result;
    }

    public void addToWhitelist(String entry) {
        this.whitelist.add(entry);
    }

    public void addToWhitelist(List<String> entries) {
        this.whitelist.addAll(entries);
    }

    public void addToBlacklist(String entry) {
        this.blacklist.add(entry);
    }

    public void addToBlacklist(List<String> entries) {
        this.blacklist.addAll(entries);
    }

    public void reset() {
        this.blacklist = new LinkedList<>();
        this.whitelist = new LinkedList<>();
    }

    public void applyDefaultConfig(Configurations cfg) {
        this.reset();

        switch (cfg) {

            case ALL_IPS: {
                this.reset();
                this.whitelist.add("0.0.0.0/0");
            }

            break;

            case NDS_BLACKLIST: {
                this.reset();

                this.whitelist.add("0.0.0.0/0");

                this.addStandardBlacklistEntries();
                this.addNdsBlacklistEntries();
            }

            break;

            case STANDARD_BLACKLIST: {
                this.reset();

                this.whitelist.add("0.0.0.0/0");

                this.addStandardBlacklistEntries();
            }

            break;

            case NULL:
            default: {
                this.reset();
            }
        }
    }

    private void addStandardBlacklistEntries() {
        this.addToBlacklist("0.0.0.0/8");           // RFC1122: "This host on this network"
        this.addToBlacklist("10.0.0.0/8");          // RFC1918: Private-Use
        this.addToBlacklist("100.64.0.0/10");       // RFC6598: Shared Address Space
        this.addToBlacklist("127.0.0.0/8");         // RFC1122: Loopback
        this.addToBlacklist("169.254.0.0/16");      // RFC3927: Link Local
        this.addToBlacklist("172.16.0.0/12");       // RFC1918: Private-Use
        this.addToBlacklist("192.0.0.0/24");        // RFC6890: IETF Protocol Assignments
        this.addToBlacklist("192.0.2.0/24");        // RFC5737: Documentation (TEST-NET-1)
        this.addToBlacklist("192.88.99.0/24");      // RFC3068: 6to4 Relay Anycast
        this.addToBlacklist("192.168.0.0/16");      // RFC1918: Private-Use
        this.addToBlacklist("198.18.0.0/15");       // RFC2544: Benchmarking
        this.addToBlacklist("198.51.100.0/24");     // RFC5737: Documentation (TEST-NET-2)
        this.addToBlacklist("203.0.113.0/24");      // RFC5737: Documentation (TEST-NET-3)
        this.addToBlacklist("240.0.0.0/4");         // RFC1112: Reserved
        this.addToBlacklist("255.255.255.255/32");  // RFC0919: Limited Broadcast
        this.addToBlacklist("224.0.0.0/4");         // RFC5771: Multicast/Reserved
    }

    private void addNdsBlacklistEntries() {
        this.addToBlacklist("66.199.141.192/27");   // datafix.com; 2017-11-28; ~dfelsch
        this.addToBlacklist("66.207.200.112/28");   // datafix.com; 2017-11-28; ~dfelsch
        this.addToBlacklist("71.36.174.176/29");    // cobra-ent.net; 2017-11-04; ~dfelsch
        this.addToBlacklist("81.82.254.234/32");    // ICT-Worx.com; 2017-11-27; ~dfelsch
        this.addToBlacklist("84.113.132.164/32");   // chello.at; 2017-11-27; ~dfelsch
        this.addToBlacklist("187.3.22.49/32");      // projectworld.net; 2017-11-04; ~dfelsch
        this.addToBlacklist("212.51.154.243/32");   // iroom.ch; 2017-11-26; ~dfelsch
        this.addToBlacklist("216.52.163.137/32");   // hardata.com; 2017-11-06; ~dfelsch
        this.addToBlacklist("216.52.163.138/31");   // hardata.com; 2017-11-06; ~dfelsch
        this.addToBlacklist("216.52.163.140/31");   // hardata.com; 2017-11-06; ~dfelsch
    }

    public enum Configurations {
        NULL,
        ALL_IPS,
        NDS_BLACKLIST,
        STANDARD_BLACKLIST
    }
}

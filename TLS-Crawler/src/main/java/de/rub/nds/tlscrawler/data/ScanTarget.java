/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlscrawler.denylist.IDenylistProvider;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ScanTarget implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private String ip;

    private String hostname;

    private int port;

    private int trancoRank;

    public ScanTarget() {}

    /**
     * Initializes a ScanTarget object from a string that potentially contains a hostname, an ip, a
     * port, the tranco rank.
     *
     * @param targetString from which to create the ScanTarget object
     * @param defaultPort that used if no port is present in targetString
     * @param denylistProvider which provides info if a host is denylisted
     * @return ScanTarget object
     */
    public static ScanTarget fromTargetString(
            String targetString, int defaultPort, IDenylistProvider denylistProvider) {
        ScanTarget target;
        try {
            target = new ScanTarget();
            // check if targetString contains rank (e.g. "1,example.com")

            if (targetString.contains(",")) {
                if (targetString.split(",")[0].chars().allMatch(Character::isDigit)) {
                    target.setTrancoRank(Integer.parseInt(targetString.split(",")[0]));
                    targetString = targetString.split(",")[1];
                } else {
                    targetString = "";
                }
            }

            // Formatting for MX hosts
            if (targetString.contains("//")) {
                targetString = targetString.split("//")[1];
            }
            if (targetString.startsWith("\"") && targetString.endsWith("\"")) {
                targetString = targetString.replace("\"", "");
                System.out.println(targetString);
            }

            // check if targetString contains port (e.g. "www.example.com:8080")
            if (targetString.contains(":")) {
                int port = Integer.parseInt(targetString.split(":")[1]);
                targetString = targetString.split(":")[0];
                if (port > 1 && port < 65535) {
                    target.setPort(port);
                }
            } else {
                target.setPort(defaultPort);
            }
            if (InetAddressValidator.getInstance().isValid(targetString)) {
                target.setIp(targetString);
            } else {
                target.setIp(InetAddress.getByName(targetString).getHostAddress());
                target.setHostname(targetString);
            }
            if (denylistProvider != null && denylistProvider.isDenylisted(target)) {
                LOGGER.error("Host {} is blacklisted and will not be scanned.", targetString);
            }
        } catch (UnknownHostException e) {
            LOGGER.error(
                    "Host {} is unknown or can not be reached with error {}.", targetString, e);
            return null;
        }
        return target;
    }

    @Override
    public String toString() {
        return hostname != null ? hostname : ip;
    }

    public String getIp() {
        return this.ip;
    }

    public String getHostname() {
        return this.hostname;
    }

    public int getPort() {
        return this.port;
    }

    public int getTrancoRank() {
        return this.trancoRank;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setTrancoRank(int trancoRank) {
        this.trancoRank = trancoRank;
    }
}

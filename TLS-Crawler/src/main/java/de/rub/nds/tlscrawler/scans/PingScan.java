/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.ScanTarget;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Instant;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/**
 * A simple scan testing whether a host is available at a given IP address.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class PingScan implements IScan {

    private static final String name = "ping_scan";
    private static final int timeOutMs = 5000;
    private static final Logger LOG = LogManager.getLogger();

    // Ping, Java style. I. e., 1 of approx. 10^10 possible implementations with unique advantages and disadvantages to
    // each. Yeah. Standard port: Echo service, port nr 7
    private static boolean isReachable(String address, int port) {
        LOG.trace("isReachable()");

        if (port < 1 || port > 65535) {
            LOG.error("Tried connecting to a port outside the 16-bit range.");
            throw new IllegalArgumentException("port must be in range 1-65535.");
        }

        try (Socket soc = new Socket()) {
            soc.connect(new InetSocketAddress(address, port), PingScan.timeOutMs);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Document scan(ScanTarget target) {
        LOG.trace("scan()");

        Document document = new Document();
        document.put("timestamp", Instant.now());
        document.put("timeout", timeOutMs);


        if (isReachable(target.getIp(), target.getPort())) {
            document.put("reachablePorts", new ArrayList<>(target.getPort()));
            document.put("unreachablePorts", new ArrayList<>());
        } else {
            document.put("reachablePorts", new ArrayList<>());
            document.put("unreachablePorts", new ArrayList<>(target.getPort()));
        }

        return document;
    }

}

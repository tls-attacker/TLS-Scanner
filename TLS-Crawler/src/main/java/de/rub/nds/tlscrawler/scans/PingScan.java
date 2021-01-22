/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.ScanTarget;
import de.rub.nds.tlscrawler.utility.Tuple;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/**
 * A simple scan testing whether a host is available at a given IP address.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class PingScan implements IScan {

    private static Logger LOG = LogManager.getLogger();

    private static final String name = "ping_scan";
    private static final int timeOutMs = 5000;

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Document scan(ScanTarget target) {
        LOG.trace("scan()");

        Document document = new Document();
        document.put("timestamp", Instant.now());
        document.put("timeout", this.timeOutMs);

        Collection<Tuple> portwiseScanResult = new LinkedList<>();
        portwiseScanResult.add(Tuple.create(target.getPort(), isReachable(target.getIp(), target.getPort())));

        List<Integer> reachablePorts = portwiseScanResult.stream()
                .filter(x -> (boolean) x.getSecond())
                .map(x -> (int) x.getFirst())
                .collect(Collectors.toList());

        List<Integer> unreachablePorts = portwiseScanResult.stream()
                .filter(x -> !(boolean) x.getSecond())
                .map(x -> (int) x.getFirst())
                .collect(Collectors.toList());

        document.put("reachablePorts", reachablePorts);
        document.put("unreachablePorts", unreachablePorts);

        return document;
    }

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

}

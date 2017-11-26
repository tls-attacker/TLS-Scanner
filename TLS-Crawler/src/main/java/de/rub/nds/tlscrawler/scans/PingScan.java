/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.utility.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A simple scan testing whether a host is available at a given IP address.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class PingScan implements IScan {
    private static Logger LOG = LoggerFactory.getLogger(PingScan.class);

    private static final String name = "ping";
    private static final int timeOutMs = 5000;

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public IScanResult scan(IScanTarget target) {
        IScanResult result = new ScanResult(this.getName());

        result.addTimestamp("timestamp", Instant.now());
        result.addInteger("timeout", this.timeOutMs);

        Collection<Tuple> portwiseScanResult = new LinkedList<>();
        for (Integer port : target.getPorts()) {
            portwiseScanResult.add(Tuple.create(port, isReachable(target.getIp(), port)));
        }

        List<Integer> reachablePorts = portwiseScanResult.stream()
                .filter(x -> (boolean)x.getSecond())
                .map(x -> (int)x.getFirst())
                .collect(Collectors.toList());

        List<Integer> unreachablePorts = portwiseScanResult.stream()
                .filter(x -> !(boolean)x.getSecond())
                .map(x -> (int)x.getFirst())
                .collect(Collectors.toList());

        result.addIntegerArray("reachablePorts", reachablePorts);
        result.addIntegerArray("unreachablePorts", unreachablePorts);

        return result;
    }

    // Ping, Java style. I. e., 1 of approx. 10^10 possible implementations with unique advantages and disadvantages to
    // each. Yeah. Standard port: Echo service, port nr 7
    private static boolean isReachable(String address, int port) {
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

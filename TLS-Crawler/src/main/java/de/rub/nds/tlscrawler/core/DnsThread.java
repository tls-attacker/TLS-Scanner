package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.ScanTarget;
import java.net.InetAddress;
import java.util.concurrent.Callable;

public class DnsThread implements Callable<ScanTarget> {

    private final String hostname;
    private final int port;

    public DnsThread(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public ScanTarget call() {
        try {
            InetAddress address = InetAddress.getByName(hostname);
            return new ScanTarget(address.getHostAddress(), hostname, port);
        } catch (Exception E) {
            //TODO LOG
            return new ScanTarget(null, hostname, port);
        }
    }
}

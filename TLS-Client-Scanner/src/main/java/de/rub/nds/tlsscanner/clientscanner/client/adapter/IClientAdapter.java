package de.rub.nds.tlsscanner.clientscanner.client.adapter;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;

public interface IClientAdapter {
    public ClientInfo getReportInformation();

    public void prepare(boolean clean);

    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException;

    public void cleanup(boolean deleteAll);
}
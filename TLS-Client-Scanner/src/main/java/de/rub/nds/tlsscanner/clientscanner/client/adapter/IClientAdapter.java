package de.rub.nds.tlsscanner.clientscanner.client.adapter;

import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;

public interface IClientAdapter {
    public ClientInfo getReportInformation();

    public void prepare(boolean clean);

    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException;

    public void cleanup(boolean deleteAll);

}
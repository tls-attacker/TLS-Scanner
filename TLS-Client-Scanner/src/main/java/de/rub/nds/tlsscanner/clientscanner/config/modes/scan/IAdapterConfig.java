package de.rub.nds.tlsscanner.clientscanner.config.modes.scan;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;

public interface IAdapterConfig {
    IClientAdapter createClientAdapter();
}

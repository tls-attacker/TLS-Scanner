/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.recon;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.HelloReconProbe.HelloReconResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class SNIProbe extends BaseAnalyzingProbe {

    @Override
    ClientProbeResult analyzeChlo(ClientReport report, HelloReconResult chloResult) {
        ServerNameIndicationExtensionMessage SNI = null;
        for (ExtensionMessage ext : chloResult.chlo.getExtensions()) {
            if (ext instanceof ServerNameIndicationExtensionMessage) {
                SNI = (ServerNameIndicationExtensionMessage) ext;
                break;
            }
        }
        return new SNIProbeResult(SNI != null);
    }

    public static class SNIProbeResult extends ClientProbeResult {
        public final boolean supported;

        public SNIProbeResult(boolean supported) {
            this.supported = supported;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(SNIProbe.class, this);
        }
    }

}
package de.rub.nds.tlsscanner.clientscanner.probe.recon;

import java.util.Collections;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.HelloReconProbe.HelloReconResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class SupportedCipherSuitesProbe extends BaseAnalyzingProbe {

    @Override
    ClientProbeResult analyzeChlo(ClientReport report, HelloReconResult chloResult) {
        return new SupportedCipherSuitesResult(chloResult.state.getTlsContext().getClientSupportedCiphersuites());
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class SupportedCipherSuitesResult extends ClientProbeResult {
        private final List<CipherSuite> supportedSuites;

        public SupportedCipherSuitesResult(List<CipherSuite> supportedSuites) {
            this.supportedSuites = supportedSuites;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(SupportedCipherSuitesProbe.class, this);
        }

        public List<CipherSuite> getSupportedSuites() {
            return Collections.unmodifiableList(supportedSuites);
        }

        public boolean supportsKeyExchangeDHE(boolean tls13, boolean ec, boolean ff) {
            for (CipherSuite cs : supportedSuites) {
                if (tls13 && cs.isTLS13()) {
                    // TODO: need to look at supported groups extension
                    // to determine whether ff or ec (or both)
                    return true;
                } else {
                    if (ff && cs.name().contains("_DHE_")) {
                        return true;
                    }
                    if (ec && cs.name().contains("_ECDHE_")) {
                        return true;
                    }
                }
            }
            return false;
        }

    }

}

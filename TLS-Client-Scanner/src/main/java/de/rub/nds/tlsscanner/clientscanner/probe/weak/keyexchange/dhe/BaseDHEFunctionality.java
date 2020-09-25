package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe.CipherSuiteReconResult;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

class BaseDHEFunctionality {
    private BaseDHEFunctionality() {
        throw new UnsupportedOperationException("Utility class");
    }

    private static List<CipherSuite> dhe_suites;

    static {
        dhe_suites = new LinkedList<>();
        for (CipherSuite cs : CipherSuite.values()) {
            if (cs.isTLS13() || (cs.usesDH() && cs.isEphemeral())) {
                dhe_suites.add(cs);
            }
        }
    }

    public static boolean canBeExecuted(ClientReport report) {
        if (!report.hasResult(CipherSuiteReconProbe.class)) {
            return false;
        }
        CipherSuiteReconResult res = report.getResult(CipherSuiteReconProbe.class, CipherSuiteReconResult.class);
        return res.supportsKeyExchangeDHE();
    }

    public static ClientProbeResult getCouldNotExecuteResult(Class<? extends IProbe> clazz, ClientReport report) {
        if (!report.hasResult(CipherSuiteReconProbe.class)) {
            return new NotExecutedResult(clazz, "Missing result for CipherSuiteReconProbe");
        }
        CipherSuiteReconResult res = report.getResult(CipherSuiteReconProbe.class, CipherSuiteReconResult.class);
        if (!res.supportsKeyExchangeDHE()) {
            return new NotExecutedResult(clazz, "Client does not support DHE");
        }
        return new NotExecutedResult(clazz, "Internal scheduling error");
    }

    public static void prepareConfig(Config config) {
        config.setDefaultServerSupportedCiphersuites(dhe_suites);
        config.setDefaultSelectedCipherSuite(dhe_suites.get(0));
    }

}

package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe.SupportedCipherSuitesResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

class BaseDHEFunctionality {
    private BaseDHEFunctionality() {
        throw new UnsupportedOperationException("Utility class");
    }

    private static List<CipherSuite> ffdhe_suites;
    private static List<CipherSuite> ecdhe_suites;
    private static List<CipherSuite> tls13_suites;

    static {
        ffdhe_suites = new ArrayList<>();
        ecdhe_suites = new ArrayList<>();
        tls13_suites = new ArrayList<>();
        for (CipherSuite cs : CipherSuite.values()) {
            if (cs.isTLS13()) {
                tls13_suites.add(cs);
            } else {
                String n = cs.name();
                if (n.contains("_DHE_")) {
                    ffdhe_suites.add(cs);
                } else if (n.contains("_ECDHE_")) {
                    ecdhe_suites.add(cs);
                }
            }
        }
    }

    public static boolean canBeExecuted(ClientReport report, boolean tls13, boolean ec, boolean ff) {
        if (!report.hasResult(SupportedCipherSuitesProbe.class)) {
            return false;
        }
        SupportedCipherSuitesResult res = report.getResult(SupportedCipherSuitesProbe.class, SupportedCipherSuitesResult.class);
        return res.supportsKeyExchangeDHE(tls13, ec, ff);
    }

    public static ClientProbeResult getCouldNotExecuteResult(Class<? extends IProbe> clazz, ClientReport report, boolean tls13, boolean ec, boolean ff) {
        if (!report.hasResult(SupportedCipherSuitesProbe.class)) {
            return new NotExecutedResult(clazz, "Missing result for CipherSuiteReconProbe");
        }
        SupportedCipherSuitesResult res = report.getResult(SupportedCipherSuitesProbe.class, SupportedCipherSuitesResult.class);
        if (!res.supportsKeyExchangeDHE(tls13, ec, ff)) {
            return new NotExecutedResult(clazz, "Client does not support DHE");
        }
        return new NotExecutedResult(clazz, "Internal scheduling error");
    }

    public static void prepareConfig(Config config, boolean tls13, boolean ec, boolean ff) {
        List<CipherSuite> suites = new ArrayList<>();
        if (ec) {
            suites.addAll(ecdhe_suites);
        }
        if (ff) {
            suites.addAll(ffdhe_suites);
        }
        // if we add tls13 suites first, the ServerHelloPreparator will try to choose
        // these first. But these suites are invalid in 1.2
        if (tls13) {
            suites.addAll(tls13_suites);
        }
        config.setDefaultServerSupportedCiphersuites(suites);
        config.setDefaultSelectedCipherSuite(suites.get(0));
    }

}

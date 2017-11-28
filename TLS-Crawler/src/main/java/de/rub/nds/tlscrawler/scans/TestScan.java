package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.TLSScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;

public class TestScan implements IScan {
    @Override
    public String getName() {
        return "test_scan";
    }

    @Override
    public IScanResult scan(IScanTarget target) {
        ScannerConfig config = new ScannerConfig(new GeneralDelegate());
        config.setThreads(1);

        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);

        TLSScanner scanner = new TLSScanner(config);

        SiteReport report = scanner.scan();

        System.out.println(report.getStringReport());

        IScanResult result = new ScanResult(TestScan.class.getName());
        result.addString("ergebnis", report.getStringReport());
        return result;
    }
}

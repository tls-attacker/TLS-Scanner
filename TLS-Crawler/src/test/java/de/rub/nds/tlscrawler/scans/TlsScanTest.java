package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import org.junit.Test;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class TlsScanTest {

    @Test
    public void ParserTest() {
        SiteReport sr = new SiteReport("local", new LinkedList<ProbeType>(), false);

        HashMap<Integer, List<ResponseFingerprint>> porm = new HashMap<>();
        LinkedList<ResponseFingerprint> rfl = new LinkedList<>();
        rfl.add(new ResponseFingerprint(false, false, 0, 0,
                new LinkedList<>(), new LinkedList<>(), new LinkedList<>(), new LinkedList<>(), SocketState.SOCKET_EXCEPTION));
        porm.put(0, rfl);

        PaddingOracleTestResult potr = new PaddingOracleTestResult(true, ProtocolVersion.SSL2, CipherSuite.GREASE_00,
                PaddingVectorGeneratorType.CLASSIC, PaddingRecordGeneratorType.LONG, porm, EqualityError.ALERT_COUNT);

        List<PaddingOracleTestResult> trl = new LinkedList<PaddingOracleTestResult>();

        trl.add(potr);

        sr.setPaddingOracleTestResultList(trl);

        IScanResult result = new ScanResult("scan");
        result.addString("slaveInstId", "slave");

        TlsScan.populateScanResultFromSiteReport(result, sr);

        new Object();
    }
}

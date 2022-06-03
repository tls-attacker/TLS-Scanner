package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.List;
import java.util.Set;

@SuppressWarnings("unchecked")
public abstract class TlsReport extends ScanReport{

	private static final long serialVersionUID = 3589254912815026376L;
	
	@SuppressWarnings("rawtypes")
	public synchronized List getPaddingOracleTestResultList() {
    	ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_PADDINGORACLE_TESTRESULT);
    	return listResult == null ? null : listResult.getList();
    }
	
    @SuppressWarnings("rawtypes")
	public synchronized List getClientSimulationResultList() {
    	ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_CLIENT_SIMULATION_RESULTS);
    	return listResult == null ? null : listResult.getList();
    }
    
    @SuppressWarnings("rawtypes")
    public synchronized List getCertificateChainList() {
    	ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_CERTIFICATE_CHAINS);
    	return listResult == null ? null : listResult.getList();
    }

	public synchronized Set<CipherSuite> getSupportedCipherSuites() {
        SetResult<?> setResult = getSetResult(TlsAnalyzedProperty.SET_SUPPORTED_CIPHERSUITES);
		return setResult == null ? null : (Set<CipherSuite>) setResult.getSet();
    }
	
    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
    	ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS);
    	return listResult == null ? null : (List<VersionSuiteListPair>) listResult.getList();    
    }
    
    public synchronized List<ProtocolVersion> getSupportedProtocolVersions() {
    	ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS);
    	return listResult == null ? null : (List<ProtocolVersion>) listResult.getList();    
    }
    


}

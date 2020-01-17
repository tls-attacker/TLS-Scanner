/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.config;

import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;

public class ParallelScannerConfig extends TLSDelegateConfig{


    public ParallelScannerConfig(GeneralDelegate delegate) {
		super(delegate);
	}

	@Parameter(names =  {"-d", "--domains"}, required = true, description = "List of domains to scan.")
    private String domainsFileName = null;
	
	@Parameter(names =  {"-s", "--supported-out"}, required = false, description = "Outputlist for domanis with esni support.")
    private String supportingDomainsOutFileName = null;
	
	@Parameter(names = {"-u", "--unsupported-out"}, required = false, description = "Outputlist for domanis without esni support.")
    private String unsupportingDomainsOutFileName = null;
	
	
	@Parameter(names = {"-t","--threads"}, required = false, description = "Number of threads")
	private int threadCount = 1;

	public String getDomainsFileName() {
		return domainsFileName;
	}


	public void setDomainsFileName(String domainsFileName) {
		this.domainsFileName = domainsFileName;
	}
	
	public String getSupportingDomainsOutFileName() {
		return supportingDomainsOutFileName;
	}

	public void setSupportingDomainsOutFileName(String supportingDomainsOutFileName) {
		this.supportingDomainsOutFileName = supportingDomainsOutFileName;
	}


	public String getUnsupportingDomainsOutFileName() {
		return unsupportingDomainsOutFileName;
	}


	public void setUnsupportingDomainsOutFileName(String unsupportingDomainsOutFileName) {
		this.unsupportingDomainsOutFileName = unsupportingDomainsOutFileName;
	}


	public int getThreadCount() {
		return threadCount;
	}


	public void setThreadCount(int threadCount) {
		this.threadCount = threadCount;
	}	

}
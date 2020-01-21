 
/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.tlsscanner.config.ParallelScannerConfig;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;


public class Main{

    private static final Logger LOGGER = LogManager.getLogger();
    private  List<String> domains = new LinkedList();
    private  List<String> esniSupportingDomains= new LinkedList(); 
    private  List<String> esniUnsupportingDomains = new LinkedList();
    
    private  String domainsFileName;
    private  String supportingDomainsOutFileName;
    private  String unsupportingDomainsOutFileName;
    
    public static void main(String[] args) throws IOException {

        ParallelScannerConfig config= new ParallelScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
        	commander.parse(args);            
            
        	if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
        	String domainsFileName = config.getDomainsFileName();
            String supportingDomainsOutFileName= config.getSupportingDomainsOutFileName();
            String unsupportingDomainsOutFileName = config.getUnsupportingDomainsOutFileName();
            int threadCount = config.getThreadCount();
   
            Main main = new Main(domainsFileName,supportingDomainsOutFileName,unsupportingDomainsOutFileName);
            main.scanParallel(threadCount);
            
        } catch (ParameterException e) {
            LOGGER.error("Could not parse provided parameters", e);
            commander.usage();
        }
    }
    
    public Main(String domainsFileName,String supportingDomanisOut, String unsupportingDomanisOut) {
    	this.domainsFileName = domainsFileName;
    	this.supportingDomainsOutFileName  = supportingDomanisOut;
    	this.unsupportingDomainsOutFileName = unsupportingDomanisOut;
    }
        
    
    public void scanParallel(int threadCount) {
    	List<Thread> scanThreads= new ArrayList();	
    	domains = readListFormFile(domainsFileName);  
    	if (domains.isEmpty())
    	{
    		LOGGER.warn("Empty input file.");
    	}
    	else {
    		

    	List<String>[] domainSublists = splitList(domains,threadCount);

    	LOGGER.info("Start scanning with "+ domainSublists.length + " threads.");
    	for (List<String> domainSublist : domainSublists) {
    		scanThreads.add(this.startNewScannerThread(domainSublist));
    	}
        
       	for (Thread job : scanThreads) {
    		try {
				job.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
    	}
    	}
       	if (this.supportingDomainsOutFileName  != null) {
       		writeListToFile(this.supportingDomainsOutFileName , this.esniSupportingDomains);
       	}
       	if (this.unsupportingDomainsOutFileName  != null) {
       		writeListToFile(this.unsupportingDomainsOutFileName , this.esniUnsupportingDomains);
       	}
    }

    private Thread startNewScannerThread(List<String> domainSublist) {
    	Thread thread = new Thread() {
    		  @Override public void run() {
    		    	for ( String domain : domainSublist) {
    		        	ScannerConfig config = new ScannerConfig(new GeneralDelegate());
    		        	TestResult result;
    		        	try {
    		        	TlsScanner scanner = new TlsScanner(config);
    		        	config.getClientDelegate().setHost(domain);
    		        	SiteReport report = scanner.scan();
    		        	result = report.getResult("SUPPORTS_ESNI");
    		        	} catch(TransportHandlerConnectException e) {
    		        		result = TestResult.FALSE;
    		        	}
    		        	wirteResult(domain,result);
    		    	}   
    		  }
    		};
    		thread.start();
    		return thread;
    }  
     
    private synchronized void wirteResult(String domain, TestResult result) {
    	if (result == TestResult.TRUE)
		{
    		esniSupportingDomains.add(domain);
          	 LOGGER.info(domain + ": ESNI support.");
		}else
		{
			esniUnsupportingDomains.add(domain);
			LOGGER.info(domain + ": No ESNI support.");
		}    	
    }
    
    private synchronized List<String>  readListFormFile(String file)  {
    	List<String>  list = new LinkedList();
    	try (BufferedReader br = new BufferedReader(new FileReader(file))) {
    	    String line;
    	    while ((line = br.readLine()) != null) {
    	    	list.add(line);
    	    }
    	}catch(FileNotFoundException e) {
    		ConsoleLogger.CONSOLE.error("No such File.");
    	}catch(IOException e) {
    		ConsoleLogger.CONSOLE.error("Failed to read file.");
    	}
    	return list;
    }
    
    private synchronized void writeListToFile(String file, List<String> list) {
    	try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
    		for(String line : list) {
    			pw.write(line+"\n");
    		}
    	}catch(IOException e) {
    		ConsoleLogger.CONSOLE.error("Failed to write file.");
    	}
    }
    
    private List<String>[] splitList(List<String> list ,int intervalCount){
    	int listLen = list.size();
    	intervalCount = intervalCount < listLen ? intervalCount : listLen;
    	int intervalLen = listLen/intervalCount;
    	List<String>[] subLists = new List[intervalCount];
    	
    	int r = listLen%intervalCount;  	
    	int lower = 0;
    	int upper = 0 + intervalLen + r;
    	subLists[0] = list.subList(lower, upper);
    	
    	for (int i = 1 ; i < intervalCount ; i++) {
    		lower = upper;
    		upper = upper+intervalLen;
    		subLists[i] = list.subList(lower, upper);
    	}
    	return subLists;
    }
}

package de.rub.nds.tlscrawler.samples;


import java.util.HashMap;
import java.util.Map;



public class InvalidCurveReport {

    private String host;

    private Map<String , ParameterSetResult> parameterSetMap;


    public InvalidCurveReport(String host) {
        this.host = host;
        parameterSetMap = new HashMap<>();
    }
    
    public InvalidCurveReport(InvalidCurveReport r) {
        this.host = r.host;
    }
    
    public boolean contradicts(InvalidCurveReport otherReport) {
        for (String otherParameterSet : otherReport.getParameterSetMap().keySet()) {
            for (String myParameterSet : getParameterSetMap().keySet()) {
                if(myParameterSet.equals(otherParameterSet)) {
                    ParameterSetResult otherResult = otherReport.getParameterSetMap().get(otherParameterSet);
                    ParameterSetResult myResult = getParameterSetMap().get(myParameterSet);
                    if(myResult.isShowsNotValidated() != otherResult.isShowsNotValidated()){
                        return true;
                    }
                    else if(!myResult.fingerprintsLookSimialar(otherResult)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * @return the parameterSetMap
     */
    public Map<String , ParameterSetResult> getParameterSetMap() {
        return parameterSetMap;
    }

    /**
     * @param parameterSetMap the parameterSetMap to set
     */
    public void setParameterSetMap(Map<String , ParameterSetResult> parameterSetMap) {
        this.parameterSetMap = parameterSetMap;
    }

    /**
     * @return the host
     */
    public String getHost() {
        return host;
    }

    /**
     * @param host the host to set
     */
    public void setHost(String host) {
        this.host = host;
    }
}

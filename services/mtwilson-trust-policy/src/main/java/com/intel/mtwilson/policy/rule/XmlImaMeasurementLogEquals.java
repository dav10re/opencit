/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.mtwilson.model.Measurement;
import com.intel.mtwilson.model.MeasurementSha1;
import com.intel.mtwilson.model.MeasurementSha256;
import com.intel.mtwilson.model.PcrIndex;
import com.intel.mtwilson.model.XmlImaMeasurementLog;
import com.intel.mtwilson.policy.BaseRule;
import com.intel.mtwilson.policy.HostReport;
import com.intel.mtwilson.policy.RuleResult;
import com.intel.mtwilson.policy.fault.XmlMeasurementLogContainsUnexpectedEntries;
import com.intel.mtwilson.policy.fault.XmlMeasurementLogMissing;
import com.intel.mtwilson.policy.fault.XmlMeasurementLogMissingExpectedEntries;
import com.intel.mtwilson.policy.fault.XmlMeasurementLogValueMismatchEntries;
import com.intel.mtwilson.policy.fault.XmlImaMeasurementLogValueMismatchEntries;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The functionality of this policy is to verify the whitelist ima measurement log against what is provided by the host during host attestation.
 * Need to ensure that there are no additional modules or any modules missing. Also the digest value of all the modules are matching.
 *
 * Sample format of the log would like:
 * <IMA_Measurements xmlns="mtwilson:ima:measurements:1.0" DigestAlg="sha1">
 *      <File Path="/cioa">97639cbf7dccd953de5691c82194b4a1feb6ab16</File>
 *      <File Path="/dh/dgg">04a189508cc2fcbc9a5a87d33909a740433680c3</File>
 *      <File Path="/ye5/gdh/tye3">bd700fb89f1d0314104852708815cb36482447d9</File>
 * </IMA_Measurements>
 *
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class XmlImaMeasurementLogEquals extends BaseRule {
    private Logger log = LoggerFactory.getLogger(getClass());
    private XmlImaMeasurementLog expected;
    private PcrIndex pcrIndex;
    
    protected XmlImaMeasurementLogEquals() {
        this.expected = new XmlImaMeasurementLog(PcrIndex.PCR10);
    } // for desearializing jackson
    
    public XmlImaMeasurementLogEquals(XmlImaMeasurementLog expected) {
        this.expected = expected;
        this.pcrIndex = expected.getPcrIndex();
    }
    
    public PcrIndex getPcrIndex() {
        return this.pcrIndex;
    }
    
    public XmlImaMeasurementLog getXmlImaMeasurementLog() { return expected; }
    
    @Override
    public RuleResult apply(HostReport hostReport) {
        log.debug("XmlImaMeasurementLogEquals: About to apply the XmlImaMeasurementLogEquals policy");
        RuleResult report = new RuleResult(this);
        
        if( hostReport.pcrManifest.getImaMeasurementXml() == null || hostReport.pcrManifest.getImaMeasurementXml().isEmpty()) {
            
            log.debug("XmlImaMeasurementLogEquals: XmlImaMeasurementLog missing fault is being raised.");
            report.fault(new XmlMeasurementLogMissing());
            
        } else {
            // Retrieve the list of (ima) modules as measurements from the XML log provided by the host
            List<Measurement> actualModules = new XmlImaMeasurementLog(expected.getPcrIndex(), hostReport.pcrManifest.getImaMeasurementXml()).getMeasurements();
            log.debug("XmlImaMeasurementLogEquals: About to apply the XmlImaMeasurementLogEquals policy for {} entries.", actualModules.size());
            if( actualModules.isEmpty() ) {
                report.fault(new XmlMeasurementLogMissing());
            }
            else {
                // We will first check if the host provided any additional modules as part of the log
                // hostActualUnexpected = actual modules - expected modules = only extra modules that shouldn't be there;
                // comparison is done BY HASH VALUE,  not by name or any "other info"
                ArrayList<Measurement> hostActualUnexpected = new ArrayList<>(actualModules);
                hostActualUnexpected.removeAll(expected.getMeasurements());
                
                ArrayList<Measurement> hostActualMissing = new ArrayList<>(expected.getMeasurements());
                
                log.debug("XmlImaMeasurementLogEquals: About to check host entries {} against the whitelist which has {} entries.",
                          actualModules.size(), hostActualMissing.size());
                //                log.debug("XmlMeasurementLogEquals: Verifying {} against {}", expected.toString(), actualModules.toString());  //throwing NPE if expected value empty
                hostActualMissing.removeAll(actualModules); // hostActualMissing = expected modules - actual modules = only modules that should be there but aren't
                
                raiseFaultForModifiedEntries(hostActualUnexpected, new ArrayList<>(expected.getMeasurements()), report);
                
                if( !hostActualUnexpected.isEmpty() ) {
                    log.debug("XmlImaMeasurementLogEquals : Host is having #{} additional modules compared to the white list.", hostActualUnexpected.size());
                    report.fault(new XmlMeasurementLogContainsUnexpectedEntries(expected.getPcrIndex(), hostActualUnexpected));
                } else {
                    log.debug("XmlImaMeasurementLogEquals: Host is not having any additional modules compared to the white list");
                }
                
                if( !hostActualMissing.isEmpty() ) {
                    log.debug("XmlImaMeasurementLogEquals : Host is missing #{} modules compared to the white list.", hostActualMissing.size());
                    report.fault(new XmlMeasurementLogMissingExpectedEntries(expected.getPcrIndex(), new HashSet<>(hostActualMissing)));
                } else {
                    log.debug("XmlImaMeasurementLogEquals: Host is not missing any modules compared to the white list");
                }
            }
        }
        return report;
    }
    
    private void raiseFaultForModifiedEntries(ArrayList<Measurement> hostActualUnexpected, ArrayList<Measurement> expectedmeas, RuleResult report) {
        ArrayList<Measurement> hostModifiedModules = new ArrayList<>();
        ArrayList<Measurement> tempHostActualUnexpected = new ArrayList<>(hostActualUnexpected);
        //ArrayList<Measurement> tempHostActualMissing = new ArrayList<>(expectedmeas);
        HashMap<String,Measurement> tempHostActualMissing = new HashMap<String,Measurement>();
        for(Measurement meas: expectedmeas)
            tempHostActualMissing.put(meas.getLabel(), meas);
        
        
        try {
            for (Measurement tempUnexpected : tempHostActualUnexpected) {
                
                /*log.debug("RaiseFaultForModifiedEntries (IMA): Comparing module {} with hash {} to module {} with hash {}.", tempUnexpected.getLabel(),
                 tempUnexpected.getValue().toString(), tempMissing.getLabel(), tempMissing.getValue().toString());*/
                //if (tempUnexpected.getLabel().equalsIgnoreCase(tempMissing.getLabel())) {
                Measurement tempMissing = tempHostActualMissing.get(tempUnexpected.getLabel());
                if(tempMissing != null){
                    log.debug("(IMA) Adding the entry to the list of modified modules and deleting from the other 2 lists.");
                    
                    // We are storing the whitelist value and the actual value so that we do not need to compare again when generating the reports.
                    HashMap<String, String> tempHashMapToAdd = new HashMap<>();
                    tempHashMapToAdd.put("Actual_Value", tempUnexpected.getValue().toString());
                    Measurement measurementToAdd;
                    
                    //This if clause controls that the digest is a SHA1/SHA256 digest even if a IMA digest is always SHA1
                    /*if (Sha256Digest.isValid(tempMissing.getValue().toByteArray())) {
                     measurementToAdd = new MeasurementSha256((Sha256Digest)tempMissing.getValue(), tempMissing.getLabel(), tempHashMapToAdd);
                     } else {*/
                    measurementToAdd = new MeasurementSha1((Sha1Digest)tempMissing.getValue(), tempMissing.getLabel(), tempHashMapToAdd);
                    //}
                    
                    hostModifiedModules.add(measurementToAdd);
                    hostActualUnexpected.remove(tempUnexpected);
                    
                    //hostActualMissing.remove(tempMissing);
                }
                //}
            }
            
            if (!hostModifiedModules.isEmpty()) {
                log.debug("XmlImaMeasurementLogEquals : Host has updated #{} modules compared to the white list.", hostModifiedModules.size());
                
                //report.fault(new XmlMeasurementLogValueMismatchEntries(expected.getPcrIndex(), new HashSet<>(hostModifiedModules)));   //original
                
                report.fault(new XmlImaMeasurementLogValueMismatchEntries(expected.getPcrIndex(), new ArrayList<>(hostModifiedModules)));
            } else {
                log.debug("RaiseFaultForModifiedEntries (IMA): No updated modules found.");
            }
            
        } catch (Exception ex) {
            log.error("RaiseFaultForModifiedEntries (IMA): Error during verification of changed modules.", ex);
        }
    }
}




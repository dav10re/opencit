/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.dcsg.cpg.crypto.AbstractDigest;
import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.mtwilson.model.Measurement;
import com.intel.mtwilson.model.PcrIndex;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.digest.Digest;
import com.intel.mtwilson.model.XmlImaMeasurementLog;
import com.intel.mtwilson.policy.BaseRule;
import com.intel.mtwilson.policy.HostReport;
import com.intel.mtwilson.policy.RuleResult;
import com.intel.mtwilson.policy.fault.XmlMeasurementLogMissing;
import com.intel.mtwilson.policy.fault.XmlMeasurementValueMismatch;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This policy verifies the integrity of the ima measurement log provided by the host. It does
 * this integrity verification by calculating the expected final hash value by extending
 * all the modules measured in the exact same order and comparing it with the module in the quote
 * (Remeber for IMA it is useless to have a whitelist value of PCR 10)
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class XmlImaMeasurementLogIntegrity extends BaseRule {
    private Logger log = LoggerFactory.getLogger(getClass());

    private String expectedValue;
    private PcrIndex pcrIndex;
    
    protected XmlImaMeasurementLogIntegrity() { } // for desearializing jackson
    
    public XmlImaMeasurementLogIntegrity(String expectedValue, PcrIndex pcrIndex) {
        this.expectedValue = expectedValue;
        this.pcrIndex = pcrIndex;
    }
    
    public String getExpectedValue() { return expectedValue; }
    
    //Set the expected value got from the quote
    public void setExpectedValue(HostReport hostReport) {
        DigestAlgorithm digestAl = DigestAlgorithm.SHA1;
        
        //Get the PCR 10 from the quote
        this.expectedValue = hostReport.pcrManifest.getPcrs(digestAl).get(10).getValue().toString();
        
    }

    public PcrIndex getPcrIndex() {
        return pcrIndex;
    }
    

    @Override
    public RuleResult apply(HostReport hostReport) {
        
        setExpectedValue(hostReport);
        log.debug("XmlImaMeasurementLogIntegrity: setting the expected value got from the quote: {}",expectedValue);

        
        log.debug("XmlImaMeasurementLogIntegrity: About to apply the XmlImaMeasurementLogIntegrity policy");
        RuleResult report = new RuleResult(this);
        if( hostReport.pcrManifest.getImaMeasurementXml() == null || hostReport.pcrManifest.getImaMeasurementXml().isEmpty()) {
            
            log.debug("XmlImaMeasurementLogIntegrity: XmlMeasurementLog missing fault is being raised.");
            report.fault(new XmlMeasurementLogMissing());
            
        } else {

            List<Measurement> measurements = new XmlImaMeasurementLog(this.pcrIndex, hostReport.pcrManifest.getImaMeasurementXml()).getMeasurements();
            log.debug("XmlImaMeasurementLogIntegrity: Retrieved #{} of measurements from the log.", measurements.size());
            if( measurements.size() > 0 ) {
                DigestAlgorithm finalDigestAlgorithm = DigestAlgorithm.SHA1;
                AbstractDigest expectedValueDigest;
                AbstractDigest actualValue = computeHistory(measurements); // calculate expected' based on history
                if (Sha1Digest.isValidHex(expectedValue)) {
                    expectedValueDigest = Sha1Digest.valueOfHex(expectedValue);
                } else {
                    expectedValueDigest = Sha256Digest.valueOfHex(expectedValue);
                }
                // for linux TPM 1.2 and windows, module digest is SHA1, so take the SHA1 of the actual SHA256 value for comparison
                if (Sha1Digest.isValidHex(expectedValue) && Sha256Digest.isValid(actualValue.toByteArray())) {
                    log.debug("(IMA?) XmlMeasurementLogIntegrity: Expected value [{}] is SHA1, taking SHA1 digest of SHA256 actual value [{}] with byte length [{}]", expectedValueDigest.toString(), actualValue.toHexString(), actualValue.toByteArray().length);
                    actualValue = Sha1Digest.valueOf(Digest.sha1().digestHex(actualValue.toHexString()).getBytes());
                    finalDigestAlgorithm = DigestAlgorithm.SHA1;
                }
                log.debug("XmlImaMeasurementLogIntegrity: About to verify the calculated final hash {} with expected hash {}", actualValue.toString(), expectedValueDigest.toString());
                // make sure the expected pcr value matches the actual pcr value
                if( !expectedValueDigest.equals(actualValue) ) {
                    log.info("XmlImaMeasurementLogIntegrity: Mismatch in the expected final hash value for the XML Measurement log.");
                    report.fault(XmlMeasurementValueMismatch.newInstance(finalDigestAlgorithm, expectedValueDigest, actualValue));
                } else {
                    log.debug("Verified the integrity of the XML IMA measurement log successfully.");
                }
            }
        }
        return report;
    }
    
    private Sha1Digest computeHistory(List<Measurement> list) {
        // start with a default value of zero...  that should be the initial value of every PCR ..  if a pcr is reset after boot the tpm usually sets its starting value at -1 so the end result is different , which we could then catch here when the hashes don't match        
            Sha1Digest result = Sha1Digest.ZERO;
            for (Measurement m : list) {
                //result = result.extend(m.getValue().toString().getBytes());
                if (m.getValue() != null && m.getValue().toString() != null) {
                    log.debug("XmlImaMeasurementLogIntegrity-computeHistory: Extending value [{}] to current value [{}]", m.getValue().toString(), result.toString());
                    result = result.extend(Sha1Digest.valueOfHex(m.getValue().toString()));
                }
            }
            return result;     
    }
}

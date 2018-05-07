/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.policy.impl.vendor;

import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.model.Bios;
import com.intel.mtwilson.model.Vmm;
import com.intel.mtwilson.policy.Rule;
import com.intel.mtwilson.policy.impl.JpaPolicyReader;
import com.intel.mtwilson.policy.impl.TrustMarker;
import com.intel.mtwilson.policy.rule.AikCertificateTrusted;
import com.intel.mtwilson.policy.rule.PcrMatchesConstant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 *
 * @author dczech
 */
public class IntelTpmDaHostTrustPolicyFactory extends IntelHostTrustPolicyFactory {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(IntelTpmDaHostTrustPolicyFactory.class);
    
    public IntelTpmDaHostTrustPolicyFactory(JpaPolicyReader util) {
        super(util);
    }
    
    @Override
    public Set<Rule> loadTrustRulesForBios(Bios bios, TblHosts host) {
        if (cacerts == null) {
            cacerts = loadTrustedAikCertificateAuthorities();
        }
        HashSet<Rule> rules = new HashSet<>();
        AikCertificateTrusted aikcert = new AikCertificateTrusted(cacerts);
        aikcert.setMarkers(TrustMarker.BIOS.name());
        rules.add(aikcert);
        // first add all the constant rules. EventLog dynamic PCRs will be blank in the whitelist db, and won't be added to the Set
        Set<Rule> pcrConstantRules = reader.loadPcrMatchesConstantRulesForBios(bios, host);
        
        for(Iterator<Rule> it = pcrConstantRules.iterator(); it.hasNext();) {
            PcrMatchesConstant r = (PcrMatchesConstant)it.next();
            
            //----------- Added by dav10re ------------
            //Only for debug
            
            log.debug("PcrConstantRules created for BIOS: rule with pcr {}", r.getExpectedPcr().toString());
            
            //-----------------------------------------
            
            if(r.getExpectedPcr().getPcrBank() != DigestAlgorithm.valueOf(host.getPcrBank())) {
                it.remove();
                
                //---------- Added by dav10re -----------
                
                log.debug("PcrConstantRules removed rule for BIOS: rule with pcr {}", r.getExpectedPcr().toString());
                
                //---------------------------------------
            }            
        }
        
        rules.addAll(pcrConstantRules);
        
        if(host.getBiosMleId().getRequiredManifestList().contains("17")) {
            // 17 is a host specific PCR TPM DA Mode
            Set<Rule> pcrEventRules = reader.loadPcrEventLogIncludesRuleForBiosDaMode(bios, host);
            rules.addAll(pcrEventRules);
        }
        return rules;
    }
    
    @Override
    public Set<Rule> loadComparisonRulesForVmm(Vmm vmm, TblHosts host) {
        HashSet<Rule> rules = new HashSet<>();
        
        Set<Rule> pcrConstantRules = reader.loadPcrMatchesConstantRulesForVmm(vmm, host);
        
        for (Iterator<Rule> it = pcrConstantRules.iterator(); it.hasNext();) {
            PcrMatchesConstant r = (PcrMatchesConstant) it.next();
            
            //----------- Added by dav10re ------------
            //Only for debug
            
            log.debug("PcrConstantRules created for VMM: rule with pcr {}", r.getExpectedPcr().toString());
            
            /* The following if will remove the rule for pcr 10 because it doesn't have a sha256 value (the best bank for the host is sha256)*/
            
            //The original if clause
            
             
             if (r.getExpectedPcr().getPcrBank() != DigestAlgorithm.valueOf(host.getPcrBank())) {
             it.remove();
             
             
            
            //if there is the pcr 10, do not remove the PcrConstantRule
            
            /*if (r.getExpectedPcr().getPcrBank() != DigestAlgorithm.valueOf(host.getPcrBank()) && !r.getExpectedPcr().getIndex().toString().equals("10")) {
                it.remove();
            */
            //-----------------------------------------
                
            } else {
                log.debug("IntelTpmDaHostTrustPolicyFactory: PcrMatchesConstant rule added for [{}] with measurement [{}]", r.getExpectedPcr().getIndex().toString(), r.getExpectedPcr().getValue().toHexString());
            }
        }
        
        rules.addAll(pcrConstantRules);
        
        if(host.getVmmMleId().getRequiredManifestList().contains("17") || host.getVmmMleId().getRequiredManifestList().contains("19")) {
            Set<Rule> pcrEventLogRules = reader.loadPcrEventLogIncludesRuleForVmmDaMode(vmm,host);
            rules.addAll(pcrEventLogRules);
        }
        // Next we need to add all the modules
        if( host.getVmmMleId().getRequiredManifestList().contains("19") ) {
            // Add rules to verify the meaurement log which would contain modules for attesting application/data
            Set<Rule> xmlMeasurementLogRules = reader.loadXmlMeasurementLogRuleForVmm(vmm, host);
            rules.addAll(xmlMeasurementLogRules);
        }
        
        
        //------------ Added by dav10re -----------------
        
        if( host.getVmmMleId().getRequiredManifestList().contains("10") ) {
            
            // Add rules to verify the ima meaurement log
            
            Set<Rule> xmlImaMeasurementLogRules = reader.loadXmlImaMeasurementLogRuleForVmm(vmm, host);
            rules.addAll(xmlImaMeasurementLogRules);
        }
        
        
        //-----------------------------------------------
        
        return rules;
    }
    
    @Override
    public Set<Rule> loadTrustRulesForVmm(Vmm vmm, TblHosts host) {
        return loadComparisonRulesForVmm(vmm, host);
    }
}

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.tag.rest.v2.repository;

import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.intel.mtwilson.jaxrs2.server.resource.DocumentRepository;
import com.intel.mtwilson.tag.common.Global;
import com.intel.mtwilson.tag.model.HostUuid;
import com.intel.mtwilson.tag.model.HostUuidCollection;
import com.intel.mtwilson.tag.model.HostUuidFilterCriteria;
import com.intel.mtwilson.tag.model.HostUuidLocator;
import java.util.List;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author ssbangal
 */
public class HostUuidRepository implements DocumentRepository<HostUuid, HostUuidCollection, HostUuidFilterCriteria, HostUuidLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(HostUuidRepository.class);
    

    @Override
    @RequiresPermissions("host_uuids:search")         
    public HostUuidCollection search(HostUuidFilterCriteria criteria) {
        HostUuidCollection objCollection = new HostUuidCollection();
        log.debug("HostUuid:Search - Got request to search for the host UUID.");  
        try {
            String ip = criteria.hostId;
            List<TxtHostRecord> hostList = Global.mtwilson().queryForHosts(ip,true);
            if(hostList == null || hostList.size() < 1) {
                log.debug("host uuid didn't return back any results");
                throw new Exception("No host records found");
            }
            log.debug("Search for host uuid returned " + hostList.get(0).Hardware_Uuid);
            HostUuid obj = new HostUuid();
            obj.setHardwareUuid(hostList.get(0).Hardware_Uuid);
            objCollection.getHostUuids().add(obj);
        } catch (WebApplicationException aex) {
            throw aex;            
        } catch (Exception ex) {
            log.error("Error during search for host hardware uuid.", ex);
            throw new WebApplicationException("Please see the server log for more details.", Response.Status.INTERNAL_SERVER_ERROR);
        }        
        return objCollection;
    }

    @Override
    @RequiresPermissions("host_uuids:retrieve")         
    public HostUuid retrieve(HostUuidLocator locator) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    @RequiresPermissions("host_uuids:store")         
    public void store(HostUuid item) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    @RequiresPermissions("host_uuids:create")         
    public void create(HostUuid item) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    @RequiresPermissions("host_uuids:delete")         
    public void delete(HostUuidLocator locator) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    @Override
    @RequiresPermissions("host_uuids:delete,search")         
    public void delete(HostUuidFilterCriteria criteria) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
        
}

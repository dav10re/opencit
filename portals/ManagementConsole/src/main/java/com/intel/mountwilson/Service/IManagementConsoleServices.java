/**
 * 
 */
package com.intel.mountwilson.Service;

import java.util.List;

import com.intel.mountwilson.common.ManagementConsolePortalException;
import com.intel.mountwilson.datamodel.ApiClientListType;
import com.intel.mountwilson.datamodel.HostDetails;
import com.intel.mountwilson.datamodel.ApiClientDetails;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.datatypes.HostConfigData;
import com.intel.mtwilson.datatypes.HostConfigDataList;
import com.intel.mtwilson.datatypes.HostConfigResponseList;
import com.intel.mtwilson.datatypes.Role;

/**
 * @author yuvrajsx
 *
 */
public interface IManagementConsoleServices {
	
        public boolean saveWhiteListConfiguration(HostDetails hostDetailsObj,HostConfigData hostConfig, ApiClient apiObj) throws ManagementConsolePortalException;

        public List<HostDetails> getHostEntryFromVMWareCluster(String clusterName,String vCenterConnection)throws ManagementConsolePortalException;

        public HostDetails registerNewHost(HostDetails hostDetailList, ApiClient apiObj)throws ManagementConsolePortalException;

        //public HostDetails updateRegisteredHost(HostDetails hostDetailList, ApiClient apiObj)throws ManagementConsolePortalException;

        public boolean deleteSelectedRequest(String fingerprint, ApiClient apiObj)throws ManagementConsolePortalException;

        public Role[] getAllRoles(ApiClient apiObj) throws ManagementConsolePortalException;
                
        public List<ApiClientDetails> getApiClients(ApiClient apiObj, ApiClientListType apiType )throws ManagementConsolePortalException;

        public List<ApiClientDetails> getCADetails(ApiClient apiObj)throws ManagementConsolePortalException;
    
        public boolean updateRequest(ApiClientDetails apiClientDetailsObj, ApiClient apiObj, boolean approve) throws ManagementConsolePortalException;
        
        public HostConfigResponseList registerHosts(ApiClient apiObj, List<HostDetails> hostRecords) throws ManagementConsolePortalException;

}

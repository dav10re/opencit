#!/bin/bash
#
# chkconfig: 2345 80 30
# description: Intel TrustAgent Service
#

###################################################################################################
#Set environment specific variables here 
###################################################################################################


java_required_version=1.7.0_51

###################################################################################################

script_name=tagent
intel_conf_dir=/etc/intel/cloudsecurity
package_name=trustagent
package_dir=/opt/intel/cloudsecurity/${package_name}
package_config_filename=${intel_conf_dir}/${package_name}.properties
package_env_filename=${package_dir}/${package_name}.env
package_install_filename=${package_dir}/${package_name}.install

# FUNCTION LIBRARY, VERSION INFORMATION, and LOCAL CONFIGURATION
if [ -f "${package_dir}/functions" ]; then . "${package_dir}/functions"; else echo "Missing file: ${package_dir}/functions"; exit 1; fi
if [ -f "${package_dir}/version" ]; then . "${package_dir}/version"; else echo_warning "Missing file: ${package_dir}/version"; fi
load_conf 2>&1 >/dev/null
load_defaults 2>&1 >/dev/null


# the install file should define TRUST_AGENT_HOME
# the env file should define JAVA_HOME (like /usr/local/jdk1.7.0_51) and java  ($JAVA_HOME/bin/java)
function read_local_config() {
    shell_include_files "${package_env_filename}" "${package_install_filename}"

    serviceNameLo="tagent"                                  # service name with the first letter in lowercase
    serviceName="Trust Agent"                                    # service name
    serviceUser="root"                                      # OS user name for the service
    serviceGroup="root"                                    # OS group name for the service
    CLASSPATH=$TRUST_AGENT_HOME/lib/TrustAgent.jar
    serviceUserHome="/home/$serviceUser"                       # home directory of the service user
    serviceLogFile="/var/log/$serviceNameLo.log"               # log file for StdOut/StdErr
    maxShutdownTime=15                                         # maximum number of seconds to wait for the daemon to terminate normally
    pidFile="/var/run/$serviceNameLo.pid"                      # name of PID file (PID = process ID number)
    storePass="$TRUSTAGENT_KEYSTORE_PASS"   #`read_property_from_file trustagent.keystore.password "${package_config_filename}"`
    export TaKeyStorePassword=$storePass
    javaVMArgs="-Djavax.net.ssl.trustStore=$intel_conf_dir/trustagent.jks -Djavax.net.ssl.keyStore=$intel_conf_dir/trustagent.jks -Djavax.net.ssl.keyStorePassword=env:TaKeyStorePassword -Dapp.path=$package_dir -Ddebug=true"  # arguments for Java launcher
    javaArgs="-classpath $CLASSPATH com.intel.mountwilson.trustagent.TASecureServer"  # arguments for Java launcher
    javaCommandLine="$java $javaVMArgs  $javaArgs"                       # command line to start the Java service application
    javaCommandLineKeyword="TrustAgent.jar"                   # a keyword that occurs on the commandline, used to detect an already running service process and to distinguish it from others
}

read_local_config



# Makes the file $1 writable by the group $serviceGroup.
function makeFileWritable {
   local filename="$1"
   touch $filename || return 1
   chgrp $serviceGroup $filename || return 1
   chmod g+w $filename || return 1
   return 0; }
 
# Returns 0 if the process with PID $1 is running.
function checkProcessIsRunning {
   local pid="$1"
   if [ -z "$pid" -o "$pid" == " " ]; then return 1; fi
   if [ ! -e /proc/$pid ]; then return 1; fi
   return 0; }
 
# Returns 0 if the process with PID $1 is our Java service process.
function checkProcessIsOurService {
   local pid="$1"
#   if [ "$(ps -p $pid --no-headers -o comm)" != "$javaCommand" ]; then return 1; fi
#   grep -q --binary -F "$javaCommandLineKeyword" /proc/$pid/cmdline
#   if [ $? -ne 0 ]; then return 1; fi
   isTrustAgent=`ps -p $pid -o cmd | grep "$javaCommandLineKeyword" | wc -l`
   if [ "$isTrustAgent" == "0" ]; then return 1; fi
   return 0; }

# Returns 0 when the service is running and sets the variable $pid to the PID.
function getServicePID {
   if [ ! -f $pidFile ]; then return 1; fi
   pid="$(<$pidFile)"
   echo $pid 
   checkProcessIsRunning $pid || return 1
   checkProcessIsOurService $pid || return 1
   return 0; }
 
function startServiceProcess {
   cd $package_dir || return 1
   rm -f $pidFile
   read_local_config
   makeFileWritable $pidFile || return 1
   makeFileWritable $serviceLogFile || return 1
   cmd="nohup $javaCommandLine >>$serviceLogFile 2>&1 & echo \$! >$pidFile"

   su -m $serviceUser -s $SHELL -c "$cmd" || return 1
   sleep 0.1
   pid="$(<$pidFile)"
   if checkProcessIsRunning $pid; then :; else
      echo
      echo "$serviceName start failed, see logfile $serviceLogFile"
      return 1
   fi
   return 0; }
 
function stopServiceProcess {
   kill $pid || return 1
   for ((i=0; i<maxShutdownTime*10; i++)); do
      checkProcessIsRunning $pid
      if [ $? -ne 0 ]; then
         rm -f $pidFile
         return 0
         fi
      sleep 0.1
      done
   echo "$serviceName did not terminate within $maxShutdownTime seconds, sending SIGKILL..."
   kill -s KILL $pid || return 1
   local killWaitTime=15
   for ((i=0; i<killWaitTime*10; i++)); do
      checkProcessIsRunning $pid
      if [ $? -ne 0 ]; then
         rm -f $pidFile
         return 0
         fi
      sleep 0.1
      done
   echo "Error: $serviceName could not be stopped within $maxShutdownTime+$killWaitTime seconds!"
   return 1; }
 
function startService {
   tcsd
    if [ -z "$java" ]; then
        if [ ! -f "${package_env_filename}" ]; then
          setup_env > "${package_env_filename}"
        fi
        . "${package_env_filename}"
        read_local_config
    fi
    if no_java $java_required_version; then echo "Cannot find Java $java_required_version or later"; exit 1; fi

   # make sure we have files from privacy ca
   report_files_exist /etc/intel/cloudsecurity/PrivacyCA.cer /etc/intel/cloudsecurity/hisprovisioner.properties
   if [ $? -ne 0 ]; then
     echo_failure "Privacy CA files are missing"
     return 1
   fi

   # take ownership if not taken
   tpm_owned=`cat /sys/class/misc/tpm0/device/owned`
   if [[ "${tpm_owned}" == "0" ]]; then
     $java -cp $CLASSPATH -DforceCreateEk=true com.intel.mountwilson.trustagent.commands.TakeOwnershipCmd
   fi

   getServicePID
   if [ $? -eq 0 ]; then echo "$serviceName is already running"; RETVAL=0; return 0; fi
   echo -n "Starting $serviceName   "
   startServiceProcess
   if [ $? -ne 0 ]; then RETVAL=1; echo "failed"; return 1; fi
   echo "started PID=$pid"
   RETVAL=0
   return 0; }
 
function stopService {
   getServicePID
   if [ $? -ne 0 ]; then echo "$serviceName is not running"; RETVAL=0; echo ""; return 0; fi
   echo -n "Stopping $serviceName   "
   stopServiceProcess
   if [ $? -ne 0 ]; then RETVAL=1; echo "failed"; return 1; fi
   echo "stopped PID=$pid"
   RETVAL=0
   return 0; }
 
function checkServiceStatus {
    TRUST_AGENT_RUNNING=""
   echo -n "Checking for $serviceName:   "
   if getServicePID; then
    TRUST_AGENT_RUNNING="$pid"
    echo "Running (PID=$pid)"
    RETVAL=0
   else
    echo "Stopped"
    RETVAL=3
   fi
   return 0;
}

setup_env() {
  yum_detect > /dev/null
  java_detect > /dev/null
  local datestr=`date +%Y-%m-%d.%H%M`
  echo "# environment on ${datestr}"
  echo "JAVA_HOME=$JAVA_HOME"
  echo "java=$java"
}

setup() {
  # bug #492 if a jdk/jre was already configured, we need to leave it alone because it may have customized security policy to allow bouncycastle
  read_local_config
  if no_java $java_required_version; then echo "Cannot find Java $java_required_version or later"; exit 1; fi
  yum_detect > /dev/null
  # create the env file first because pcakey in the interactive install depends on it
  setup_env > "${package_env_filename}"
  . "${package_env_filename}"
  read_local_config
  setup_interactive_install
}
   
setup_print_summary() {
  echo "Requirements summary:"
  if [ -n "$JAVA_HOME" ]; then
    echo "Java: $JAVA_VERSION"
  else
    echo "Java: not found"
  fi
}

setup_interactive_install() {
    # Java installation is now a pre-requisite to trust agent setup 
    # and it is installed by the trust agent install script. 
    if [ -n "$JAVA_HOME" ]; then
	checkServiceStatus
	if [ -z "$TRUST_AGENT_RUNNING" ]; then
	    stopService
        fi
        # This is the place to do any setup while trust agent is not running
        /usr/local/bin/pcakey
        if [ $? == 1 ]; then exit 1; fi
        $java -cp $CLASSPATH -DforceCreateEk=true com.intel.mountwilson.trustagent.commands.TakeOwnershipCmd 2>&1 >/dev/null
        # After setup is done, start the trust agent:
	checkServiceStatus
	if [ -z "$TRUST_AGENT_RUNNING" ]; then
	    startService
	fi
    fi
}

function main {
   RETVAL=0
   case "$1" in
      version)
        echo "${package_name}"
	echo "Version ${VERSION:-Unknown}"
	echo "Build ${BUILD:-Unknown}"
        ;;
      start)                                               # starts the Java program as a Linux service
         startService
         ;;
      stop)                                                # stops the Java program service
         stopService
         ;;
      restart)                                             # stops and restarts the service
         stopService && startService
         ;;
      status)                                              # displays the service status
         checkServiceStatus
         ;;
      setup)                                               # completes service setup
         setup
         ;;
  edit)
        update_property_in_file "${2}" "${package_config_filename}" "${3}"
       ;;
  show)
        read_property_from_file "${2}" "${package_config_filename}"
        ;;
  fixek)
        java_detect > /dev/null
        if no_java $java_required_version; then echo "Cannot find Java $java_required_version or later"; exit 1; fi
        stopService
        pcakey
        $java -cp $CLASSPATH -DforceCreateEk=true com.intel.mountwilson.trustagent.commands.TakeOwnershipCmd
        startService
        ;;
  newid)
        java_detect > /dev/null
        if no_java $java_required_version; then echo "Cannot find Java $java_required_version or later"; exit 1; fi
        stopService
        if [ -f "$intel_conf_dir/cert/aikblob.dat" ]; then
          backup_file "$intel_conf_dir/cert/aikblob.dat"
          rm "$intel_conf_dir/cert/aikblob.dat"
        fi
        if [ -f "$intel_conf_dir/cert/aikcert.pem" ]; then
          backup_file "$intel_conf_dir/cert/aikcert.pem"
          rm "$intel_conf_dir/cert/aikcert.pem"
        fi
        pcakey
        $java -cp $CLASSPATH $javaVMArgs -DforceCreateEk=true com.intel.mountwilson.trustagent.commands.CreateIdentityCmd
        startService
        ;;
  tpmstatus)
        tpm_owned=`cat /sys/class/misc/tpm0/device/owned`
        tpm_enabled=`cat /sys/class/misc/tpm0/device/enabled`
        tpm_pcrs=`cat /sys/class/misc/tpm0/device/pcrs`
        if [[ "${tpm_owned}" == "1" ]]; then
          echo_success "TPM is owned"
        else
          echo_warning "TPM is not owned"
        fi
        if [[ "${tpm_enabled}" == "1" ]]; then
          echo_success "TPM is enabled"
        else
          echo_warning "TPM is not enabled"
        fi
        echo "${tpm_pcrs}"
        ;;
  uninstall)
        stopService
        datestr=`date +%Y-%m-%d.%H%M`
        mkdir -p "${intel_conf_dir}"
        cp "${package_config_filename}" "${intel_conf_dir}"/${package_name}.properties.${datestr}
        echo "Saved configuration file in ${intel_conf_dir}/${package_name}.properties.${datestr}"
        # prevent disaster by ensuring that package_dir is inside /opt/intel
        if [[ "${package_dir}" == /opt/intel/* ]]; then
          rm -rf "${package_dir}"
        fi
	rm /usr/local/bin/${script_name}
        rm -fr /etc/monit/monitrc
	echo "Stopping Monit service..."
	service monit stop &> /dev/null
	if [ -f /etc/monit/monitrc ]; then
	 #remove monit config so when it starts back up it has nothing to monitor
	 # idealy here we should be uninstalling instead
	 rm -fr /etc/monit/monitrc
        fi
        ;;
      *)
         echo "Usage: $0 {version|restart|setup|edit|show|fixek|newid|tpmstatus|uninstall}"
         exit 1
         ;;
      esac
   exit $RETVAL
}
 
main $1
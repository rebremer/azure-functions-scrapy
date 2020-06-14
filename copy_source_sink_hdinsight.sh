#! /bin/bash

usage() {
    echo ""
    echo "Usage: sudo -E bash add-storage-account.sh <storage-account-name> <storage-account-key> [-p]" ;
	echo "If -p option is specified, then storage account key will be stored in plain text. Otherwise, it will be encrypted."
    echo "This script does NOT require Ambari username and password";
    exit 132;
}

#validate user input
if [ -z "$1" ]
    then
        usage
        echo "Source storage account name must be provided."
        exit 133
fi

if [ -z "$2" ]
    then
        usage
        echo "Source account key must be provided."
        exit 134
fi

if [ -z "$3" ]
    then
        usage
        echo "Source account container must be provided."
        exit 135
fi

if [ -z "$4" ]
    then
        usage
        echo "Sink storage account name must be provided."
        exit 136
fi

if [ -z "$5" ]
    then
        usage
        echo "Sink account key must be provided."
        exit 137
fi

if [ -z "$6" ]
    then
        usage
        echo "Sink account container must be provided."
        exit 138
fi


DISABLEENCRYPTION=false

STORAGEACCOUNTNAME_SOURCE=$1
if [[ $1 == *blob.core.windows.net* ]]; then
    echo "Extracting storage account name from $1"
    STORAGEACCOUNTNAME_SOURCE=$(echo $1 | cut -d'.' -f 1)
fi
echo STORAGE ACCOUNT IS: $STORAGEACCOUNTNAME_SOURCE

STORAGEACCOUNTKEY_SOURCE=$2
STORAGEACCOUNTCONTAINER_SOURCE=$3

STORAGEACCOUNTNAME_SINK=$4
if [[ $4 == *blob.core.windows.net* ]]; then
    echo "Extracting storage account name from $4"
    STORAGEACCOUNTNAME_SINK=$(echo $4 | cut -d'.' -f 1)
fi
echo STORAGE ACCOUNT IS: $STORAGEACCOUNTNAME_SINK

STORAGEACCOUNTKEY_SINK=$5
STORAGEACCOUNTCONTAINER_SINK=$6

#validate storage account credentials SOURCE
echo "Validate storage account creds:"
CREDS_VALIDATION=$(echo -e "from azure.storage.blob import BlobService\nvalid=True\ntry:\n\tblob_service = BlobService(account_name='$STORAGEACCOUNTNAME_SOURCE', account_key='$STORAGEACCOUNTKEY_SOURCE')\n\tblob_service.get_blob_service_properties()\nexcept Exception as e:\n\tvalid=False\nprint valid"| sudo python)
if [[ $CREDS_VALIDATION == "False" ]]; then
    echo "Invalid Credentials provided for storage account source"
    exit 139
else
    echo "Successfully validated storage account source credentials."
fi

#validate storage account credentials SINK
echo "Validate storage account creds:"
CREDS_VALIDATION=$(echo -e "from azure.storage.blob import BlobService\nvalid=True\ntry:\n\tblob_service = BlobService(account_name='$STORAGEACCOUNTNAME_SINK', account_key='$STORAGEACCOUNTKEY_SINK')\n\tblob_service.get_blob_service_properties()\nexcept Exception as e:\n\tvalid=False\nprint valid"| sudo python)
if [[ $CREDS_VALIDATION == "False" ]]; then
    echo "Invalid Credentials provided for storage account sink"
    exit 140
else
    echo "Successfully validated storage account sink credentials."
fi


AMBARICONFIGS_PY=/var/lib/ambari-server/resources/scripts/configs.py
PORT=8080

ACTIVEAMBARIHOST=headnodehost

#Import helper module
wget -O /tmp/HDInsightUtilities-v01.sh -q https://hdiconfigactions.blob.core.windows.net/linuxconfigactionmodulev01/HDInsightUtilities-v01.sh && source /tmp/HDInsightUtilities-v01.sh && rm -f /tmp/HDInsightUtilities-v01.sh

checkHostNameAndSetClusterName() {
	PRIMARYHEADNODE=`get_primary_headnode`
    
	#Check if values retrieved are empty, if yes, exit with error
	if [[ -z $PRIMARYHEADNODE ]]; then
	echo "Could not determine primary headnode."
	exit 141
	fi

	fullHostName=$(hostname -f)
    echo "fullHostName=$fullHostName. Lower case: ${fullHostName,,}"
    echo "primary headnode=$PRIMARYHEADNODE. Lower case: ${PRIMARYHEADNODE,,}"
    if [ "${fullHostName,,}" != "${PRIMARYHEADNODE,,}" ]; then
        echo "$fullHostName is not primary headnode. This script has to be run on $PRIMARYHEADNODE."
        exit 0
    fi
    CLUSTERNAME=$(sed -n -e 's/.*\.\(.*\)-ssh.*/\1/p' <<< $fullHostName)
    if [ -z "$CLUSTERNAME" ]; then
        CLUSTERNAME=$(echo -e "import hdinsight_common.ClusterManifestParser as ClusterManifestParser\nprint ClusterManifestParser.parse_local_manifest().deployment.cluster_name" | python)
        if [ $? -ne 0 ]; then
            echo "[ERROR] Cannot determine cluster name. Exiting!"
            exit 142
        fi
    fi
    echo "Cluster Name=$CLUSTERNAME"
}


checkHostNameAndSetClusterName

if [ "$DISABLEENCRYPTION" == true ]; then
	echo "Encryption is disabled. No changes will be made to storage account key."
	KEYPROVIDER=SimpleKeyProvider
else
	#Encrypt storage account key
	KEYPROVIDER=ShellDecryptionKeyProvider
	echo "Encrypting storage account key"

	echo "Getting encryption cert"
	for cert in `sudo ls /var/lib/waagent/*.crt`
	do
		SUBJECT=`sudo openssl x509 -in $cert -noout -subject`
		if [[ $SUBJECT == *"cluster-$CLUSTERNAME-"* ]]; then
				CERT=$cert
				break
		fi
	done

	if [ -z "$CERT" ];then
		echo "Could not locate cert for encryption"
		exit 143
	fi

	echo $STORAGEACCOUNTKEY_SOURCE | sudo openssl cms -encrypt -outform PEM -out storagekey_source.txt $CERT
	if (( $? )); then
		echo "Could not encrypt storage account key source"
		exit 144
	fi

	echo $STORAGEACCOUNTKEY_SINK | sudo openssl cms -encrypt -outform PEM -out storagekey_sink.txt $CERT
	if (( $? )); then
		echo "Could not encrypt storage account key sink"
		exit 145
	fi

	STORAGEACCOUNTKEY_SOURCE=$(echo -e "import re\n\nfile = open('storagekey_source.txt', 'r')\nfor line in file.read().splitlines():\n\tif '-----BEGIN CMS-----' in line or '-----END CMS-----' in line:\n\t\tcontinue\n\telse:\n\t\tprint line\nfile.close()" | sudo python)
	STORAGEACCOUNTKEY_SOURCE=$(echo $STORAGEACCOUNTKEY_SOURCE | tr -d ' ')
	if [ -z "$STORAGEACCOUNTKEY_SOURCE" ];
	then
		echo "Storage account key could not be stripped off header values form encrypted key SOURCE"
		exit 146
	fi
	rm storagekey_source.txt

	STORAGEACCOUNTKEY_SINK=$(echo -e "import re\n\nfile = open('storagekey_sink.txt', 'r')\nfor line in file.read().splitlines():\n\tif '-----BEGIN CMS-----' in line or '-----END CMS-----' in line:\n\t\tcontinue\n\telse:\n\t\tprint line\nfile.close()" | sudo python)
	STORAGEACCOUNTKEY_SINK=$(echo $STORAGEACCOUNTKEY_SINK | tr -d ' ')
	if [ -z "$STORAGEACCOUNTKEY_SINK" ];
	then
		echo "Storage account key could not be stripped off header values form encrypted key SINK"
		exit 147
	fi
	rm storagekey_sink.txt

fi 


validateUsernameAndPassword() {
    #coreSiteContent=$(bash $AMBARICONFIGS_PY --user=$USERID --password=$PASSWD --action=get --port=$ACTIVEAMBARIHOST --cluster=$CLUSTERNAME --config-type=core-site)
    coreSiteContent=$($AMBARICONFIGS_PY --user=$USERID --password=$PASSWD --action=get --port=$PORT --host=$ACTIVEAMBARIHOST --cluster=$CLUSTERNAME --config-type=core-site)
	
    if [[ $coreSiteContent == *"[ERROR]"* && $coreSiteContent == *"Bad credentials"* ]]; then
        echo "[ERROR] Username and password are invalid. Exiting!"
        exit 148
    fi
}

updateAmbariConfigs() {
    #source
    updateResult_source=$($AMBARICONFIGS_PY --user=$USERID --password=$PASSWD --action=set --port=$PORT --host=$ACTIVEAMBARIHOST --cluster=$CLUSTERNAME --config-type=core-site -k "fs.azure.account.key.$STORAGEACCOUNTNAME_SOURCE.blob.core.windows.net" -v "$STORAGEACCOUNTKEY_SOURCE")
    
    if [[ $updateResult_source != *"Tag:version"* ]] && [[ $updateResult_source == *"[ERROR]"* ]]; then
        echo "[ERROR] Failed to update core-site source. Exiting!"
        echo $updateResult_source
        exit 149
    fi
    echo "Added property: 'fs.azure.account.key.$STORAGEACCOUNTNAME_SOURCE.blob.core.windows.net' with storage account key source"

    updateResult_source=$($AMBARICONFIGS_PY --user=$USERID --password=$PASSWD --action=set --port=$PORT --host=$ACTIVEAMBARIHOST --cluster=$CLUSTERNAME --config-type=core-site -k "fs.azure.account.keyprovider.$STORAGEACCOUNTNAME_SOURCE.blob.core.windows.net" -v "org.apache.hadoop.fs.azure.$KEYPROVIDER")
	if [[ $updateResult_source != *"Tag:version"* ]] && [[ $updateResult_source == *"[ERROR]"* ]]; then
		echo "[ERROR] Failed to update core-site. Exiting!"
		echo $updateResult_source
		exit 150
	fi
	echo "Added property source: 'fs.azure.account.keyprovider.$STORAGEACCOUNTNAME_SOURCE.blob.core.windows.net':org.apache.hadoop.fs.azure.$KEYPROVIDER "

    #sink
    updateResult_sink=$($AMBARICONFIGS_PY --user=$USERID --password=$PASSWD --action=set --port=$PORT --host=$ACTIVEAMBARIHOST --cluster=$CLUSTERNAME --config-type=core-site -k "fs.azure.account.key.$STORAGEACCOUNTNAME_SINK.blob.core.windows.net" -v "$STORAGEACCOUNTKEY_SINK")
    
    if [[ $updateResult_sink != *"Tag:version"* ]] && [[ $updateResult_sink == *"[ERROR]"* ]]; then
        echo "[ERROR] Failed to update core-site sink. Exiting!"
        echo $updateResult_sink
        exit 151
    fi
    echo "Added property: 'fs.azure.account.key.$STORAGEACCOUNTNAME_SOURCE.blob.core.windows.net' with storage account key sink"

    updateResult_sink=$($AMBARICONFIGS_PY --user=$USERID --password=$PASSWD --action=set --port=$PORT --host=$ACTIVEAMBARIHOST --cluster=$CLUSTERNAME --config-type=core-site -k "fs.azure.account.keyprovider.$STORAGEACCOUNTNAME_SINK.blob.core.windows.net" -v "org.apache.hadoop.fs.azure.$KEYPROVIDER")
	if [[ $updateResult_sink != *"Tag:version"* ]] && [[ $updateResult_sink == *"[ERROR]"* ]]; then
		echo "[ERROR] Failed to update core-site. Exiting!"
		echo $updateResult_sink
		exit 152
	fi
	echo "Added property sink: 'fs.azure.account.keyprovider.$STORAGEACCOUNTNAME_SINK.blob.core.windows.net':org.apache.hadoop.fs.azure.$KEYPROVIDER "


}

stopServiceViaRest() {
    if [ -z "$1" ]; then
        echo "Need service name to stop service"
        exit 153
    fi
    SERVICENAME=$1
    echo "Stopping $SERVICENAME"
    curl -u $USERID:$PASSWD -i -H 'X-Requested-By: ambari' -X PUT -d '{"RequestInfo": {"context" :"Stop Service for adding storage account"}, "Body": {"ServiceInfo": {"state": "INSTALLED"}}}' http://$ACTIVEAMBARIHOST:$PORT/api/v1/clusters/$CLUSTERNAME/services/$SERVICENAME
}

startServiceViaRest() {
    if [ -z "$1" ]; then
        echo "Need service name to start service"
        exit 154
    fi
    sleep 2
    SERVICENAME=$1
    echo "Starting $SERVICENAME"
    startResult=$(curl -u $USERID:$PASSWD -i -H 'X-Requested-By: ambari' -X PUT -d '{"RequestInfo": {"context" :"Start Service after adding storage account"}, "Body": {"ServiceInfo": {"state": "STARTED"}}}' http://$ACTIVEAMBARIHOST:$PORT/api/v1/clusters/$CLUSTERNAME/services/$SERVICENAME)
    if [[ $startResult == *"500 Server Error"* || $startResult == *"internal system exception occurred"* ]]; then
        sleep 60
        echo "Retry starting $SERVICENAME"
        startResult=$(curl -u $USERID:$PASSWD -i -H 'X-Requested-By: ambari' -X PUT -d '{"RequestInfo": {"context" :"Start Service after adding storage account"}, "Body": {"ServiceInfo": {"state": "STARTED"}}}' http://$ACTIVEAMBARIHOST:$PORT/api/v1/clusters/$CLUSTERNAME/services/$SERVICENAME)
    fi
    echo $startResult
}

##############################
if [ "$(id -u)" != "0" ]; then
    echo "[ERROR] The script has to be run as root."
    usage
fi

USERID=$(echo -e "import hdinsight_common.Constants as Constants\nprint Constants.AMBARI_WATCHDOG_USERNAME" | python)

echo "USERID=$USERID"

PASSWD=$(echo -e "import hdinsight_common.ClusterManifestParser as ClusterManifestParser\nimport hdinsight_common.Constants as Constants\nimport base64\nbase64pwd = ClusterManifestParser.parse_local_manifest().ambari_users.usersmap[Constants.AMBARI_WATCHDOG_USERNAME].password\nprint base64.b64decode(base64pwd)" | python)

validateUsernameAndPassword

echo "***************************UPDATING AMBARI CONFIG**************************"
updateAmbariConfigs
echo "***************************UPDATED AMBARI CONFIG**************************"

#stopServiceViaRest OOZIE
#stopServiceViaRest YARN
#stopServiceViaRest MAPREDUCE2
stopServiceViaRest HDFS
#stopServiceViaRest HIVE

#sleep for 30 seconds to reduce the possibility of race condition in stopping and starting services
sleep 60

#startServiceViaRest HIVE
startServiceViaRest HDFS
#startServiceViaRest MAPREDUCE2
#startServiceViaRest YARN
#startServiceViaRest OOZIE

#sleep 
sleep 60

# copy file
hadoop distcp wasbs://$STORAGEACCOUNTCONTAINER_SOURCE@$STORAGEACCOUNTNAME_SOURCE.blob.core.windows.net/ wasbs://$STORAGEACCOUNTCONTAINER_SINK@$STORAGEACCOUNTNAME_SINK.blob.core.windows.net/

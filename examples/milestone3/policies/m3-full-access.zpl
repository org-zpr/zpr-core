define adapter as a device with cn

define NextCloud as a service with cn:nc.zpr.org
define RfcDB as a service with cn:web.zpr.org

define NextCloudPing as a service with cn:nc.zpr.org
define RfcDBPing as a service with cn:web.zpr.org

Note: Allow any valid adapter to access our two services.
allow cn: adapter to access NextCloud
allow cn: adapter to access RfcDB

Note: Allow any valid adapter to ping the web and nextcloud
allow cn: adapter to access NextCloudPing
allow cn: adapter to access RfcDBPing





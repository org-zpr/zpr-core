Define adapter as a device with cn.

Define NextCloud as a service with cn:'nc.zpr.org'.
Define RfcDB as a service with cn:'web.zpr.org'.

Define NextCloudPing as a service with cn:'nc.zpr.org'.
Define RfcDBPing as a service with cn:'web.zpr.org'.

Note: Allow any valid adapter to access our two services.
Allow cn: adapter to access NextCloud.
Allow cn: adapter to access RfcDB.

Note: Allow any valid adapter to ping the web and nextcloud
Allow cn: adapter to access NextCloudPing.
Allow cn: adapter to access RfcDBPing.





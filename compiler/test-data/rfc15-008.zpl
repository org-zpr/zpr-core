define Image-database as a device with mach-type:idb
define server as service with service
allow Image-database to access service:image-database servers


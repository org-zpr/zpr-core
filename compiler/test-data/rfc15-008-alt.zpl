define Image-database as a device with mach-type:idb.

define server as service with machine-id.

allow Image-database with users to access service:image-database servers.


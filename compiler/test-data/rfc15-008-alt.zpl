define Image-database as an endpoint with mach-type:idb

define server as service with machine-id

allow Image-database with users to access servers with service:image-database


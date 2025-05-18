

note: AuthService is set to a BAS service in our configuration.
Define AuthService as a service


note: We must add access to the AuthService for devices
Allow zpr.adapter.cn: devices to access AuthService


note: Once authenticated, an adapter can ping the AuthService host.
Define AuthSvcPing as a service with device.zpr.adapter.cn:'bas.zpr.org'


note: BAS will add the user attribute "color"
Allow color:red users to access AuthSvcPing









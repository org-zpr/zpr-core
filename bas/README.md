# bas - Basic Authentication Service

Provides a ZPR authentication service that uses RSA keypairs to confirm
actor identity.  Can be configured to return atbitrary attributes along
with an identity token.


## Demonstration Usage

Add a "record" to the database.  Here we add an actor with CN=`mk.zpr`.

    ./bas create mk.zpr



Add some attributes. Here we add a single value attribute "color", a tag attribute "manager", and a multi
value attribute "groups".

    ./bas add-attribute mk.zpr color:green manager groups:marketing,finance

Start the server

    ./bas serve --key certs/tlskey.key --cert certs/tlscert.crt


Kick of authentication/authorization.  Now we are acting like an adapter.  This step will return a challange nonce
that the adapter is supposed to use to generate a signed payload.

    curl -ik -H "Content-Type: application/x-www-form-urlencoded" https://localhost:4000/preauthorize\?response_type\=code\&client_id\=mk.zpr

Response:

```bash
HTTP/1.1 200 OK
content-type: application/json
content-length: 100
date: Thu, 17 Apr 2025 15:30:11 GMT

{"nonce":"lta7gNo3sfCwvJaazs2r9+4F6FNCt0BcYMhGaVndLQn+3cMdGCdT/qo5FTZErfnwAc+leub2qfKPZQ0qDIi8xg=="}
```

Since the service does not yet actually check the signed payload, we can respond with a garbage `payload`.

    curl -d '{"client_id":"mk.zpr","nonce":"lta7gNo3sfCwvJaazs2r9+4F6FNCt0BcYMhGaVndLQn+3cMdGCdT/qo5FTZErfnwAc+leub2qfKPZQ0qDIi8xg==","payload":"fake"}' \
      -ik -H "Content-Type: application/json" \
      -X POST https://localhost:4000/authorize

Response:

```bash
HTTP/1.1 302 Found
location: https://auth.zpr?code=12625318488887027953106631712105642125
content-length: 0
date: Thu, 17 Apr 2025 15:31:05 GMT
```

Normally the adapter would now create the "BLOB" (including the `code` returned above) and
send it to the visa service for processing.  The visa service would then call the `/token`
endpoint to get the authorization token

So here we act like the visa service:


    curl -ik -d "grant_type=authorization_code&code=12625318488887027953106631712105642125&client_id=mk.zpr&redirect_url=ha" \
      -X POST https://localhost:3999/token

Response:

```bash
HTTP/1.1 200 OK
content-type: application/json
content-length: 403
date: Thu, 17 Apr 2025 15:34:17 GMT

{"access_token":"eyJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJ6cHIiLCJleHAiOiIxNzQ0OTkwMjY1IiwiaWF0IjoiMTc0NDkwMzg2NSIsImlzcyI6Inpwci9iYXMiLCJzdWIiOiJtay56cHIiLCJ6cHJhL2NvbG9yIjoiZ3JlZW4iLCJ6cHJhL2dyb3VwcyI6Im1hcmtldGluZyxmaW5hbmNlIiwienByYS9tYW5hZ2VyIjoiIn0.jiKfmi_aQdfb-y5WiJL27fOzViHPOef0pLzGtWXyGs8UN0l4jR9kYULYQCPHBBFI","token_type":"bearer","expires_in":3600,"refresh_token":null,"error":null}

```
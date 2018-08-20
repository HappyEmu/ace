# ACE - Authentication and Authorization for Constrained Environments
This repository encompasses Python implementations for the three ACE entities
authorization server, resource server and client proposed in the IETF draft
https://tools.ietf.org/pdf/draft-ietf-ace-oauth-authz-12.pdf.

### Authorization Server
The authorization server can be run using

    python3 -m as

It binds to port number 8080 and issues CBOR Web Token (CWTs) access tokens. No security
profile is implemented for the communication with the authorization server,
therefore, HTTPS shoud be used.

### Resource Server
The resource server hosts some sample protected resources such as a
simulated temperature sensor value as well as an LED value that can be 
controlled via a request. The resource server can be run using
    
    python3 -m rs
    
The RS will bind to port 8081.
    
#### Resources
    [GET] /temperature
    [POST] /led
    
#### Security Profile
The implemented security profile between the RS and client is based on
the EDHOC (Ephemeral Diffie-Hellman over COSE) IETF draft: https://tools.ietf.org/pdf/draft-selander-ace-cose-ecdhe-08.pdf

### Client
The client requests an access token from the AS and uses the issued 
token to access the protected resources on the RS. The client can
be run using

    pyhton3 -m client
    

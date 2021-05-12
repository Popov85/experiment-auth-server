# Auth server demo

#### This example uses async RSA keys: 1) private to sign JWT token, 2) public for verify JWT token

* Generate RCA keys with keytool:

Being in resource folder invoke in cmd:
`sudo keytool -genkeypair -alias ssia -keyalg RSA -keypass ssia123 -keystore ssia.jks -storepass ssia123`

Specify all required info, or leave it blank for short.

Extract public and private keys (actually we will need only public key) in cmd:
`sudo keytool -list -rfc --keystore ssia.jks | openssl x509 -inform pem -pubkey`

Create a file named public-key.pem with the content extracted from the output of the previous command, like this one:

`-----BEGIN PUBLIC KEY-----
 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoAqepdMVt27BOmQZYcbP
 cfER4At8o74Yb0uOXhxQuVoHclF6MAYkzJ0eOvsbnmNh0mzyQk1woRLRbdxV4/B7
 E8W+zLODXtOTajy//UQww67ODW01Rg2F6WSMATc62/+bDOYcsUV4AZ3ux296wBSx
 F/fd/yvFmjwGbyPgZ62tXNkv4K2pCk4odatOyUkxyNr5JDXezn0x85Znd4iJt5hE
 TKDf0Ywd0LkfxPAKEdQcnSPycD/2Cr2gwGUD76iLQfH2AYCiwjdePgPZWYhUKimH
 oL8obVF0L3aTn2XZjaevObG8HEc3ab9+iqS0SrkVIR4Kk84X25nTBGnpuHmZMkv4
 2QIDAQAB
 -----END PUBLIC KEY-----`
 
Provide this .pem file to all your client apps in order for them to verify JWT token signed with this private key that matches the public one.

* grant_type=password [deprecated, though still used extensively]

For Basic auth use: username:client1, password: secret1

`curl --location --request POST 'http://localhost:8080/oauth/token?grant_type=password&username=john&password=12345&scope=read' \
 --header 'Authorization: Basic Y2xpZW50MTpzZWNyZXQx'`
 
Response is like:

```
{
     "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MjA4NjQ5NDgsInVzZXJfbmFtZSI6ImpvaG4iLCJhdXRob3JpdGllcyI6WyJyZWFkIl0sImp0aSI6IjBiYjBhMTdkLTk2MDAtNDdhMy04YTljLTM0ODNkOTUzOGRiZSIsImNsaWVudF9pZCI6ImNsaWVudDEiLCJzY29wZSI6WyJyZWFkIl19.cfIUPVN5hAGm65guL6gSg4R8152DlydxD0Q87nX2v2PghL-iw8skr89L6Aa8fvHSE3iB_1VW7aZfOz7zllTNu43qijNpa3oqcTjPsmVyX6zaaKcVLTvJi3McD1h9lMY6oeO7MARPUye3HZGjNSLPdoPX2OWC59awRgVbyWVCYQ4zX2PAT9NM-yBGeY6hrIJsnky4Z0ZYbQBTlbN4duolXlm83BGvc1tMbDXU3paPHkwAIcOZMNVHSBTMoykXj3Zo8MriUQJwxLFj2x7r51Tdf1ZzGehVa7roCUYkwX5riWdqtpyOj9BWeSQiT2Sn9Rp7jE_h0EJvyK3Wl-_KpeOgpg",
     "token_type": "bearer",
     "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJqb2huIiwic2NvcGUiOlsicmVhZCJdLCJhdGkiOiIwYmIwYTE3ZC05NjAwLTQ3YTMtOGE5Yy0zNDgzZDk1MzhkYmUiLCJleHAiOjE2MjM0MTM3NDgsImF1dGhvcml0aWVzIjpbInJlYWQiXSwianRpIjoiNWI3Y2U5YjUtNTk4ZC00Y2M2LWIxYWYtMTQ3OTg0NTYzMWU0IiwiY2xpZW50X2lkIjoiY2xpZW50MSJ9.JSUVCY-UgmDjJRUYGktnSzbZRy6nXc5vR4lPuiLYM1X3VaNkYXUiRMIfa9qn1MXHFBcI5nDV5SktVsbezcOwm3sj9W4Pl56xslu1CMloNfgQnzPIJkRyDPY6FZ79aDaVQXXSWgLSQLctusxHUfw-AXe8sOsgu4cDSgjCKWCoYZXeV1pW0VpDnBAbehR_trootFZxLVAg1hqjGvBd3zHvhnEm9gH8kdNp8mQJ_2S4BKatnZ96GPuc7XVsfTs3LWzQmr_73woRtgrYrxxdnUy-We_vcV2znHuCYyt9L6oQGInw_g75qYQhGuw69cXRqzTgAOadtiuzeueZ8CLNeBERyA",
     "expires_in": 43199,
     "scope": "read",
     "jti": "0bb0a17d-9600-47a3-8a9c-3483d9538dbe"
 }
```
 
 Decoded JWT access token looks like this one:
 
 ```
{
    "exp": 1620864948,
    "user_name": "john",
    "authorities": [
      "read"
    ],
    "jti": "0bb0a17d-9600-47a3-8a9c-3483d9538dbe",
    "client_id": "client1",
    "scope": [
      "read"
    ]
  }
```

* grant_type=authorization_code [most used one, recommended one!]

The flow is the following:
1) In a browser, enter url:
`http://localhost:8080/oauth/authorize?response_type=code&client_id=client2&scope=read`
2) Confirm that you allow the request by pressing the button;
4) Extract the code from the returning url:
`http://localhost:8080/?code=vP1t1E`
3) Make a call to resource server.
For Basic auth use: username:client2, password: secret2
`curl --location --request POST 'http://localhost:8080/oauth/token?grant_type=authorization_code&scope=read&code=vP1t1E' \
 --header 'Authorization: Basic Y2xpZW50MjpzZWNyZXQy'`
 
 Response is like:
 ```
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MjA4Njk5MjgsInVzZXJfbmFtZSI6ImpvaG4iLCJhdXRob3JpdGllcyI6WyJyZWFkIl0sImp0aSI6IjQ5NTFkZDRlLTU5MDktNDY0Ny1iYTQ2LWNjZjQzZGZiYTk4MSIsImNsaWVudF9pZCI6ImNsaWVudDIiLCJzY29wZSI6WyJyZWFkIl19.LPqFS0oL3ftW9foGVfwwSo6jsgy-eI_dmlENpbx9P3sMkSGDwj0zwv8XD6unC197gwrjywK-x93vtQzzYUUdrEofRxYK7SY9b2IHeTOFKU9JuJt86xTebqKl1QvcCUG7oZdN5Iu2Ly1vDZKO5xilUZkuJntiiKkUZ-5jA1UxnXioqUDMNuMctqYNyyWha7WIVw8YNCMAZYV7HNvupUWr_w8QsQCvTsEulQAIjdxMr_61SIKrpkppOhzF7wmpcmRiQ4F2OvQ9FmCqdIN0Bu1U26xsNTTTulA0EPdfnlV78uY4Z33Vhs_6lvfShTeAvOkYkZDvKQnenr_ODCEbI-mxLA",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "read",
    "jti": "4951dd4e-5909-4647-ba46-ccf43dfba981"
}
```

Decoded JWT access token looks like this one:

```
{
  "exp": 1620869928,
  "user_name": "john",
  "authorities": [
    "read"
  ],
  "jti": "4951dd4e-5909-4647-ba46-ccf43dfba981",
  "client_id": "client2",
  "scope": [
    "read"
  ]
}
```

 * grant_type=client_credentials (for a client to resource server auth! Special case! No user is involved!)
 
 For Basic auth use: username:client3, password: secret3
 
 `curl --location --request POST 'http://localhost:8080/oauth/token?grant_type=client_credentials&scope=read' \
  --header 'Authorization: Basic Y2xpZW50MzpzZWNyZXQz'`
  
  Response is like:
  
  ```
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJyZWFkIl0sImV4cCI6MTYyMDg2ODEzMiwianRpIjoiNzNhYWYyZTYtNTUyYy00NzYwLThjNDAtOGJhMjRiNTliYjUzIiwiY2xpZW50X2lkIjoiY2xpZW50MyJ9.JlzRTTgzfwLw6laefW7jRvF2iDd2CISUb9gBF2EgoUxkApY8V_pNzB3k1XCOoq9Ly9Kt2hpJHnOFVWgp7SgijsUWepWJAlAV46fwehsS4TrDexBxyaWhv1Yt4BnY_SiStW0w3WO8jZSFYlj3i8q_FYBdvlQdt_s-7Az7Q5sPBU7mMLAR3OGNKHlsan3T_F3ijAb1Q8rk_7GU4VnhdW8oHaWE7Ub1y60N5fVJCyKZUJd4EoPFfOSAC-qcrAFIbrVP6CGpP1hEQtMwGbAw_mTCdH6ZzjneCRuSH48S1Sr0_KPEgdKDtlZSaqDQpkCTH9MvrkbtC_-POxBvynt_oZTSjA",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "read",
    "jti": "73aaf2e6-552c-4760-8c40-8ba24b59bb53"
}
```


Decoded JWT access token looks like this one:

```
{
  "scope": [
    "read"
  ],
  "exp": 1620868132,
  "jti": "73aaf2e6-552c-4760-8c40-8ba24b59bb53",
  "client_id": "client3"
}
```


For further info, visit:
[YouTube](https://www.youtube.com/watch?v=PAidkS89lgo&list=PLEocw3gLFc8XRaRBZkhBEZ_R3tmvfkWZz&index=13)




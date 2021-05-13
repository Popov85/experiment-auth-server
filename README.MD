# Auth server demo: exposing endpoint for getting public key (for resource server)

#### This example uses async RSA keys: 1) private to sign JWT token, 2) public for verify JWT token

Configuring this line makes it possible to expose a given URL to fetch public key

```
@Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // It allows the response on URL: GET /oauth/token_key that returns public key as string (for resource server)!
        security.tokenKeyAccess("isAuthenticated()"); // permitAll() isAuthenticated()
    }
```

Now, calling the endpoint GET /oauth/token_key

```
curl --location --request GET 'http://localhost:8080/oauth/token_key' \
--header 'Authorization: Basic Y2xpZW50MzpzZWNyZXQz' \
```

from resource server makes it return:

```
{
    "alg": "SHA256withRSA",
    "value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoAqepdMVt27BOmQZYcbPcfER4At8o74Yb0uOXhxQuVoHclF6MAYkzJ0eOvsbnmNh0mzyQk1woRLRbdxV4/B7E8W+zLODXtOTajy//UQww67ODW01Rg2F6WSMATc62/+bDOYcsUV4AZ3ux296wBSxF/fd/yvFmjwGbyPgZ62tXNkv4K2pCk4odatOyUkxyNr5JDXezn0x85Znd4iJt5hETKDf0Ywd0LkfxPAKEdQcnSPycD/2Cr2gwGUD76iLQfH2AYCiwjdePgPZWYhUKimHoL8obVF0L3aTn2XZjaevObG8HEc3ab9+iqS0SrkVIR4Kk84X25nTBGnpuHmZMkv42QIDAQAB\n-----END PUBLIC KEY-----"
}
```

For further info, visit:
[YouTube](https://www.youtube.com/watch?v=Jc4lHXPRY9I&list=PLEocw3gLFc8XRaRBZkhBEZ_R3tmvfkWZz&index=19)




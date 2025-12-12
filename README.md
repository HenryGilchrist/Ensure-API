## Express JS REST API

### Issues JWT Tokens in HTTP Cookies: invisible to the frontend.
#### Access Tokens issued at login contain a flag authorising sensitive actions — refreshed access tokens do not.
#### Passwords are not stored directly, each password is encrypted by a one-way hash function that uses a unique salt for each password, ensuring the compromise of one password through a brute-force attack doesn't expose other users’ credentials — even if they use the same password.

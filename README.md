# Exemplo de solução  de refresh-token

## Account
- Criação de conta:
```
curl --location 'https://localhost:7073/Account/' \
--header 'Content-Type: application/json' \
--data-raw '{
    "Email": "mail@mail.com",
    "Password": "Password@123",
    "ConfirmPassword": "Password@123"
}'
```

## Auth

### Token
- Criação de token:
```
curl --location 'https://localhost:7073/Auth/token' \
--header 'Content-Type: application/json' \
--data-raw '{
    "Email":"mail@mail.com",
    "Password": "Password@123"
}'
```

### Refresh-token
- Criação de refresh-token:
```
curl --location 'https://localhost:7073/Auth/refresh-token' \
--header 'Content-Type: application/json' \
--data '{
    "refresh-token": "{refresh-token gerado na requisição Auth/token }"
}'
```

## Protected
- Acesso ao endpoint restrito:
```
curl --location 'https://localhost:7073/Protected'
```

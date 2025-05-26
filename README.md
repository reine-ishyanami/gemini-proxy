## 创建证书

1. 创建私玥

    ```bash
    openssl genrsa -out privatekey.pem 2048
    ```

2. 创建自签证书

    ```bash
    openssl req -new -x509 -key privatekey.pem -out certificate.pem -days 365
    ```
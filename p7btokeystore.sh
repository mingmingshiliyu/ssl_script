#!/bin/bash
echo "先生成csr,到myserve申请7b之后放到当前文件夹下再转换成p12"
echo "请选择操作："
echo "1. 生成服务端CSR（需交互输入CN值）"
echo "2. 生成客户端CSR（需交互输入CN值）"
echo "3. 转换P7B为PEM并打包PKCS12"
echo "4. 替换keystore中的alias证书(危险)"
echo "5. (自签)生成ca"
echo "6. (自签)生成客户端证书"
echo "7. (自签)生成服务端证书"
echo "8. (自签)nginx mtls配置文件样例"
echo "9. (自签)生成keystore和truststore"
read -p "输入选项（1或2或3或4）: " choice

case $choice in
    1)
        # 生成CSR
        read -p "请输入证书的Common Name (CN)，例如 your.server.com: " cn_name
        if [ -z "$cn_name" ]; then
            echo "错误：CN不能为空！"
            exit 1
        fi

        # 生成私钥和CSR
        openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=$cn_name/OU=VW" -addext "keyUsage = digitalSignature, keyEncipherment" -addext "extendedKeyUsage = serverAuth, clientAuth" -addext "subjectAltName = DNS:*.vwautocloud.cn, DNS:*.vwcloud.cn"

        echo "CSR生成成功！"
        echo "私钥文件: server.key"
        echo "CSR文件: server.csr"
        echo "请去myserve平台将csr提交到vwg自签证书SP申请处"
        ;;
    2)
        # 生成CSR
        read -p "请输入证书的Common Name (CN)，例如 your.server.com: " cn_name
        if [ -z "$cn_name" ]; then
            echo "错误：CN不能为空！"
            exit 1
        fi

        # 生成私钥和CSR
        openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=$cn_name/OU=VW" -addext "keyUsage = digitalSignature, keyEncipherment" -addext "extendedKeyUsage = serverAuth, clientAuth" -addext "subjectAltName = DNS:*.vwautocloud.cn, DNS:*.vwcloud.cn"

        echo "CSR生成成功！"
        echo "私钥文件: client.key"
        echo "CSR文件: client.csr"
        echo "请去myserve平台将csr提交到vwg自签证书SP申请处"
        ;;
    3)
        echo "当前文件夹下文件:"
        ls 
        # 转换P7B并打包PKCS12
        read -p "请输入P7B文件路径（例如 company_ca.p7b）: " p7b_file
        read -p "请输入客户端私钥文件路径（例如 client.key）: " client_key
        read -p "输入要替换keystore中alias名称 : " alias

        if [ ! -f "$p7b_file" ] || [ ! -f "$client_key" ]; then
            echo "错误：文件不存在，请检查路径！"
            exit 1
        fi

        # 转换P7B为PEM（反转顺序）
        openssl pkcs7 -in "$p7b_file" -print_certs | awk -v RS='\n\n' '{a[i++]=$0} END {w
hile(i--) print a[i] "\n"}' > reversed_certs.pem

        # 打包PKCS12 -name "$alias"
       openssl pkcs12 -export -name "$alias"  -out bundle.p12 -inkey "$client_key" -passo
ut pass:store123456 -in reversed_certs.pem 
       echo "检查证书链是否正确,从上到下依次是子证书->中间证书->根证书.密码不能为空"
       openssl pkcs12 -in bundle.p12 -nodes -nokeys | awk '/BEGIN CERT/{cert=""; f=1} f {
cert = cert $0 "\n"} /END CERT/{print "---"; print cert | "openssl x509 -noout -subject -
issuer"; close("openssl x509 -noout -subject -issuer"); f=0}'
        echo "操作成功！"
        echo "生成的PEM证书链(包含根证书和子证书): reversed_certs.pem"
        echo "打包的PKCS12文件: bundle.p12"
        ;;
    4)
        # 导入到 Keystore
        echo "当前文件夹下文件:"
        ls
        read -p "请输入p12文件路径（例如 bundle.p12）: " p12file
        read -p "请输入keystore文件路径（例如 keystore.jks）: " JKS_FILE
        read -p "请输入要替换的alias,需要和生成p12时填写的一致（例如 megatron）: " ALIAS_
NAME
        read -p "请输入keystore密码 : " JKS_PASS
        if keytool -list -alias "$ALIAS_NAME" -keystore "$JKS_FILE" -storepass "$JKS_PASS
" 2>/dev/null; then
          create=""
        else
          create="是"
        fi
        
        echo "会删除keystore中已存在的同名alias证书文件,请谨慎操作!!!自动备份到./bakcert
中"
                
        echo "警告：此操作将修改关键配置。"
        read -p "请输入 'verify' 继续: " user_input
        TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
        mkdir bakcert_${TIMESTAMP}
        cp "$JKS_FILE" ./bakcert_${TIMESTAMP}

        if [ "$user_input" != "verify" ]; then
            echo "验证失败，操作已取消。"
            exit 1
        fi
        if [ -z "$create" ]; then
            keytool -delete -alias "$ALIAS_NAME" -keystore "$JKS_FILE" -storepass "$JKS_P
ASS"
        fi
        keytool -importkeystore -srckeystore "$p12file" -srcstoretype PKCS12 -srcstorepas
s store123456 -destkeystore "$JKS_FILE" -deststorepass "$JKS_PASS" -alias "$ALIAS_NAME" 
        echo "查看该alias的证书内容:"
        keytool -list -alias "$ALIAS_NAME"  -keystore "$JKS_FILE" -storepass "$JKS_PASS"
        ;;
    5)
        read -p "请输入cn(www.baidul.com)" cn
        read -p "请输入ca(your org): " ca
        openssl genrsa -out ca.key 4096
        # 生成 CA 根证书（有效期10年）
        openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/
CN=$cn/O=$ca"
        ;;
    6)
        read -p "请输入cn(www.baidul.com): " cn
        read -p "请输入ca(your org): " ca
        openssl genrsa -out client.key 4096
        openssl req -new -key client.key -out client.csr -subj "/CN=$cn/O=$ca/OU=$ca"
        openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cl
ient.crt -days 825 -sha256 -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage
=clientAuth")
        ;;
    7)
        read -p "请输入cn(www.baidul.com): " cn
        read -p "请输入ca(your org): " ca
        read -p "输入san(DNS:www.baidu.com): " san
        openssl genrsa -out server.key 4096

        openssl req -new -key server.key -out server.csr -subj "/CN=$cn/O=$ca"


        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out se
rver.crt -days 825 -sha256 -extfile <(printf "subjectAltName=$san\nkeyUsage=digitalSignat
ure,keyEncipherment\nextendedKeyUsage=serverAuth")
        ;;
    8)
        cat << 'EOF'
server {

        #mTLS配置
        listen 443 ssl;
        server_name    indexpage;
        ssl_certificate /nginx-mtls/server.crt;
        ssl_certificate_key /nginx-mtls/server.key;

        ssl_session_cache    shared:SSL:1m; # 配置共享会话缓存大小
        ssl_session_timeout  5m; # session有效期5分钟
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5:!DES:!3DES;
        ssl_prefer_server_ciphers  on; # 优先采取服务器算法

        ssl_client_certificate /nginx-mtls/client_certs/ca.crt;
        ssl_verify_client on;

        ssl_verify_depth 6; # 校验深度
        ssl_trusted_certificate /nginx-mtls/client_certs/ca.crt; # 将CA证书设为受信任的证
书
        # 减少点击劫持
        #add_header  X-Frame-Options DENY;
        # 禁止服务器自动解析资源类型
        add_header  X-Content-Type-Options  nosniff;
        # 防止XSS攻击
        add_header  X-Xss-Protection 1;

        location /{
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }
    }
EOF
        ;;
    9)
        read -p "请输入密码: " password
        read -p "请输入cn: " cn
        read -p "请输入ca.crt位置: " ca
        keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 -keysto
re keystore.jks -storetype JKS -storepass $password -keypass $password -dname "CN=$cn, OU
=IT, O=MyCompany, L=shanghai, ST=cn, C=China" 
        keytool -importcert -alias trustedca -file $ca -keystore truststore.jks -storepas
s $password -noprompt 
        ;;
    *)
        echo "错误：无效选项！"
        exit 1
        ;;
esac

# Openssl 常用命令

## 查看
***

1.查看私钥  
> openssl rsa -in xxx.key -noout -text

2.查看公钥
> openssl rsa -in xxx.pub -pubin -noout -text

3.查看证书请求  
> openssl req -in xxx.csr -noout -text




#ifndef SCA_CSR_H
#define SCA_CSR_H

/*===========================================================================*/
/* 证书签发请求（Certificate Signing Request） */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * 证书请求 PKCS10
 *
 * 一个证书请求由三个部分组成：
 * 1.证书请求信息；
 * 2.一个签名算法定义；
 * 3.一段数字证书请求信息的数字签名；
 * 
 * 
 * 、一个公钥和一系列可选的属性组成。CA 系统可以根据用户
 * 提交的证书请求签发出相应的证书，同时，CA 会将证书请求信息传输到最终的 X.509 证书中。
 * 
 * 关于证书请求的格式参考 RFC 2986
 * 关于证书的格式参考 RFC 3280
 * 
 */

/* 证书请求 */
typedef struct sca_cert_sig_req SCA_CERT_SIG_REQ;

/* 创建证书请求结构 */
SCA_CERT_SIG_REQ *sca_csr_create();

/* 设置 */

/* 销毁证书请求 */
void sca_csr_destroy(SCA_CERT_SIG_REQ *csr);


#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_CSR_H */

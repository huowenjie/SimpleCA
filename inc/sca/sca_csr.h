#ifndef SCA_CSR_H
#define SCA_CSR_H

#include "sca_key.h"
#include "sca_digest.h"

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
 * 注意，这段签名是用 subject 所属的私钥来签发的，同样的，该 subject 会将自己的公钥
 * 保存在证书请求里
 * 
 * 、一个公钥和一系列可选的属性组成。CA 系统可以根据用户
 * 提交的证书请求签发出相应的证书，同时，CA 会将证书请求信息传输到最终的 X.509 证书中。
 * 
 * 关于证书请求的格式参考 RFC 2986
 * 关于证书的格式参考 RFC 5280
 * 关于 Distinguished Name 的解释参考 RFC 4519 和 RFC 4514
 */

/* 证书请求 */
typedef struct sca_cert_sig_req SCA_CERT_SIG_REQ;

/* 创建证书请求结构 */
SCA_CERT_SIG_REQ *sca_csr_create();

/* 加载证书请求 */
SCA_CERT_SIG_REQ *sca_csr_load(const char *file);

/*
 * 设置主题项
 *
 * CN -- commonName (2.5.4.3)
 * C -- countryName (2.5.4.6)
 * L -- localityName (2.5.4.7)
 * ST -- stateOrProvinceName (2.5.4.8)
 * STREET -- streetAddress (2.5.4.9)
 * O -- organizationName (2.5.4.10)
 * OU -- organizationalUnitName (2.5.4.11)
 * 
 * field 可以是 oid，也可以是通用字段名
 */
int sca_csr_set_subject(SCA_CERT_SIG_REQ *csr, const char *field, const struct sca_data *dn);

/* 获取主题项数量 */
int sca_csr_get_subject_count(SCA_CERT_SIG_REQ *csr);

/* 根据索引枚举主题项 */
int sca_csr_enum_subject(SCA_CERT_SIG_REQ *csr, int index, struct sca_data *dn);

/* 根据字段或者oid来获取主题项 */
int sca_csr_get_subject_name(SCA_CERT_SIG_REQ *csr, const char *field, struct sca_data *dn);

/* 设置公钥数据 */
int sca_csr_set_pubkey(SCA_CERT_SIG_REQ *csr, SCA_KEY *key);

/* 获取公钥，需要调用 sca_key_destroy 来释放 */
SCA_KEY *sca_csr_get_pubkey(SCA_CERT_SIG_REQ *csr);

/* 生成签名数据 */
int sca_csr_sign(SCA_CERT_SIG_REQ *csr, enum SCA_MD_ALGO md, SCA_KEY *key);

/* 验证证书请求 */
int sca_csr_verify(SCA_CERT_SIG_REQ *csr, SCA_KEY *key);

/* 编码证书请求并输出到指定文件 */
int sca_csr_enc(SCA_CERT_SIG_REQ *csr, const char *file);

/* 销毁证书请求 */
void sca_csr_destroy(SCA_CERT_SIG_REQ *csr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_CSR_H */

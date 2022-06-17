#ifndef SCA_CERT_H
#define SCA_CERT_H

#include "sca_csr.h"

/*===========================================================================*/
/* 证书 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct sca_cert SCA_CERT;

/* 创建证书 默认是 v3 版本 */
SCA_CERT *sca_cert_create();

/* 加载证书 */
SCA_CERT *sca_cert_load(const char *file);

/* 将证书请求的信息导入证书中 */
int sca_cert_import_csr(SCA_CERT *cert, SCA_CERT_SIG_REQ *req);

/* 随机生成 20 字节的证书序列号 */
int sca_cert_gen_serial(SCA_CERT *cert);

/* 获取证书序列号，用字符串表示其十六进制 */
int sca_cert_get_serial(SCA_CERT *cert, struct sca_data *serial);

/* 设置签名算法 */
int sca_cert_set_sign_algo(SCA_CERT *cert, const char *field);

/*
 * 设置证书有效期
 *
 * start 和 end 的格式为 GeneralizedTime 时间格式 YYYYMMDDHHMMSSZ，秒数为 0，
 * 且不允许有小数秒
 * 参照 RFC 5280
 */
int sca_cert_set_validity(SCA_CERT *cert, const char *start, const char *end);

/* 设置颁发者信息 */
int sca_cert_set_issuer(SCA_CERT *cert, const char *field, const struct sca_data *dn);

/* 获取颁发者信息数量 */
int sca_cert_get_issuer_count(SCA_CERT *cert);

/* 根据索引枚举颁发者项 */
int sca_cert_enum_issuer(SCA_CERT *cert, int index, struct sca_data *dn);

/* 根据字段或者 oid 来获取颁发者项 */
int sca_cert_get_issuer_name(SCA_CERT *cert, const char *field, struct sca_data *dn);

/* 设置证书主题项 */
int sca_cert_set_subject(SCA_CERT *cert, const char *field, const struct sca_data *dn);

/* 获取主题项数量 */
int sca_cert_get_subject_count(SCA_CERT *cert);

/* 根据索引枚举主题项 */
int sca_cert_enum_subject(SCA_CERT *cert, int index, struct sca_data *dn);

/* 根据字段或者 oid 来获取主题项 */
int sca_cert_get_subject_name(SCA_CERT *cert, const char *field, struct sca_data *dn);

/* 设置 subject 公钥数据 */
int sca_cert_set_subject_pubkey(SCA_CERT *cert, SCA_KEY *key);

/* 获取 subject 公钥，需要调用 sca_key_destroy 来释放 */
SCA_KEY *sca_cert_get_subject_pubkey(SCA_CERT *cert);

/*
 * 证书扩展项 X.509 V3 新增的功能
 *
 * 根据 RFC 5280，作为 CA 必须支持的扩展项如下：
 * （1）key identifiers 密钥标识符
 * （2）basic constrains 基本约束
 * （3）key usage 密钥用途
 * （4）certificate policies 证书策略
 * （5）如果 CA 的颁发者证书中的 subject 字段为空序列，那么 CA 必须支持 name extension
 * 
 * 对于应用，X.509 证书需要支持以下扩展：
 * （1）key usage 密钥用途
 * （2）certificate policies 证书策略
 * （3）subject alternative name 主体备用名称
 * （4）basic constrains 基本约束
 * （5）name constrains 名称约束
 * （6）policy constrains 策略约束
 * （7）extented key usage 扩展密钥用途
 * （8）inhibit anyPolicy （这个看不懂，貌似是限制任意策略）
 * 不仅如此，对于应用，X.509 规定还应该识别认证和主体的密钥定义和策略映射扩展，RFC5280
 * 用 SHOULD 来标记，表示建议或者强烈建议实现这个功能。
 * 
 * --------------- 标准扩展定义 Standard Extensions ----------------------------
 * 对象定义 id-ce OBJECT IDENTIFER ::= { joint-iso-ccitt(2) ds(5) 29 }
 * 
 * ---------------认证密钥标识符 authority key identifier ----------------------
 * 对象定义 id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::= { id-ce 35 }
 *
 *     这个扩展主要用于在颁发者有多个签名密钥的情况。所有符合条件的 CA 都要包含认证密钥定义
 * 扩展的 keyIdentifier 字段来支持证书路径约束。有一个例外就是当 CA 以一种自签证书的形
 * 式分发公钥时，authority key identifier 扩展可能被省略。自签证书的签名值是用该证书
 * 主题项相关联的公钥对应的私钥来生成。
 *     一般来讲，认证密钥标识符的值由两种方式生成，一种是直接从用于验证该证书签名的公钥中获取，
 * 另一种是利用一个生成唯一值的方法来生成。
 *     CA 必须标记该扩展是非关键项。
 *     认证密钥标识符的具体对象定义参照 RFC5280。
 * 
 * ------------------ 主题密钥标识符 Subject Key Identifier --------------------
 * id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::= { id-ce 14 }
 *
 *     主题密钥标识符提供了识别包含了特殊公钥的证书的含义。为了便于支持证书路径约束，这个扩
 * 展必须在所有符合条件的证书中包含，即所有包含基本约束扩展，且该基本约束扩展的 cA 值为
 * TRUE 的证书。主题密钥标识符的值是通过本证书的主题项生成，这个值会保存在 authority key
 * identifier 扩展的 key identifier 字段中。
 *     CA 必须标记该扩展是个非关键项，生成方式见 RFC5280 的 4.2.1.2 节，这里不再赘述。
 * 
 * ------------------- 密钥用途 Key Usage -------------------------------------
 * id-ce-keyUsage OBJECT IDENTIFIER ::= { id-ce 15 }
 * 
 *     主要用处是限制有可能用于多种操作的密钥，例如，当一个 RSA 密钥仅用于验证对象签名
 * 而不是公钥证书和证书吊销列表时，digitalSignature 和/或 nonRepudiation 位将被断言；
 * 此外，当一个 RSA 密钥仅被用于密钥管理时，keyEncipherment 位将被断言。
 *     符合要求的 CA 必须在证书中包含这个扩展，该证书包含了用于验证其他公钥证书和吊销
 * 列表签名的公钥。
 *     CA 必须标记该扩展项是一个关键项。密钥用途的结构和各个位的含义详见 RFC5280 的
 * 4.2.1.3 节。
 *
 * 
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_CERT_H */

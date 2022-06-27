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

/* 创建证书 约定是 v3 版本 */
SCA_CERT *sca_cert_create();

/* 销毁证书 */
void sca_cert_destroy(SCA_CERT *cert);

/* 加载证书，我们默认证书文件是 PEM 格式 */
SCA_CERT *sca_cert_load(const char *file);

/* 将证书请求的信息导入证书中 */
int sca_cert_import_csr(SCA_CERT *cert, SCA_CERT_SIG_REQ *req);

/* 随机生成 20 字节的证书序列号 */
int sca_cert_gen_serial(SCA_CERT *cert);

/* 设置整数序列号，整数序列号以字符串表示，必须是正整数，最大长度 20 字节 */
int sca_cert_set_serial(SCA_CERT *cert, const struct sca_data *serial);

/* 获取证书序列号，format 为 0，serial 以二进制表示；format 为 1，serial 以字符串 16 进制表示 */
int sca_cert_get_serial(SCA_CERT *cert, int format, struct sca_data *serial);

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
 * ------------------- 证书策略 Certificate Policies --------------------------
 * 
 *     证书策略扩展包含了一些列的策略信息项，每一个策略信息项由一个对象标识符（OID）
 * 和可选的限定符组成。可选的限定符存在与否不会改变策略的定义。一个证书策略 OID 在证书
 * 策略扩展中只能出现一次。
 *     在一个终端证书中，这些策略信息项指明了包含在已签发证书中的策略和证书可能被使用的
 * 目的。在一个 CA 证书中，这些策略信息限制了一系列包含在证书中的证书路径策略。当 CA 并
 * 不希望限制这些策略时，它有可能断言一个特殊的策略 anyPolicy，值为 { 2 5 29 32 0 }
 *     具有特定策略需求的应用程序应该有一个它们可接受的策略列表，并将证书中的策略 OID 和
 * 该列表进行比较。如果这个扩展是关键项，那么路径认证的软件必须能够识别这个扩展，或者必须
 * 拒绝这个证书。
 *     为了促进互操作性，RFC5280 标准建议策略信息项仅由一个 OID 组成。如果单独的 OID 是
 * 不能胜任，标准强烈建议仅使用本节定义的那些限定符。当这些限定符使用了特殊的策略 anyPolicy，
 * 这些限定符同样仅能使用本节的定义。仅那些作为路径验证结果返回值的限定符被考虑。
 *     具体的策略定义见 RFC5280 4.2.1.4 节。
 * 
 * ----------------------- 策略映射 Policy Mapping ----------------------------
 *     这个扩展用于 CA 证书，它列出系列接配对结构，这个结构中包含一对 OID，其中一个是
 * issuerDomainPolicy，另一个是 subjectDomainPolicy。这种配对表明，签发 CA 认为
 * 它的 issuerDomainPolicy 等同于使用者 CA 的 subjectDomainPolicy。
 *     更多内容见 RFC 5280 4.2.1.5 节。
 * 
 * -------------------- 主题可选名称 Subject Alternative Name -------------------
 *     主题可选名称扩展允许身份被绑定到证书的 subject 。这些身份可能会被包含在主题字段
 * 的身份信息之内或之外的位置。这些身份选项包含了网络电子邮件地址，DNS 名称，IP 地址，
 * 统一资源标识符 URI。也存在其他选项，如包括了完整的本地定义的选项、多名称每个名称多实例
 * 的选项。每当这些定义被绑定到证书，主题可选名称（或者颁发者可选名称）扩展都必须被启用。
 *     因为主题可选名称被认为与公钥明确绑定，所有主题可选名称部分都要被 CA 验证。
 *     如果证书中包含的唯一主题标识是另一种名称形式(例如，电子邮件地址)，那么subject可辨别
 * 名称必须为空(空序列)，并且必须存在 subjectAltName 扩展名。如果该 subject 字段包含了一个
 * 空的序列，那么颁发 CA 就必须包含一个被标记为关键项的 subjectAltName 扩展。当包含在
 * 证书中的 subjectAltName 扩展有一个非空的 subject 可辨别名称时，确保 CA 应将其标记为
 * 非关键项。
 *     更多详细的规则见 RFC5280 4.2.1.6 节。
 * 
 * -------------------- 颁发者可选名称 Issuer Alternative Name -----------------
 *     非关键项，见 RFC5280 4.2.1.7 节。
 * 
 * ------------------ 主题目录属性 Subject Directory Attributes ----------------
 *     这个扩展主要用于传送主题的识别属性  convey identification attributes of the
 * subject。详见 RFC5280 4.2.1.8 节。
 * 
 * ------------------------- 基本约束 Basic Constraints ------------------------
 *     基本约束扩展确定证书主题项是否是 CA，同时确定包含在该证书中的有效证书路径的最大
 * 长度。
 *     cA 布尔值指明证书的公钥是否可能被用于验证证书签名。如果 cA 布尔值没有被断言，
 * 那么在密钥用途扩展的 keyCertSign 位不能被断言。如果基本约束扩展在 X509 v3 版本不存在，
 * 或者该扩展存在但是 cA 布尔值没有被断言，那么证书公钥不能被用于验证证书签名。
 *     更多信息参照 RFC5280 4.2.1.9 节。
 * 
 * ------------------------- 名称约束 Name Constraints ------------------------
 *     名称约束扩展，必须且仅被用在 CA 证书中，指明一个涵盖所有主题名称的名称空间，这些
 * 主题名称位于必定在证书路径中被定位的子证书中。限制应用到主题可辨别名称和主题可选名称，
 * 只有当具体的名称形式存在时才适用该限制。如果在证书中没有该类型的名称，那么该证书可接受。
 *     名称约束并不适用于自签证书（除非这个证书在证书路径中是最终的证书）。（这也是防止
 * 使用来自于自签证书的名称约束的 CA 实现更换密钥的操作。）
 *     更多关于名称约束的信息见 RFC5280 4.2.1.10 节。
 * 
 * ----------------------------------------------------------------------------
 *     除了以上扩展，还有策略约束（Policy Constraints)，扩展密钥用途（Extended Key
 * Usage），CRL 分发点，抑制任意策略（Inhibit anyPolicy），最新 CRL（Freshest CRL）
 * ，私有网络扩展项（Private Internet Extensions），机构信息权限（Authority Infoma-
 * tion Access），主题信息权限（Subject Information Access）等，更多信息见 RFC 5280。
 */

/* 添加扩展项, crit 为非零整数，则 ext 为关键项 */
int sca_cert_add_ext(SCA_CERT *cert, const char *oid, int crit, const struct sca_data *ext);

/* 获取扩展项数量 */
int sca_cert_ext_count(SCA_CERT *cert);

/* 根据 oid 搜索扩展项索引 */
int sca_cert_get_ext_loc(SCA_CERT *cert, const char *oid);

/* 获取扩展项 OID */
int sca_cert_get_ext_oid(SCA_CERT *cert, int loc, struct sca_data *oid);

/* 获取扩展项数据 */
int sca_cert_get_ext_data(SCA_CERT *cert, int loc, struct sca_data *data);

/* 扩展项是否是关键项 */
int sca_cert_ext_is_critica(SCA_CERT *cert, int loc);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_CERT_H */

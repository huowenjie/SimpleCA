#ifndef SCA_KEY_H
#define SCA_KEY_H

#include "sca_type.h"

/*===========================================================================*/
/* 密钥管理 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 定义密钥和密钥对象 */
typedef struct sca_key SCA_KEY;

/* 密钥类型 */
enum SCA_KEY_TYPE{
    SCA_UNKNOW = 0,
    SCA_RSA,
    SCA_EC
};

/**
 * 生成密钥
 * 
 * 参数：
 *     type[in] -- 密钥类型
 *     bitlen[in] -- RSA 密钥的模长
 *
 * 返回值：
 *     成功，返回新创建的密钥；失败，返回 NULL。
 *
 * 特殊说明：
 *     如果 type 为 SCA_RSA，bitlen 则为密钥模长的位长度;
 *     返回的 SCA_KEY 对象必须调用 sca_destroy_key 释放。
 */
extern SCA_KEY *sca_gen_key(enum SCA_KEY_TYPE type, int bitlen);

/**
 * 从文件中加载密钥
 * 
 * 参数：
 *     passwd[in] -- 加密密钥的口令
 *     file[in] -- 密钥文件的路径
 *
 * 返回值：
 *     成功，返回新加载的密钥；失败，返回 NULL。
 *
 * 特殊说明：
 *     返回的 SCA_KEY 对象必须调用 sca_destroy_key 释放。
 */
extern SCA_KEY *sca_load_key(const char *passwd, const char *file);

/**
 * 从文件中加载公钥
 * 
 * 参数：
 *     file[in] -- 公钥文件的路径
 *
 * 返回值：
 *     成功，返回新加载的密钥；失败，返回 NULL。
 *
 * 特殊说明：
 *     返回的 SCA_KEY 对象必须调用 sca_destroy_key 释放。
 */
extern SCA_KEY *sca_load_pub_key(const char *file);

/**
 * 销毁密钥
 * 
 * 参数：
 *     key[in] -- 密钥对象
 *
 * 返回值：
 *     void
 */
extern void sca_destroy_key(SCA_KEY *key);

/**
 * 编码密钥数据并输出到指定文件
 * 
 * 参数：
 *     key[in] -- 密钥对象
 *     passwd[in] -- 密钥保护口令，如果为 NULL，则不设口令
 *     file[in] -- 要保存密钥文件的路径
 *
 * 返回值：
 *     成功，返回 SCA_ERR_SUCCESS ；失败，返回相应的错误码。
 *
 * 特殊说明：
 *     密钥会被编码为 PEM 格式。
 */
extern int sca_enc_key(SCA_KEY *key, const char *passwd, const char *file);

/**
 * 编码公钥数据
 * 
 * 参数：
 *     key[in] -- 密钥对象
 *     file[in] -- 要保存密钥文件的路径
 *
 * 返回值：
 *     成功，返回 SCA_ERR_SUCCESS；失败，返回相应的错误码。
 *
 * 特殊说明：
 *     密钥会被编码为 PEM 格式，公钥不需要保护口令。
 */
extern int sca_enc_pub_key(SCA_KEY *key, const char *file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_KEY_H */

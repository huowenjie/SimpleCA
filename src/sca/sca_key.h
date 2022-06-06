#ifndef SCA_KEY_H
#define SCA_KEY_H

#include <sca_type.h>

/*===========================================================================*/
/* 密钥管理 */
/*===========================================================================*/

/* 定义密钥 */
typedef void *SCA_KEY;

/* 生成 rsa 密钥 */
SCA_KEY *sca_gen_rsa_key(int bitlen);

/* 加载 rsa 密钥 */
SCA_KEY *sca_load_rsa_key(const struct SCA_DATA *der);

/* 销毁 rsa 密钥 */
void sca_destroy_rsa_key(SCA_KEY *key);

/* 编码私钥 der 数据 */

/* 编码公钥 der 数据 */


/*===========================================================================*/

#endif /* SCA_KEY_H */

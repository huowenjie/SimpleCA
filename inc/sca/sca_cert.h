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

/* 创建证书 */
SCA_CERT *sca_cert_create();

/* 加载证书 */
SCA_CERT *sca_cert_load(const char *file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_CERT_H */

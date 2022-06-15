#ifndef SCA_INNER_H
#define SCA_INNER_H

#include <openssl/x509.h>
#include <openssl/pem.h>

#include <sca_csr.h>
#include <sca_key.h>
#include <sca_digest.h>

/*===========================================================================*/
/* SCA 内部对象定义 */
/*===========================================================================*/

/* 密钥 */
struct sca_key {
    EVP_PKEY *pkey;
};

/* 证书请求 */
struct sca_cert_sig_req {
    X509_REQ *req;
};

/* 摘要 */
struct sca_digest {
    EVP_MD_CTX *ctx;
};

/*===========================================================================*/

#endif /* SCA_INNER_H */

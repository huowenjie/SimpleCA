#include <sca_trace.h>
#include <sca_key.h>
#include <sca_csr.h>

#include "sca_cmd_test.h"

static char test_dn[] = "CN";

/*===========================================================================*/

int sca_cmd_test(struct sca_cmd_opt *opt)
{
    SCA_KEY *key = NULL;
    SCA_CERT_SIG_REQ *req = NULL;

    struct sca_data dn = {
        (sizeof(test_dn) - 1),
        (SCA_BYTE *)test_dn
    };

    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    key = sca_gen_key(SCA_RSA, 1024);

    sca_enc_key(key, NULL, "test.key");
    sca_enc_pub_key(key, "test.pub");

    req = sca_csr_create();

    sca_csr_set_subject(req, "C", &dn);
    sca_csr_set_pubkey(req, key);
    sca_csr_sign(req, SCA_MD_SHA1, key);
    sca_csr_verify(req, key);
    sca_csr_verify(req, NULL);
    sca_csr_enc(req, "test.csr");

    sca_csr_destroy(req);
    sca_destroy_key(key);

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/

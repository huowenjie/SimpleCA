#include "sca_csr.h"

/*===========================================================================*/

SCA_CERT_SIG_REQ *sca_csr_create()
{
    return NULL;
}

int sca_csr_set_subject(SCA_CERT_SIG_REQ *csr, const char *oid, const struct sca_data *dn)
{
    return 0;
}

int sca_csr_set_pubkey(SCA_CERT_SIG_REQ *csr, SCA_KEY *key)
{
    return 0;
}

int sca_csr_set_pubkey_oid(SCA_CERT_SIG_REQ *csr, const char *oid)
{
    return 0;
}

int sca_csr_get_info_der(SCA_CERT_SIG_REQ *csr, struct sca_data *dn)
{
    return 0;
}

int sca_csr_set_sign_oid(SCA_CERT_SIG_REQ *csr, const char *oid)
{
    return 0;
}

int sca_csr_set_sign_data(SCA_CERT_SIG_REQ *csr, const struct sca_data *dn)
{
    return 0;
}

int sca_csr_enc(SCA_CERT_SIG_REQ *csr, const char *file)
{
    return 0;
}

void sca_csr_destroy(SCA_CERT_SIG_REQ *csr)
{
    return 0;
}

/*===========================================================================*/

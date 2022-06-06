#include <sca_trace.h>

#include "sca_cmd_test.h"

/*===========================================================================*/

int sca_cmd_test(struct sca_cmd_opt *opt)
{
    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    SCA_TRACE("num = %d\n", opt->arg_num);

    if (opt->arg_num > 0) {
        SCA_TRACE("arg[0] = %s\n", opt->args[0]);
    }

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/

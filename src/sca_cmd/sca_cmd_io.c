#include <string.h>
#include <sca_trace.h>

#include "sca_cmd_io.h"
#include "sca_cmd_buf.h"

#include "../sca_err/sca_cmd_err.h"

/*===========================================================================*/

int sca_cmd_input(struct sca_cmd_opt *opt)
{
    if (opt->arg_num != 1) {
        SCA_TRACE_CODE(SCA_CMD_ERR_UNKNOWN_ARGS);
        return SCA_CMD_ERR_UNKNOWN_ARGS;
    }

    if (!strcmp(opt->args[0], CMD_IO_STD)) {
        return sca_cmd_buf_in_std(SCA_BUF_NAME_IO);
    }
    return sca_cmd_buf_in_file(SCA_BUF_NAME_IO, opt->args[0]);
}

int sca_cmd_output(struct sca_cmd_opt *opt)
{
    if (opt->arg_num != 1) {
        SCA_TRACE_CODE(SCA_CMD_ERR_UNKNOWN_ARGS);
        return SCA_CMD_ERR_UNKNOWN_ARGS;
    }

    if (!strcmp(opt->args[0], CMD_IO_STD)) {
        return sca_cmd_buf_out_std(SCA_BUF_NAME_IO);
    }
    return sca_cmd_buf_out_file(SCA_BUF_NAME_IO, opt->args[0]);
}

/*===========================================================================*/

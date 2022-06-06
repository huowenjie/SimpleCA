#include <stdlib.h>
#include <string.h>
#include <sca_trace.h>

#include "sca_cmd_list.h"

#include "../sca_err/sca_cmd_err.h"

/*===========================================================================*/

struct sca_cmd_list
{
    int max_num;
    int cur_num;
    struct sca_cmd_opt **opt;
};

#define SCA_CMD_LIST_SIZE 16

static struct sca_cmd_opt *def_opt_list[SCA_CMD_LIST_SIZE] = { 0 };

static SCA_CMD_LIST def_cmd_list = {
    SCA_CMD_LIST_SIZE, 0, def_opt_list
};

/*===========================================================================*/

SCA_CMD_LIST *sca_cmd_list_def() {
    return &def_cmd_list;
}

void sca_cmd_list_init(SCA_CMD_LIST *list) {
    if (!list) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return;
    }

    list->cur_num = 0;
    memset(list->opt, 0, list->max_num * sizeof(struct sca_cmd_opt *));
}

int sca_cmd_list_push(SCA_CMD_LIST *list, struct sca_cmd_opt *opt)
{
    int i = 0;

    if (!list || !opt)
    {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if ((i = list->cur_num) >= list->max_num)
    {
        SCA_TRACE_CODE(SCA_CMD_ERR_LIST_IS_FULL);
        return SCA_CMD_ERR_LIST_IS_FULL;
    }

    list->opt[i++] = opt;
    list->cur_num = i;
    return SCA_ERR_SUCCESS;
}

struct sca_cmd_opt *sca_cmd_list_pop(SCA_CMD_LIST *list)
{
    int i = 0;
    struct sca_cmd_opt *opt = NULL;

    if (!list) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return NULL;
    }

    if ((i = list->cur_num) > 0) {
        opt = list->opt[--i];
        list->opt[i] = NULL;
        list->cur_num = i;
    }

    return opt;
}

int sca_cmd_list_clear(SCA_CMD_LIST *list)
{
    int i = 0;

    if (!list) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!(i = list->cur_num)) {
        return SCA_ERR_SUCCESS;
    }

    memset(list->opt, 0, i * sizeof(struct sca_cmd_opt *));
    list->cur_num = 0;

    return SCA_ERR_SUCCESS;
}

static int cmd_comp(const void *a, const void *b)
{
    const struct sca_cmd_opt *c1 = NULL;
    const struct sca_cmd_opt *c2 = NULL;

    if (a && !b) {
        return 1;
    } else if (!a && b) {
        return -1;
    } else if (!a && !b) {
        return 0;
    }

    c1 = *((struct sca_cmd_opt **)a);
    c2 = *((struct sca_cmd_opt **)b);

    if (c1 && !c2) {
        return 1;
    } else if (!c1 && c2) {
        return -1;
    } else if (!c1 && !c2) {
        return 0;
    } else if (c1->priority > c2->priority) {
        return 1;
    } else if (c1->priority < c2->priority) {
        return -1;
    }

    return 0;
}

int sca_cmd_list_sort(SCA_CMD_LIST *list)
{
    int i = 0;

    if (!list) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if ((i = list->cur_num) > 0) {
        qsort(list->opt, i, sizeof(struct sca_cmd_opt *), cmd_comp);
    }

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/

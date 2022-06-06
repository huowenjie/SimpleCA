#include <stdio.h>
#include <string.h>

#include <sca_hash.h>
#include <sca_trace.h>

#include "sca_cmd_buf.h"
#include "sca_cmd_menu.h"

/*===========================================================================*/

struct cmd_buf {
    SCA_BYTE  *buf;
    SCA_UINT32 size;
    SCA_UINT32 dlen;
    int type;
};

static SCA_HASH_MAP *global_buffer = NULL;

static void cmd_buf_free(SCA_BYTE *elem, int len)
{
    if (elem) {
        struct cmd_buf *head = (struct cmd_buf *)elem;

        if (len != sizeof(*head)) {
            SCA_TRACE_CODE(SCA_ERR_PARAM);
        }

        if (head->buf) {
            free(head->buf);
        }

        free(elem);
    }
}

static struct cmd_buf *cmd_buf_find_elem(const char *name)
{
    SCA_BYTE *buf = NULL;

    if (!name || !name[0]) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return NULL;
    }

    if (!global_buffer) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return NULL;
    }

    sca_hash_map_retrieve(global_buffer, name, &buf, NULL);

    if (!buf) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return NULL;
    }

    return (struct cmd_buf *)buf;
}

/*---------------------------------------------------------------------------*/

int sca_cmd_buf_start()
{
    if (!global_buffer) {
        global_buffer = sca_hash_map_new(0);
    }
    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_end()
{
    if (global_buffer) {
        sca_hash_map_clear_item(global_buffer, cmd_buf_free);
        sca_hash_map_del(global_buffer);
        global_buffer = NULL;
    }
    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_create(const char *name, int size)
{
    SCA_BYTE *buf = NULL;
    struct cmd_buf *head = NULL;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    if (!global_buffer) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    if (size <= 0) {
        size = 1024;
    }

    head = malloc(sizeof(*head));
    buf = malloc(size);

    memset(head, 0, sizeof(*head));
    memset(buf, 0, size);

    head->buf  = buf;
    head->size = (SCA_UINT32)size;
    head->dlen = 0;

    sca_hash_map_insert(global_buffer, name, (SCA_BYTE *)head, sizeof(*head));
    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_destroy(const char *name)
{
    SCA_BYTE *buf = NULL;
    int len = 0;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    if (!global_buffer) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    sca_hash_map_remove(global_buffer, name, &buf, &len);
    cmd_buf_free(buf, len);

    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_size(const char *name)
{
    struct cmd_buf *head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return 0;
    }
    return (int)head->size;
}

int sca_cmd_buf_last_size(const char *name)
{
    struct cmd_buf *head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return 0;
    }
    return (int)head->dlen;
}

int sca_cmd_buf_get_type(const char *name)
{
    struct cmd_buf *head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return 0;
    }
    return (int)head->type;
}

void sca_cmd_buf_set_type(const char *name, int type)
{
    struct cmd_buf *head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return;
    }
    head->type = type;
}

int sca_cmd_buf_read(const char *name, struct sca_data *data)
{
    struct cmd_buf *head = NULL;

    if (!data) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    if (!data->value) {
        data->size = head->dlen;
        return SCA_ERR_SUCCESS;
    }

    if (head->dlen > data->size) {
        SCA_TRACE_CODE(SCA_ERR_FAILED);
        return SCA_ERR_FAILED;
    }

    memcpy(data->value, head->buf, head->dlen);
    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_write(const char *name, const struct sca_data *data)
{
    struct cmd_buf *head = NULL;
    SCA_BYTE *buf = NULL;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    if (!data) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    buf = head->buf;
    if (data->size > head->size) {
        buf = realloc(buf, data->size + 1);
        head->buf = buf;
        head->size = data->size + 1;
    }

    memcpy(buf, data->value, data->size);
    head->dlen = data->size;

    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_in_std(const char *name)
{
    struct sca_data data;
    const char *str = INPUT_STR("");

    if (!str || !*str) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    SCA_DATA_INIT(&data);
    SCA_DATA_SET(&data, str, strlen(str));

    sca_cmd_buf_write(name, &data);
    sca_cmd_buf_set_type(name, STRING);

    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_in_file(const char *name, const char *file)
{
    FILE *fp = NULL;
    SCA_UINT32 size = 0;
    SCA_BYTE *buf = NULL;
    struct cmd_buf *head = NULL;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    if (!file || !*file) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    fp = fopen(file, "rb");
    if (!fp) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    fseek(fp, 0, SEEK_END);
    size = (SCA_UINT32)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = head->buf;

    if (size > head->size) {
        buf = realloc(buf, size + 1);

        head->buf  = buf;
        head->size = size + 1;
    }

    if ((SCA_UINT32)fread(buf, sizeof(SCA_BYTE), size, fp) != size) {
        head->dlen = 0;
        head->type = BINARY;
        memset(buf, 0, head->size);

        fclose(fp);
        SCA_TRACE_CODE(SCA_ERR_FAILED);
        return SCA_ERR_FAILED;
    }

    head->dlen = size;
    head->type = BINARY;
    fclose(fp);
    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_out_std(const char *name)
{
    struct cmd_buf *head = NULL;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    switch (head->type) {
    case BINARY:
        SCA_TRACE_BIN("data", head->buf, head->dlen);
        break;

    case STRING:
        if (head->dlen < head->size) {
            head->buf[head->dlen] = '\0';
            SCA_TRACE("%s\n", head->buf);
        }
        break;
    }
    return SCA_ERR_SUCCESS;
}

int sca_cmd_buf_out_file(const char *name, const char *file)
{
    FILE *fp = NULL;
    SCA_UINT32 size = 0;
    SCA_BYTE *buf = NULL;
    struct cmd_buf *head = NULL;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    if (!file || !*file) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    head = cmd_buf_find_elem(name);
    if (!head) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return SCA_ERR_NULL_POINTER;
    }

    fp = fopen(file, "wb");
    if (!fp) {
        SCA_TRACE_CODE(SCA_ERR_FAILED);
        return SCA_ERR_FAILED;
    }

    size = head->dlen;
    buf = head->buf;

    if ((SCA_UINT32)fwrite(buf, sizeof(SCA_BYTE), size, fp) != size) {
        fclose(fp);
        SCA_TRACE_CODE(SCA_ERR_FAILED);
        return SCA_ERR_FAILED;
    }

    fclose(fp);
    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/

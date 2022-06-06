#include <sca_link.h>
#include <sca_hash.h>

#include "../sca_err/sca_hash_err.h"

/*===========================================================================*/

/* 伸缩单位长度定义 */
#define SCA_HASH_EXPAND_LEN 32
#define SCA_HASH_CONTRACT_LEN 16

/* hash 表默认及最大、最小长度 */
#define SCA_HASH_DEF_LEN 32
#define SCA_HASH_MAX_LEN 256
#define SCA_HASH_MIN_LEN 32

/* 允许的最大节点数 */
#define SCA_HASH_NODE_MAX 512

/* 继承自 struct sca_link */
struct sca_hash_link {
    SCA_HASH_NODE *head;
    SCA_HASH_NODE *tail;

    int count;
};

/* 继承自 struct sca_link_node */
struct sca_hash_node {
    SCA_HASH_NODE *prev;
    SCA_HASH_NODE *next;

    struct sca_data key;
    struct sca_data data;
};

struct sca_hash_map
{
    SCA_HASH_LINK *hash_link_list;  /* hash 链表 */
    SCA_MAP_ITERATOR *iterator;     /* 迭代器 */

    int node_count;                 /* 当前的节点总数 */
    int list_len;                   /* 散列表长度 */
    int max_link;                   /* 最长链表长度 */
    int alloc_size;                 /* 表占用的空间大小 */
};

struct sca_map_iterator
{
    SCA_HASH_MAP  *map;
    SCA_HASH_NODE *cur;

    int link_index;
    int node_index;
};

/*===========================================================================*/

/* 字符串散列值 */
static SCA_UINT32 get_string_hash(const char *key);

/* 获取链表节点 */
static int get_hash_node(
    SCA_HASH_LINK *link,
    const char *key,
    SCA_HASH_NODE **node
);

/*===========================================================================*/

SCA_HASH_MAP *sca_hash_map_new(int len)
{
    SCA_HASH_MAP *map = NULL;
    SCA_HASH_LINK *hash_link_list = NULL;
    SCA_MAP_ITERATOR *iterator = NULL;
    size_t alloc_size = 0;

    if (len < SCA_HASH_MIN_LEN) {
        len = SCA_HASH_MIN_LEN;
    }

    if (len > SCA_HASH_MAX_LEN) {
        len = SCA_HASH_MAX_LEN;
    }

    map = malloc(sizeof(SCA_HASH_MAP));
    if (!map) {
        return NULL;
    }
    memset(map, 0, sizeof(SCA_HASH_MAP));

    iterator = malloc(sizeof(SCA_MAP_ITERATOR));
    if (!map) {
        goto err;
    }
    memset(iterator, 0, sizeof(SCA_MAP_ITERATOR));

    iterator->map = map;
    iterator->cur = NULL;
    iterator->link_index = 0;
    iterator->node_index = 0;

    alloc_size = sizeof(SCA_HASH_LINK) * len;
    hash_link_list = (SCA_HASH_LINK *)malloc(alloc_size);
    if (!hash_link_list) {
        goto err;
    }
    memset(hash_link_list, 0, alloc_size);

    map->node_count = 0;
    map->list_len = len;
    map->max_link = 0;

    map->alloc_size = (SCA_UINT32)alloc_size;
    map->hash_link_list = hash_link_list;
    map->iterator = iterator;

    return map;

err:
    if (hash_link_list) {
        free(hash_link_list);
    }

    if (iterator) {
        free(iterator);
    }

    free(map);
    return NULL;
}

void sca_hash_map_del(SCA_HASH_MAP *map)
{
    if (!map) {
        return;
    }

    map->alloc_size         = 0;
    map->max_link         = 0;
    map->list_len         = 0;
    map->node_count         = 0;

    if (map->hash_link_list) {
        free(map->hash_link_list);
        map->hash_link_list = NULL;
    }

    if (map->iterator) {
        free(map->iterator);
        map->iterator = NULL;
    }

    free(map);
}

void sca_hash_map_clear(SCA_HASH_MAP *map)
{
    SCA_UINT32 i;

    SCA_HASH_LINK *link = NULL;
    SCA_HASH_NODE *node = NULL;

    if (!map) {
        return;
    }

    link = map->hash_link_list;

    for (i = 0; i < map->list_len; i++) {
        while (link->count > 0) {
            node = (SCA_HASH_NODE *)sca_link_pop((struct sca_link *)link);

            if (node) {
                node->data.value = NULL;
                node->data.size = 0;

                free(node->key.value);
                free(node);
            }
        }

        link++;
    }
}

void sca_hash_map_clear_item(SCA_HASH_MAP *map, sca_hash_free_item free_item)
{
    SCA_UINT32 i;

    SCA_HASH_LINK *link = NULL;
    SCA_HASH_NODE *node = NULL;

    if (!map) {
        return;
    }

    link = map->hash_link_list;

    for (i = 0; i < map->list_len; i++) {
        while (link->count > 0) {
            node = (SCA_HASH_NODE *)sca_link_pop((struct sca_link *)link);
            if (node) {
                if (free_item) {
                    free_item(node->data.value, node->data.size);
                }

                node->data.value = NULL;
                node->data.size = 0;

                free(node->key.value);
                free(node);
            }
        }

        link++;
    }
}

void sca_hash_map_clear_data(SCA_HASH_MAP *map, sca_hash_free_item_data free_data)
{
    SCA_UINT32 i;

    SCA_HASH_LINK *link = NULL;
    SCA_HASH_NODE *node = NULL;

    if (!map) {
        return;
    }

    link = map->hash_link_list;

    for (i = 0; i < map->list_len; i++) {
        while (link->count > 0) {
            node = (SCA_HASH_NODE *)sca_link_pop((struct sca_link *)link);
            if (node) {
                if (free_data) {
                    free_data(&node->data);
                }

                node->data.value = NULL;
                node->data.size = 0;

                free(node->key.value);
                free(node);
            }
        }

        link++;
    }
}

SCA_UINT32 sca_hash_map_node_count(SCA_HASH_MAP *map)
{
    if (map) {
        return map->node_count;
    }
    return 0;
}

SCA_UINT32 sca_hash_map_insert(
    SCA_HASH_MAP *map,
    const char *key,
    SCA_BYTE *data,
    int len
)
{
    SCA_HASH_LINK *link = NULL;
    SCA_HASH_NODE *node = NULL;
    SCA_UINT32 hash = 0;

    if (!map || !key) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!map->hash_link_list || !map->list_len) {
        return SCA_ERR_HASH_NOT_INIT;
    }

    /* 获取表索引 */
    hash  = get_string_hash(key);
    hash %= map->list_len;

    link = map->hash_link_list + hash;

    if (!get_hash_node(link, key, &node)) {
        return SCA_ERR_HASH_NODE;
    }

    /* 哈希节点存在则直接替换数据地址，如果不存在则重新创建 */
    if (node) {
        node->data.size = len;
        node->data.value = data;
        return SCA_ERR_SUCCESS;
    }

    node = malloc(sizeof(SCA_HASH_NODE));
    if (!node) {
        return SCA_ERR_NULL_POINTER;
    }
    memset(node, 0, sizeof(SCA_HASH_NODE));

    /* 为 key 分配内存 */
    node->key.size = strlen(key) + 1;
    node->key.value = malloc(node->key.size);

    if (!node->key.value) {
        free(node);
        return SCA_ERR_NULL_POINTER;
    }

    memcpy(node->key.value, key, node->key.size);

    node->data.size  = len;
    node->data.value = data;

    /* 将新的节点接到链表末尾 */
    sca_link_push((struct sca_link *)link, (struct sca_link_node *)node);

    map->node_count++;
    map->max_link = link->count > map->max_link ? link->count : map->max_link;
    map->alloc_size += (SCA_UINT32)sizeof(SCA_HASH_NODE);
    map->alloc_size += node->key.size;

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_hash_map_insert_data(
    SCA_HASH_MAP *map,
    const char *key,
    struct sca_data *value
)
{
    if (value) {
        return sca_hash_map_insert(map, key, value->value, value->size);        
    }

    return SCA_ERR_NULL_PARAM;
}

SCA_UINT32 sca_hash_map_remove(
    SCA_HASH_MAP *map,
    const char *key,
    SCA_BYTE **data,
    int *len
)
{
    SCA_HASH_LINK *link = NULL;
    SCA_HASH_NODE *node = NULL;
    SCA_UINT32 hash = 0;

    if (!map || !key || !*key) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!map->hash_link_list || !map->list_len) {
        return SCA_ERR_HASH_NOT_INIT;
    }

    /* 获取表索引 */
    hash  = get_string_hash(key);
    hash %= map->list_len;

    link = map->hash_link_list + hash;

    if (!get_hash_node(link, key, &node)) {
        return SCA_ERR_HASH_NODE;
    }

    if (!node) {
        return SCA_ERR_SUCCESS;
    }

    /* 出参赋值 */
    if (data) {
        *data = node->data.value;
    }

    if (len) {
        *len = node->data.size;
    }

    /* 将节点从链表上移除 */
    sca_link_remove_force((struct sca_link *)link, (struct sca_link_node *)node);

    map->node_count--;
    map->max_link = link->count > map->max_link ? link->count : map->max_link;
    map->alloc_size -= (SCA_UINT32)sizeof(SCA_HASH_NODE);
    map->alloc_size -= node->key.size;

    /* 释放内存 */
    free(node->key.value);
    free(node);

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_hash_map_remove_data(SCA_HASH_MAP *map, const char *key, struct sca_data *value)
{
    if (value) {
        return sca_hash_map_remove(map, key, &value->value, &value->size);
    }
    return sca_hash_map_remove(map, key, NULL, NULL);
}

SCA_UINT32 sca_hash_map_retrieve(
    SCA_HASH_MAP *map,
    const char *key,
    SCA_BYTE **data,
    int *len
)
{
    SCA_HASH_LINK *link = NULL;
    SCA_HASH_NODE *node = NULL;
    SCA_UINT32 hash = 0;

    if (!map || !key || !*key) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!map->hash_link_list || !map->list_len) {
        return SCA_ERR_HASH_NOT_INIT;
    }

    /* 获取表索引 */
    hash  = get_string_hash(key);
    hash %= map->list_len;

    link = map->hash_link_list + hash;

    if (!get_hash_node(link, key, &node)) {
        return SCA_ERR_HASH_NODE;
    }

    if (!node) {
        return SCA_ERR_HASH_NO_ELEM;
    }

    if (data) {
        *data = node->data.value;
    }

    if (len) {
        *len = node->data.size;
    }

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_hash_map_retrieve_data(
    SCA_HASH_MAP *map,
    const char *key,
    struct sca_data *value
)
{
    if (value) {
        return sca_hash_map_retrieve(map, key, &value->value, &value->size);
    }
    return sca_hash_map_retrieve(map, key, NULL, NULL);
}

SCA_MAP_ITERATOR *sca_hash_map_iterator(SCA_HASH_MAP *map)
{
    if (map) {
        return map->iterator;
    }
    return NULL;
}

SCA_MAP_ITERATOR *sca_hash_map_first(SCA_MAP_ITERATOR *it)
{
    SCA_HASH_LINK *link = NULL;
    SCA_HASH_MAP  *map  = NULL;

    int i   = 0;
    int len = 0;

    if (!it) {
        return NULL;
    }

    map = it->map;
    if (!map || map->iterator != it) {
        return NULL;
    }

    /* 获取链表数组 */
    link = map->hash_link_list;
    if (!link) {
        return NULL;
    }

    /* 查找第一个有元素的节点 */
    for (len = map->list_len; i < len; i++) {
        if (link->count > 0) {
            break;
        }
        link++;
    }

    if (i == len) {
        return NULL;
    }

    it->cur = link->head;
    it->link_index = i;
    it->node_index = 0;

    return it;
}

SCA_MAP_ITERATOR *sca_hash_map_next(SCA_MAP_ITERATOR *it)
{
    SCA_HASH_LINK *link = NULL;
    SCA_HASH_MAP  *map  = NULL;
    SCA_HASH_NODE *node = NULL;

    int i = 0;
    int j = 0;
    int len = 0;

    if (!it) {
        return NULL;
    }

    map = it->map;
    if (!map || map->iterator != it) {
        return NULL;
    }

    /* 调用本方法之前必须先调用 *_first 给 cur 赋值，否则直接返回 NULL */
    node = it->cur;
    if (!node) {
        return NULL;
    }

    /* 获取链表数组 */
    link = map->hash_link_list;
    if (!link) {
        return NULL;
    }

    i = it->link_index;
    j = it->node_index;
    len = map->list_len;

    if (i >= len) {
        return NULL;
    }

    /* 沿着链表数组搜索到对应的链表 */
    link = link + i;

    /* 利用索引检测当前节点是否是链表最后一个节点 */
    if (j < (int)(link->count - 1)) {
        j++;
        node = node->next;

        it->cur = node;
        it->link_index = i;
        it->node_index = j;

        return it;
    }

    /* 如果当前的链表是 hash map 中最后一个表，则返回 NULL */
    if (i == (len - 1)) {
        return NULL;
    }

    /* 搜索下一个链表 */
    link = link + 1;

    while (++i < len) {
        if (link->count > 0) {
            break;
        }
        link++;
    }

    if (i >= len) {
        return NULL;
    }

    it->cur = link->head;
    it->link_index = i;
    it->node_index = 0;

    return it;
}

SCA_UINT32 sca_hash_get_key(SCA_MAP_ITERATOR *it, char *buff, int *len)
{
    struct sca_data *key = NULL;
    int size = 0;

    if (!it || !len) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!it->cur) {
        return SCA_ERR_NULL_PARAM;
    }

    key = &it->cur->key;
    size = key->size;

    if (!buff) {
        *len = size;
        return SCA_ERR_SUCCESS;
    }

    if (*len < size) {
        return SCA_ERR_PARAM;
    }

    strcpy(buff, (const char *)key->value);
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_hash_get_value(SCA_MAP_ITERATOR *it, SCA_BYTE **value, int *len)
{
    struct sca_data *data = NULL;

    if (!it) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!it->cur) {
        return SCA_ERR_NULL_PARAM;
    }

    data = &it->cur->data;

    if (value) {
        *value = data->value;
    }

    if (len) {
        *len = data->size;
    }

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_hash_get_data(SCA_MAP_ITERATOR *it, struct sca_data *data)
{
    if (it && data) {
        return sca_hash_get_value(it, &data->value, &data->size);
    }
    return SCA_ERR_NULL_PARAM;
}

SCA_UINT32 sca_hash_set_value(
    SCA_MAP_ITERATOR *it,
    SCA_BYTE *value,
    int len
)
{
    if (it && it->cur) {
        struct sca_data *data = &it->cur->data;
        data->value = value;
        data->size  = len;
    }
    return SCA_ERR_NULL_PARAM;
}

SCA_UINT32 sca_hash_set_data(SCA_MAP_ITERATOR *it, struct sca_data *data)
{
    if (it && it->cur && data) {
        it->cur->data = *data;
    }
    return SCA_ERR_NULL_PARAM;
}

/*===========================================================================*/

SCA_UINT32 get_string_hash(const char *key)
{
    SCA_UINT32 ret = 0;

    if (!key || !*key) {
        return ret;
    }

    while (*key) {
        ret = (ret << 5) ^ *key;
        key++;
    }

    return ret;
}

int get_hash_node(
    SCA_HASH_LINK *link,
    const char *key,
    SCA_HASH_NODE **node)
{
    SCA_UINT32 i = 0;

    SCA_HASH_NODE *ret  = NULL;
    SCA_HASH_NODE *tmp  = NULL;

    size_t key_size = 0;

    if (!link)
    {
        return 0;
    }

    if (!key || !*key || !node)
    {
        return 0;
    }

    if (!link->count)
    {
        *node = NULL;
        return 1;
    }

    key_size = strlen(key) + 1;
    tmp = link->head;

    /* 检索具有相同键的链表节点 */
    while (i++ < link->count) {
        /* 比较数据长度和数据内容 */
        if (tmp->key.size == key_size && 
            !memcmp(tmp->key.value, key, key_size)) {
            ret = tmp;
            break;
        }

        tmp = tmp->next;
    }

    *node = ret;
    return 1;
}

/*===========================================================================*/

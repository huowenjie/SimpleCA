#ifndef SCA_HASH_H
#define SCA_HASH_H

#include "sca_type.h"

/*===========================================================================*/
/* 字符串-数据哈希映射链表 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct sca_hash_link SCA_HASH_LINK;
typedef struct sca_hash_node SCA_HASH_NODE;
typedef struct sca_hash_map SCA_HASH_MAP;
typedef struct sca_map_iterator SCA_MAP_ITERATOR;

typedef void (*sca_hash_free_item)(SCA_BYTE *elem, int len);
typedef void (*sca_hash_free_item_data)(struct sca_data *elem);

/* 创建哈希表, 指定初始长度 */
SCA_HASH_MAP *sca_hash_map_new(int len);

/* 释放哈希表 */
void sca_hash_map_del(SCA_HASH_MAP *map);

/* 清空哈希表 */
void sca_hash_map_clear(SCA_HASH_MAP *map);

/* 清空哈希表并释放单个元素 */
void sca_hash_map_clear_item(
    SCA_HASH_MAP *map,
    sca_hash_free_item free_item
);

/* 清空哈希表并释放数据块 */
void sca_hash_map_clear_data(
    SCA_HASH_MAP *map,
    sca_hash_free_item_data free_data
);

/* 获取元素数量 */
SCA_UINT32 sca_hash_map_node_count(SCA_HASH_MAP *map);

/* 插入元素, 允许 data 为空 */
SCA_UINT32 sca_hash_map_insert(
    SCA_HASH_MAP *map,
    const char *key,
    SCA_BYTE *data,
    int len
);

/* 插入元素, 对于 value 只保存地址信息，已存在的元素会直接被覆盖 */
SCA_UINT32 sca_hash_map_insert_data(
    SCA_HASH_MAP *map,
    const char *key,
    struct sca_data *value
);

/* 移除元素，data 和 len 为出参可以为 NULL */
SCA_UINT32 sca_hash_map_remove(
    SCA_HASH_MAP *map,
    const char *key,
    SCA_BYTE **data,
    int *len
);

/* 移除元素, value 为出参 */
SCA_UINT32 sca_hash_map_remove_data(
    SCA_HASH_MAP *map,
    const char *key,
    struct sca_data *value
);

/* 检索元素 */
SCA_UINT32 sca_hash_map_retrieve(
    SCA_HASH_MAP *map,
    const char *key,
    SCA_BYTE **data,
    int *len
);

/* 检索数据 */
SCA_UINT32 sca_hash_map_retrieve_data(
    SCA_HASH_MAP *map,
    const char *key,
    struct sca_data *value
);

/* 获取迭代器 */
SCA_MAP_ITERATOR *sca_hash_map_iterator(SCA_HASH_MAP *map);

/* 将迭代器指针定位到首个元素上 */
SCA_MAP_ITERATOR *sca_hash_map_first(SCA_MAP_ITERATOR *it);

/* 访问下一个元素，如果返回值为 NULL，则说明没有元素 */
SCA_MAP_ITERATOR *sca_hash_map_next(SCA_MAP_ITERATOR *it);

/* 获取键，len 为缓冲区长度，buff 为 NULL 时，len 返回缓冲区长度 */
SCA_UINT32 sca_hash_get_key(SCA_MAP_ITERATOR *it, char *buff, int *len);

/* 获取值（直接赋值），value 和 len 皆可为 NULL */
SCA_UINT32 sca_hash_get_value(
    SCA_MAP_ITERATOR *it,
    SCA_BYTE **value,
    int *len
);

/* 获取二进制数据块 */
SCA_UINT32 sca_hash_get_data(SCA_MAP_ITERATOR *it, struct sca_data *data);

/* 设置值，我们会重新覆盖原有的数据 */
SCA_UINT32 sca_hash_set_value(
    SCA_MAP_ITERATOR *it,
    SCA_BYTE *value,
    int len
);

/* 设置数据块 */
SCA_UINT32 sca_hash_set_data(SCA_MAP_ITERATOR *it, struct sca_data *data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_HASH_H */

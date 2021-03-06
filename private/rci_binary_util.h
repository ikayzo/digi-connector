/*
 * Copyright (c) 2013 Digi International Inc.,
 * All rights not expressly granted are reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */

#if (defined connector_request_id_remote_config_configurations)
static connector_remote_config_data_t connector_rci_config_data = {
        NULL, NULL, connector_rci_error_COUNT, 0
};

#else
typedef struct {
    connector_remote_group_table_t const * group_table;
    char const * const * error_table;
    unsigned int global_error_count;
    uint32_t firmware_target_zero_version;
} connector_remote_config_data_t;

static connector_remote_config_data_t const connector_rci_config_data = {
        connector_group_table,
#if defined RCI_PARSER_USES_ERROR_DESCRIPTIONS
        connector_rci_errors,
#else
        NULL,
#endif
        connector_global_error_COUNT,
        FIRMWARE_TARGET_ZERO_VERSION
};
#endif

#define BINARY_RCI_FIELD_LOWER_ID_MASK UINT32_C(0x3F)
#define BINARY_RCI_FIELD_MIDDLE_ID_MASK UINT32_C(0x380)
#define BINARY_RCI_FIELD_MIDDLE_BIT_ID_MASK UINT32_C(0x800)
#define BINARY_RCI_FIELD_UPPER_ID_MASK (~UINT32_C(0x1FFF))


static unsigned int decode_element_id(uint32_t const value)
{
    unsigned int id;

    id = (value & BINARY_RCI_FIELD_LOWER_ID_MASK);
    id |= ((value & BINARY_RCI_FIELD_MIDDLE_ID_MASK) >> 1);
    id |= ((value & BINARY_RCI_FIELD_MIDDLE_BIT_ID_MASK) >> 2);
    id |= ((value & BINARY_RCI_FIELD_UPPER_ID_MASK) >> 3);

    return id;
}

static uint32_t encode_element_id(unsigned int const id)
{

    uint32_t value;

    value = (id & BINARY_RCI_FIELD_LOWER_ID_MASK);
    value |= ((id  << 1) & BINARY_RCI_FIELD_MIDDLE_ID_MASK);
    value |= ((id  << 2) & BINARY_RCI_FIELD_MIDDLE_BIT_ID_MASK);
    value |= ((id  << 3) & BINARY_RCI_FIELD_UPPER_ID_MASK);

    return value;
}


#define BINARY_RCI_GROUP_ID_LOWER_BIT_MASK  UINT32_C(0x03F)   /* [5:0] */
#define BINARY_RCI_GROUP_ID_MIDDLE_BIT_MASK UINT32_C(0xF80)   /* [11:7] */
#define BINARY_RCI_GROUP_ID_UPPER_BIT_MASK  ~(UINT32_C(0x1FF))    /* [:13] */

static unsigned int decode_group_id(uint32_t const group_id)
{

    unsigned int id = 0;

    id = (group_id & BINARY_RCI_GROUP_ID_LOWER_BIT_MASK);
    id |= ((group_id & BINARY_RCI_GROUP_ID_MIDDLE_BIT_MASK) >> 1);
    id |= ((group_id & BINARY_RCI_GROUP_ID_UPPER_BIT_MASK) >> 2);

    return id;
}

static uint32_t encode_group_id(unsigned int const group_id)
{
    uint32_t id;

    id = (group_id & BINARY_RCI_GROUP_ID_LOWER_BIT_MASK);
    id |= ((group_id << 1) & BINARY_RCI_GROUP_ID_MIDDLE_BIT_MASK);
    id |= ((group_id << 2) & BINARY_RCI_GROUP_ID_UPPER_BIT_MASK);

    return id;
}


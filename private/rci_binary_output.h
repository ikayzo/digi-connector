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
static void rci_set_output_error(rci_t * const rci, unsigned int const id, char const * const hint, rci_output_state_t state)
{
    rci_global_error(rci, id, hint);
    set_rci_output_state(rci, state);
    state_call(rci, rci_parser_state_output);
}

static connector_bool_t rci_output_data(rci_t * const rci, rci_buffer_t * const output, uint8_t const * const data, size_t const bytes)
{
    connector_bool_t const overflow = connector_bool(rci_buffer_remaining(output) < bytes);

    if (overflow)
    {
        rci->status = rci_status_flush_output;
    }
    else
    {
        memcpy(rci_buffer_position(output), data, bytes);
        rci_buffer_advance(output, bytes);
    }

    return overflow;
}

static size_t get_bytes_followed(uint32_t value)
{
    /* Bytes needed for the value:
     * 1 byte is 0 to 0x7F
     * 2 bytes is 0 to 0x1FFF
     * 3 bytes is 0 to 0xFFFF
     * 5 bytes is 0 to 0xFFFFFFFF
     *
     * Get additional bytes needed according to the value.
     */
    size_t bytes = 0;
    if (value <= UINT32_C(0x7F))
    {
        bytes = 0;
    }
    else if (value < UINT32_C(0x2000))
    {
        bytes = 1;
    }
    else if (value < UINT32_C(0x10000))
    {
        bytes = 2;
    }
    else
    {
        bytes = 4;
    }

    return bytes;
}

static connector_bool_t rci_output_uint32(rci_t * const rci, uint32_t const value)
{
    connector_bool_t overflow;
    size_t const bytes_follow = get_bytes_followed(value);

    rci_buffer_t * const output = &rci->buffer.output;
    size_t const total_bytes = bytes_follow + 1;

    overflow = connector_bool(rci_buffer_remaining(output) < total_bytes);
    if (overflow)
    {
        rci->status = rci_status_flush_output;
    }
    else
    {
        uint8_t * const rci_ber = rci_buffer_position(output);

        /*
         *        opcode
         *    7 6 5 4 3 2 1 0 bit
         *    ---------------
         *    0 X X X X X X X   (0 : 0x7F)
         *    1 0 0 X X X X X   + 1 byte followed (0: 0x1FFF)
         *    1 0 1 - - - 0 0   + 2 bytes followed (0: 0xFFFF)
         *    1 0 1 - - - 0 1   + 4 bytes followed (0: 0xFFFFFFFF)
         *    1 0 1 - - - 1 0   + 8 bytes followed (0: 0xFFFFFFFFFFFFFFFF)
         *    1 1 0 - - - - -   Reserved
         *    1 1 1 0 0 0 0 0   NONUM (No Value)
         *    1 1 1 0 0 0 0 1   TRM (Terminator)
         */
        switch (total_bytes)
        {
            case record_bytes(rci_ber):
            {
                /* one byte with range [0, 0x7F] */
                uint8_t const data = (uint8_t)value;
                message_store_u8(rci_ber, value, data);
                break;
            }
            case record_bytes(rci_ber_u8):
            {
                #define MAX_ONE_BYTE_FOLLOW_VALUE   UINT32_C(0x1FFF)

                /* two bytes with range [0, 0x1FFF] */
                uint8_t * const rci_ber_u8 = rci_ber;
                uint8_t data;
                uint16_t data_value = (uint16_t)value;

                ASSERT(value <= MAX_ONE_BYTE_FOLLOW_VALUE);

                data = BINARY_RCI_SIZE_ALTERNATE_FLAG;
                data |= HIGH8(data_value);
                message_store_u8(rci_ber_u8, opcode, data);

                data =  LOW8(data_value);
                message_store_u8(rci_ber_u8, value, data);

                #undef MAX_ONE_BYTE_FOLLOW_VALUE
                break;
            }
            case record_bytes(rci_ber_u16):
            {
                /* 3 bytes with range [0, 0xFFFF] */
                uint8_t * const rci_ber_u16 = rci_ber;
                uint8_t const opcode = BINARY_RCI_SET_MULTI_FOLLOW_BYTES(binary_rci_two_follow_byte);
                uint16_t const data = (uint16_t)value;

                message_store_u8(rci_ber_u16, opcode, opcode);
                message_store_be16(rci_ber_u16, value, data);
                break;
            }
            case record_bytes(rci_ber_u32):
            {
                /* 5 bytes with range [0, 0xFFFFFFFF */
                uint8_t * const rci_ber_u32 = rci_ber;
                uint8_t const opcode = BINARY_RCI_SET_MULTI_FOLLOW_BYTES(binary_rci_four_follow_byte);

                message_store_u8(rci_ber_u32, opcode, opcode);
                message_store_be32(rci_ber_u32, value, value);

                break;

            }
        }
        rci_buffer_advance(output, total_bytes);
    }
    return overflow;
}

static connector_bool_t rci_output_string(rci_t * const rci, char const * const string, size_t const length)
{

    rci_buffer_t * const output = &rci->buffer.output;
    connector_bool_t overflow = connector_true;

    /* output:  | length | string | */
    if (!rcistr_valid(&rci->output.content))
    {
        /* set up the data and its length */
        overflow = rci_output_uint32(rci, length);
        if (overflow) goto done;
        rci->output.content.data = (uint8_t *)string;
        rci->output.content.length = length;
    }

    if (rci->output.content.length > 0)
    {
        size_t const avail_bytes = rci_buffer_remaining(output);
        size_t const write_bytes = (rci->output.content.length < avail_bytes) ? rci->output.content.length : avail_bytes;

        overflow = rci_output_data(rci, output, (uint8_t  *)rci->output.content.data, write_bytes);
        if (overflow) goto done;

        rci->output.content.data += write_bytes;
        rci->output.content.length -= write_bytes;

    }

    if (rci->output.content.length > 0)
    {
        overflow = connector_true;
        rci->status = rci_status_flush_output;
    }
    else
    {
        clear_rcistr(&rci->output.content);
    }

done:
    return overflow;
}

#if defined RCI_PARSER_USES_IPV4
static connector_bool_t rci_output_ipv4(rci_t * const rci, char const * const string)
{
    rci_buffer_t * const output = &rci->buffer.output;
    connector_bool_t overflow = connector_true;
    size_t const avail_bytes = rci_buffer_remaining(output);

    if (avail_bytes < sizeof(uint32_t))
    {
        goto done;
    }
    else
    {
        uint32_t ipv4 = 0;
        uint8_t * const rci_ber_u32 = rci_buffer_position(output);
        int dot_count = 0;
        size_t i;
        size_t length = strlen(string);
        char aux_string[4] = {'\0', '\0', '\0', '\0'}; /* Three chars plus terminator. */

        size_t index = 0;

        for (i = 0; i < length; i++)
        {
            if (index > sizeof(aux_string) - 1)
                break;

            if (string[i] != '.')
            {
                aux_string[index++] = string[i];
            }

            if (string[i] == '.' || i == (length -1))
            {
                long int val;
                char * endptr;

                val = strtol(aux_string, &endptr, 10);
                if (endptr == NULL || *endptr != '\0' || val < 0 || val > 255)
                {
                    break;
                }

                ipv4 = (ipv4 << 8) | val;
                dot_count++;
                index = 0;
                memset(aux_string, '\0', sizeof aux_string);
            }
        }
        if (dot_count != 4)
        {
            connector_request_id_t request_id;
            request_id.remote_config_request = connector_request_id_remote_config_group_process;
            notify_error_status(rci->service_data->connector_ptr->callback, connector_class_id_remote_config, request_id, connector_invalid_data_range);
            rci->status = rci_status_error;
            overflow = connector_false;
            connector_debug_printf("Invalid IPv4 \"%s\"\n", string);
            goto done;
        }

        message_store_u8(rci_ber_u32, opcode, sizeof ipv4);
        message_store_be32(rci_ber_u32, value, ipv4);

        rci_buffer_advance(output, record_bytes(rci_ber_u32));

        overflow = connector_false;
    }

done:
    return overflow;
}
#endif

static connector_bool_t rci_output_uint8(rci_t * const rci, uint8_t const value)
{
    uint8_t const data = value;
    rci_buffer_t * const output = &rci->buffer.output;

    return rci_output_data(rci, output, &data, sizeof data);
}

#if defined RCI_PARSER_USES_FLOAT
static connector_bool_t rci_output_float(rci_t * const rci, float const value)
{
    float const float_value = value;
    uint32_t float_integer;

    ASSERT(sizeof value == sizeof float_integer);

    memcpy(&float_integer, &float_value, sizeof float_integer);

    return rci_output_uint32(rci, float_integer);
}
#endif

#define rci_output_no_value(rci)    rci_output_uint8((rci), BINARY_RCI_NO_VALUE)
#define rci_output_terminator(rci)  rci_output_uint8((rci), BINARY_RCI_TERMINATOR)

static void rci_output_command_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    uint32_t command_id = 0;

    switch (rci->shared.callback_data.group.type)
    {
        case connector_remote_group_setting:
            switch (rci->shared.callback_data.action)
            {
            case connector_remote_action_set:
                command_id = rci_command_set_setting;
                break;
            case connector_remote_action_query:
                command_id = rci_command_query_setting;
                break;
            }
            break;
        case connector_remote_group_state:
            switch (rci->shared.callback_data.action)
            {
            case connector_remote_action_set:
                command_id = rci_command_set_state;
                break;
            case connector_remote_action_query:
                command_id = rci_command_query_state;
                break;
            }
            break;
    }

    {
        connector_bool_t const overflow = rci_output_uint32(rci, command_id);

        if (!overflow)
        {
            if (remote_config->error_id != connector_success)
                state_call(rci, rci_parser_state_error);
            else
                state_call(rci, rci_parser_state_traverse);
        }
    }

    return;
}

static void rci_output_group_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
    uint32_t encoding_data;

    if (!have_group_id(rci))
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    encoding_data = encode_group_id(get_group_id(rci));

    if (get_group_index(rci) > 1)
        encoding_data |= BINARY_RCI_ATTRIBUTE_BIT;

    {
        connector_bool_t const overflow = rci_output_uint32(rci, encoding_data);

        if (!overflow)
        {
            if (remote_config->error_id != connector_success)
                state_call(rci, rci_parser_state_error);
            else
                set_rci_output_state(rci, rci_output_state_group_attribute);
        }
    }

done:
    return;
}

static connector_bool_t encode_attribute(rci_t * const rci, unsigned int const index)
{
    uint32_t encoding_data;
    connector_bool_t overflow = connector_false;

    if (index > 1)
    {
        #define BINARY_RCI_ATTRIBUTE_TYPE_INDEX                 0x20
        #define BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_ONE_BYTE     31
        #define BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_TWO_BYTES    0x1FFF

        if (index < BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_ONE_BYTE)
        {
            /* attribute output
             * bit |7 | 6 5 | 4 3 2 1 0|
             *     |x | 0 1 | - index -|
             */
            encoding_data = index | BINARY_RCI_ATTRIBUTE_TYPE_INDEX;
        }
        else
        {
            /* attribute must be wrapped around the "attribute type" bits (bits 5 and 6)
             *
             * bit |15 14 13 12 11 10 9 8 7 | 6 5 | 4 3 2 1 0|
             *     |       - index -        | 0 1 | - index -|
             */
            uint16_t encoding_data_high, encoding_data_low;

            ASSERT(index  < BINARY_RCI_MAX_ATTRIBUTE_INDEX_FOR_TWO_BYTES);
            encoding_data_low = index & 0x1F;
            encoding_data_high = index & (~(0x1F));
            encoding_data = (encoding_data_high << 2)| BINARY_RCI_ATTRIBUTE_TYPE_INDEX | encoding_data_low;
        }
        overflow = rci_output_uint32(rci, encoding_data);
    }

    return overflow;
}

static void rci_output_group_attribute(rci_t * const rci)
{
    unsigned int const index = get_group_index(rci);
    connector_bool_t overflow = encode_attribute(rci, index);

    if (!overflow)
       state_call(rci, rci_parser_state_traverse);
}


static void rci_output_field_id(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;

    if (!have_element_id(rci))
    {
        state_call(rci, rci_parser_state_error);
        goto done;
    }

    {
        /* output field id */
        uint32_t id =  encode_element_id(get_element_id(rci));

        if (remote_config->error_id != connector_success) id |= BINARY_RCI_FIELD_TYPE_INDICATOR_BIT;

        {
            connector_bool_t const overflow = rci_output_uint32(rci, id);

            if (overflow) goto done;

            if (remote_config->error_id != connector_success)
                state_call(rci, rci_parser_state_error);
            else
                set_rci_output_state(rci, rci_output_state_field_value);
        }

    }

done:
    return;
}


static void rci_output_field_value(rci_t * const rci)
{
    connector_group_element_t const * const element = get_current_element(rci);
    connector_element_value_type_t const type = element->type;

    connector_bool_t overflow = connector_false;


    switch (rci->shared.callback_data.action)
    {
        case connector_remote_action_set:
            overflow = rci_output_no_value(rci);
            goto done;

        case connector_remote_action_query:
            break;
    }

    switch (type)
    {
#if defined RCI_PARSER_USES_STRINGS

#if defined RCI_PARSER_USES_STRING
    case connector_element_type_string:
#endif

#if defined RCI_PARSER_USES_MULTILINE_STRING
    case connector_element_type_multiline_string:
#endif

#if defined RCI_PARSER_USES_PASSWORD
    case connector_element_type_password:
#endif

#if defined RCI_PARSER_USES_FQDNV4
    case connector_element_type_fqdnv4:
#endif

#if defined RCI_PARSER_USES_FQDNV6
    case connector_element_type_fqdnv6:
#endif

#if defined RCI_PARSER_USES_DATETIME
    case connector_element_type_datetime:
#endif
        ASSERT(rci->shared.value.string_value != NULL);
        overflow = rci_output_string(rci, rci->shared.value.string_value, strlen(rci->shared.value.string_value));
        break;
#endif

#if defined RCI_PARSER_USES_IPV4
    case connector_element_type_ipv4:
        ASSERT(rci->shared.value.string_value != NULL);
        overflow = rci_output_ipv4(rci, rci->shared.value.string_value);
        break;
#endif

#if defined RCI_PARSER_USES_INT32
    case connector_element_type_int32:
        overflow = rci_output_uint32(rci, rci->shared.value.signed_integer_value);
        break;
#endif

#if (defined RCI_PARSER_USES_UNSIGNED_INTEGER)
#if defined RCI_PARSER_USES_UINT32
    case connector_element_type_uint32:
#endif

#if defined RCI_PARSER_USES_HEX32
    case connector_element_type_hex32:
#endif

#if defined RCI_PARSER_USES_0X_HEX32
    case connector_element_type_0x_hex32:
#endif

        overflow = rci_output_uint32(rci, rci->shared.value.unsigned_integer_value);
        break;
#endif

#if defined RCI_PARSER_USES_FLOAT
    case connector_element_type_float:
        overflow = rci_output_float(rci, rci->shared.value.float_value);
        break;
#endif

#if defined RCI_PARSER_USES_ENUM
    case connector_element_type_enum:
        overflow = rci_output_uint32(rci, rci->shared.value.enum_value);
        break;
#endif

#if defined RCI_PARSER_USES_ON_OFF
    case connector_element_type_on_off:
        overflow = rci_output_uint32(rci, rci->shared.value.on_off_value);
        break;
#endif

#if defined RCI_PARSER_USES_BOOLEAN
    case connector_element_type_boolean:
        overflow = rci_output_uint32(rci, rci->shared.value.boolean_value);
        break;
#endif
    }

done:
    if (!overflow)
        state_call(rci, rci_parser_state_traverse);

}

static void rci_output_field_terminator(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;

    connector_bool_t const overflow = rci_output_terminator(rci);
    if (!overflow)
    {
        invalidate_element_id(rci);

        if (remote_config->error_id != connector_success)
            state_call(rci, rci_parser_state_error);
        else
            state_call(rci, rci_parser_state_traverse);
    }
    return;
}

static void rci_output_group_terminator(rci_t * const rci)
{
    connector_remote_config_t const * const remote_config = &rci->shared.callback_data;

    if (remote_config->error_id != connector_success)
    {
        state_call(rci, rci_parser_state_error);
    }
    else
    {
        connector_bool_t const overflow = rci_output_terminator(rci);
        if (overflow) goto done;

        set_rci_output_state(rci, rci_output_state_response_done);
    }

    invalidate_group_id(rci);

done:
    return;
}

static void rci_generate_output(rci_t * const rci)
{
    rci_buffer_t * const output = &rci->buffer.output;

    if ((rci_buffer_remaining(output) != 0))
    {
        rci_debug_printf("output: %s\n", rci_output_state_t_as_string(rci->output.state));

        switch (rci->output.state)
        {
            case rci_output_state_command_id:
                rci_output_command_id(rci);
                break;

            case rci_output_state_group_id:
                rci_output_group_id(rci);
                break;

            case rci_output_state_group_attribute:
                rci_output_group_attribute(rci);
                break;

            case rci_output_state_field_id:
                rci_output_field_id(rci);
                break;

            case rci_output_state_field_value:
                rci_output_field_value(rci);
                break;

            case rci_output_state_field_terminator:
                rci_output_field_terminator(rci);
                break;

            case rci_output_state_group_terminator:
                rci_output_group_terminator(rci);
                break;

            case rci_output_state_response_done:

                if (get_rci_input_state(rci) == rci_input_state_done)
                {
                    trigger_rci_callback(rci, connector_request_id_remote_config_session_end);
                    set_rci_output_state(rci, rci_output_state_done);
                }
                else
                {
                    state_call(rci, rci_parser_state_input);
                    set_rci_input_state(rci, rci_input_state_command_id);
                }
                break;

            case rci_output_state_done:
            {
                connector_remote_config_t const * const remote_config = &rci->shared.callback_data;
                if (remote_config->error_id != connector_success)
                    state_call(rci, rci_parser_state_error);
                else
                    rci->status = rci_status_complete;
                break;
            }
        }
    }
    else if ((rci_buffer_used(&rci->buffer.output) > 0) && (rci->status == rci_status_busy))
    {
        /* We are here since we have no space left for more output data and we have output data waiting to be sent.
           So set up the state to send out the output data and come back to rci */

        rci->status = rci_status_flush_output;
    }


#if defined RCI_DEBUG
    {
        size_t const bytes = rci_buffer_used(&rci->buffer.output);
        if (bytes > 0)
        {
            connector_debug_hexvalue("Response", rci->buffer.output.start, bytes);
        }
    }
#endif

    return;
}


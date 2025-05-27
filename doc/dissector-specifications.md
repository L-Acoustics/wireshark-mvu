# Dissector Specifications

This document describes:

- the list of MVU packets that the dissector should analyze,
- the fields added to the protocol dissector,
- the rules applied to display logic and errors detection.

1. [Any MVU packet](#any-mvu-packet)
1. [Any MVU command](#any-mvu-command)
1. [Any MVU response](#any-mvu-response)
1. [GET_MILAN_INFO command](#get_milan_info-command)
1. [GET_MILAN_INFO response](#get_milan_info-response)
1. [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)
1. [SET_SYSTEM_UNIQUE_ID response](#set_system_unique_id-response)
1. [GET_SYSTEM_UNIQUE_ID command](#get_system_unique_id-command)
1. [GET_SYSTEM_UNIQUE_ID response](#get_system_unique_id-response)
1. [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)
1. [SET_MEDIA_CLOCK_REFERENCE_INFO response](#set_media_clock_reference_info-response)
1. [GET_MEDIA_CLOCK_REFERENCE_INFO command](#get_media_clock_reference_info-command)
1. [GET_MEDIA_CLOCK_REFERENCE_INFO response](#get_media_clock_reference_info-response)
1. [BIND_STREAM command](#bind_stream-command)
1. [BIND_STREAM_RESPONSE](#bind_stream_response)
1. [UNBIND_STREAM command](#unbind_stream-command)
1. [UNBIND_STREAM response](#unbind_stream-response)
1. [GET_STREAM_INPUT_INFO_EX command](#get_stream_input_info_ex-command)
1. [GET_STREAM_INPUT_INFO_EX response](#get_stream_input_info_ex-response)

## Any MVU packet

### Expected information in the packet

| Field                | Protocol         | Description                                    |
| -------------------- | ---------------- | ---------------------------------------------- |
| timestamp            | -                | Frame timestamp in the capture file            |
| message_type         | IEEE 1722.1 AECP | Type of the AECP message                       |
| status               | IEEE 1722.1 AECP | MVU command status                             |
| control_data_length  | IEEE 1722.1 AECP | Length of the Control Data payload             |
| target_entity_id     | IEEE 1722.1 AECP | ID of the target entity                        |
| controller_entity_id | IEEE 1722.1 AECP | ID of the controller entity                    |
| sequence_id          | IEEE 1722.1 AECP | Controller's commands incrementing sequence ID |
| protocol_id          | IEEE 1722.1 AECP | AECP vendor unique protocol                    |
| u                    | MVU              | 1 for responses resulting from a notification  |
| command_type         | MVU              | Type of the MVU command                        |

### Dissector fields

| Field                                  | Display name                | Field Type          |
| -------------------------------------- | --------------------------- | ------------------- |
| `mvu.unsolicited_response`             | Unsolicited Response        | Boolean             |
| `mvu.command_type`                     | Command Type                | Number (enum)       |
| `mvu.status`                           | Status                      | Number (enum)       |
| `mvu.specifications_version`           | -                           | String (generated)  |
| `mvu.has_errors`                       | -                           | Boolean (generated) |
| `mvu.expert.sequence_id_duplicate`     | Sequence ID duplicate error | Expert              |
| `mvu.expert.control_data_length_error` | Control Data Length error   | Expert              |
| `mvu.expert.command_status_error`      | MVU Command Status error    | Expert              |

### Dissector rules

#### Rules for `mvu.command`

Displays the name of the command type with its bytes value.

The MVU message type (Command/Response) is extracted from the IEEE 1722.1
protocol and inserted in the name of the MVU section in the packet tree.

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: GET_MEDIA_CLOCK_REFERENCE_INFO (0x00000004)

#### Rules for `mvu.status`

Replicates the status field from the IEEE 1722.1 protocol.

###### Example

    ▼ Milan Vendor Unique (Command)
        Status: SUCCESS (0x00)

#### Rules for `mvu.specifications_version`

The Milan specifications version is determined by the command_type, message_type and control_data_length values. Typically commands have a first specification version they were introduced with. Then an increased value of control_data_length is associated with a newer specifications version.

The Milan specifications version is also inserted in the Protocol column in the packets list. (e.g. `MVU 1.2`)

###### Example

SET_SYSTEM_UNIQUE_ID was introduced in version 1.2 with a control_data_length of 24 for the command and the response.

    ▼ IEEE 1722.1 Protocol
        .... .000 0001 1000 Control data Length: 24
    ▼ Milan Vendor Unique (Command)
        Command Type: SET_SYSTEM_UNIQUE_ID (0x00000001)
        [Version 1.2]

In version 1.2.10, the new control_data_length of SET_SYSTEM_UNIQUE_ID is 92 for the command and response.

    ▼ IEEE 1722.1 Protocol
        .... .000 0101 1100 Control data Length: 92
    ▼ Milan Vendor Unique (Command)
        Command Type: SET_SYSTEM_UNIQUE_ID (0x00000001)
        [Version 1.2.10]

#### Rules for `mvu.has_errors`

This field is not displayed in the packet tree but can be used in packet filters.

Its value is set to true when at least one error was detected in the packet.

#### Rules for `mvu.expert.sequence_id_duplicate`

This expert field is added to the tree with severity level set to Error when a previous packet in the capture has the same controller_entity_id, sequence_id and message_type.

However, the dissector shall detect when the sequence ID of an entity is reset to 0 which could be a legit behavior when the device is rebooted, and not raise this error in such case.

###### Example

    ▼ Milan Vendor Unique (Command)
      ► Another packet (frame number 20) with this controller entity ID (0x00e04c40902a0082), sequence ID (11) and message type (VENDOR_UNIQUE_RESPONSE) was already parsed.

#### Rules for `mvu.expert.control_data_length_error`

This expert field is added to the tree with severity level set to Error when the control_data_length is unexpected.

This can happen when:

- the control_data_length is smaller than the minimum allowed value of 20
- the control_data_length is greater than the maximum allowed value of 254
- there are not enough bytes in the payload to satisfy the control_data_length
- there are bytes in the payload that exceed the position defined by the control_data_length (with the exception of padding bytes added to achieve the Ethernet minimum frame size)
- in an MVU response with the NOT_IMPLEMENTED_FLAG set to 1, the control_data_length does not have the same value as in the originating MVU command in the packet capture

###### Example

    ▼ Milan Vendor Unique (Command)
      ► Control Data Length (19) is too small for an MVU message (minimum expected: 20)

#### Rules for `mvu.expert.command_status_error`

This expert field is added to the tree with severity level set to Error when the command status value is invalid.

This can happen when:

- the status code is unknown
- a non-response message has the NOT_IMPLEMENTED status code

## Any MVU command

### Expected information in the packet

> No additional fields

### Dissector fields

> No additional fields

### Dissector rules

The MVU message type (Command/Response) is extracted from the IEEE 1722.1 protocol and inserted in the name of the MVU section in the packet tree.

###### Example

    ► Milan Vendor Unique (Command)

## Any MVU response

### Expected information in the packet

> No additional fields

### Dissector fields

> No additional fields

### Dissector rules

The MVU message type (Command/Response) is extracted from the IEEE 1722.1 protocol and inserted in the name of the MVU section in the packet tree.

###### Example

    ► Milan Vendor Unique (Response)

## GET_MILAN_INFO command

### Expected information in the packet

> No additional fields

### Dissector fields

> No additional fields

### Dissector rules

> No additional rules

## GET_MILAN_INFO response

### Expected information in the packet

| Field                 | Description                                           | MVU Protocol Version |
| --------------------- | ----------------------------------------------------- | -------------------- |
| protocol_version      | Milan protocol version supported by the PAAD-AE       | $\geqslant$ 1.1      |
| features_flags        | Bitfield of supported features                        | $\geqslant$ 1.1      |
| certification_version | Milan certification the PAAD-AE has passed            | $\geqslant$ 1.1      |
| specification_version | Milan specifications version supported by the PAAD-AE | $\geqslant$ 1.2.10   |

### Dissector fields

| Field                                 | Display name                          | Field Type |
| ------------------------------------- | ------------------------------------- | ---------- |
| `mvu.protocol_version`                | Protocol Version                      | Number     |
| `mvu.feature_flags`                   | Feature Flags                         | Bitfield   |
| `mvu.feature.redundancy`              | REDUNDANCY                            | Boolean    |
| `mvu.feature.talker_dynamic_mappings` | TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING | Boolean    |
| `mvu.paad_certification_version`      | PAAD certification version            | String     |
| `mvu.paad_specification_version`      | PAAD specification version            | String     |

### Dissector rules

#### Rules for `mvu.paad_certification_version`

This field is inserted in the tree only when its value is not 0x00000000.

###### Example

    ▼ Milan Vendor Unique (Response)
        Command Type: GET_MILAN_INFO (0x00000000)
        [Version 1.1]
        Status: SUCCESS (0x00)
        Protocol Version: 1
        Feature Flags: 0x00000002
        .... .... .... .... .... .... .... ..1. = TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING: True
        .... .... .... .... .... .... .... ...0 = REDUNDANCY: False
        PAAD certification version: 1.1

## SET_SYSTEM_UNIQUE_ID command

### Expected information in the packet

| Field  | Description                                  | MVU Protocol Version |
| ------ | -------------------------------------------- | -------------------- |
| number | Number of the network-wide unique identifier | $\geqslant$ 1.2      |
| name   | Name of the network-wide unique identifier   | $\geqslant$ 1.2.10   |

### Dissector fields

| Field                       | Display name          | Field Type   |
| --------------------------- | --------------------- | ------------ |
| `mvu.system_unique_id`      | System Unique ID      | Number (hex) |
| `mvu.system_unique_id_name` | System Unique ID Name | String       |

### Dissector rules

> No additional rules

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: SET_SYSTEM_UNIQUE_ID (0x00000001)
        [Version 1.2]
        Status: SUCCESS (0x00)
        System Unique ID: 123
        System Unique ID Name: example name

## SET_SYSTEM_UNIQUE_ID response

### Expected information in the packet

> Same as [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)

### Dissector fields

> Same as [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)

### Dissector rules

> Same as [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)

## GET_SYSTEM_UNIQUE_ID command

### Expected information in the packet

> No additional fields

### Dissector fields

> No additional fields

### Dissector rules

> No additional rules

## GET_SYSTEM_UNIQUE_ID response

### Expected information in the packet

> Same as [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)

### Dissector fields

> Same as [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)

### Dissector rules

> Same as [SET_SYSTEM_UNIQUE_ID command](#set_system_unique_id-command)

## SET_MEDIA_CLOCK_REFERENCE_INFO command

### Expected information in the packet

| Field                   | Description                                        | MVU Protocol Version |
| ----------------------- | -------------------------------------------------- | -------------------- |
| clock_domain_index      | Index of the CLOCK_DOMAIN descriptor               | $\geqslant$ 1.2      |
| flags                   | Fields having values to be set                     | $\geqslant$ 1.2      |
| default_mcr_prio        | Default Media Clock Reference priority of the PAAD | $\geqslant$ 1.2      |
| user_mcr_prio           | User Media Clock Reference priority of the PAAD    | $\geqslant$ 1.2      |
| media_clock_domain_name | Name for the Clock Domain                          | $\geqslant$ 1.2      |

### Dissector fields

| Field                                      | Display name                           | Field Type |
| ------------------------------------------ | -------------------------------------- | ---------- |
| `mvu.clock_domain_index`                   | Clock Domain Index                     | Number     |
| `mvu.media_clock_flags`                    | Media Clock Flags                      | Bitfield   |
| `mvu.media_clock.reference_priority_valid` | REFERENCE PRIORITY VALID               | Boolean    |
| `mvu.media_clock.domain_name_valid`        | DOMAIN NAME VALID                      | Boolean    |
| `mvu.default_mcr_priority`                 | Default Media Clock Reference Priority | Number     |
| `mvu.user_mcr_priority`                    | User Media Clock Reference Priority    | Number     |
| `mvu.media_clock.domain_name`              | Media Clock Domain Name                | String     |

### Dissector rules

> No additional rules

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: SET_MEDIA_CLOCK_REFERENCE_INFO (0x00000003)
        [Version 1.2]
        Status: SUCCESS (0x00)
        Clock Domain Index: 0
        Media Clock Flags: 0x00000000
        .... ...0 = REFERENCE PRIORITY VALID: False
        .... ..0. = DOMAIN NAME VALID: False
        Default Media Clock Reference Priority: 128
        User Media Clock Reference Priority: 0
        Media Clock Domain Name: example name

## SET_MEDIA_CLOCK_REFERENCE_INFO response

### Expected information in the packet

> Same as [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)

### Dissector fields

> Same as [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)

### Dissector rules

> Same as [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)

## GET_MEDIA_CLOCK_REFERENCE_INFO command

### Expected information in the packet

| Field              | Description                          | MVU Protocol Version |
| ------------------ | ------------------------------------ | -------------------- |
| clock_domain_index | Index of the CLOCK_DOMAIN descriptor | $\geqslant$ 1.2      |

### Dissector fields

| Field                    | Display name       | Field Type |
| ------------------------ | ------------------ | ---------- |
| `mvu.clock_domain_index` | Clock Domain Index | Number     |

### Dissector rules

> No additional rules

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: GET_MEDIA_CLOCK_REFERENCE_INFO (0x00000004)
        [Version 1.2]
        Status: SUCCESS (0x00)
        Clock Domain Index: 0

## GET_MEDIA_CLOCK_REFERENCE_INFO response

### Expected information in the packet

> Same as [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)

### Dissector fields

> Same as [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)

### Dissector rules

> Same as [SET_MEDIA_CLOCK_REFERENCE_INFO command](#set_media_clock_reference_info-command)

## BIND_STREAM command

### Expected information in the packet

| Field               | Description                                                                            | MVU Protocol Version |
| ------------------- | -------------------------------------------------------------------------------------- | -------------------- |
| flags               | Bitfield parameters accompanying the command                                           | $\geqslant$ 1.2.10   |
| descriptor_type     | Descriptor type of the Listener's Stream Input to bind<br>_See IEEE 1722.1 clause 7.2_ | $\geqslant$ 1.2.10   |
| descriptor_index    | Descriptor index of the Listener's Stream Input to bind                                | $\geqslant$ 1.2.10   |
| talker_entity_id    | Entity ID of the Talker to be bound to                                                 | $\geqslant$ 1.2.10   |
| talker_stream_index | Index of the Talker's STREAM_OUTPUT to be bound to                                     | $\geqslant$ 1.2.10   |

### Dissector fields

| Field                              | Display name             | Field Type    |
| ---------------------------------- | ------------------------ | ------------- |
| `mvu.stream.flags`                 | Stream Flags             | Bitfield      |
| `mvu.stream.flags.streaming_wait`  | Bitfield: STREAMING_WAIT | Bitfield      |
| `mvu.descriptor_type`              | Descriptor Type          | Number (enum) |
| `mvu.descriptor_index`             | Descriptor Index         | Number        |
| `mvu.stream.talker_entity_id`      | Talker Entity ID         | Number (hex)  |
| `mvu.stream.talker_stream_index`   | Talker Stream Index      | Number        |
| `mvu.expert.descriptor_type_error` | Descriptor Type error    | Expert        |

### Dissector rules

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Bind Stream Flags: 0x00000000
        .... ...0 = STREAMING_WAIT: False
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 0
        Talker Entity ID: 0x123456789abcdef0
        Talker Stream Index: 1

#### Rules for `mvu.expert.descriptor_type_error`

This field is inserted when value of `mvu.descriptor_type` is not set to STREAM_INPUT (0x0005).

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Bind Stream Flags: 0x00000000
        .... ...0 = STREAMING_WAIT: False
        Descriptor Type: STREAM_OUTPUT (0x0006)
      ► The Descriptor Type shall be set to STREAM_INPUT (0x0005)

## BIND_STREAM_RESPONSE

### Expected information in the packet

> Same as [BIND_STREAM command](#bind_stream-command)

### Dissector fields

> Same as [BIND_STREAM command](#bind_stream-command)

Additional fields:

| Field                                                 | Display name                             | Field Type |
| ----------------------------------------------------- | ---------------------------------------- | ---------- |
| `mvu.expert.response_replicates_command_values_error` | Response replicates Command values error | Expert     |

### Dissector rules

#### Rules for `mvu.expert.response_replicates_command_values_error`

This field is inserted if any field in the response is not set to the same value as in the command.

###### Example

    ▼ Milan Vendor Unique (Response)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Bind Stream Flags: 0x00000000
        .... ...0 = STREAMING_WAIT: False
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 1
        Talker Entity ID: 0x123456789abcdef2
        Talker Stream Index: 1
        The following fields are not set to the same value as in the command (frame <n>): mvu.descriptor_index, mvu.stream.talker_entity_id

## UNBIND_STREAM command

### Expected information in the packet

| Field            | Description                                               | MVU Protocol Version |
| ---------------- | --------------------------------------------------------- | -------------------- |
| descriptor_type  | Descriptor type of the Listener's Stream Input to unbind  | $\geqslant$ 1.2.10   |
| descriptor_index | Descriptor index of the Listener's Stream Input to unbind | $\geqslant$ 1.2.10   |

### Dissector fields

| Field                              | Display name          | Field Type    |
| ---------------------------------- | --------------------- | ------------- |
| `mvu.descriptor_type`              | Descriptor Type       | Number (enum) |
| `mvu.descriptor_index`             | Descriptor Index      | Number        |
| `mvu.expert.descriptor_type_error` | Descriptor Type error | Expert        |

### Dissector rules

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 0

#### Rules for `mvu.expert.descriptor_type_error`

This field is inserted when value of `mvu.descriptor_type` is not set to STREAM_INPUT (0x0005).

###### Example

    ▼ Milan Vendor Unique (Command)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_OUTPUT (0x0006)
      ► The Descriptor Type shall be set to STREAM_INPUT (0x0005)

## UNBIND_STREAM response

### Expected information in the packet

> Same as [UNBIND_STREAM command](#unbind_stream-command)

### Dissector fields

> Same as [UNBIND_STREAM command](#unbind_stream-command)

Additional fields:

| Field                                                 | Display name                             | Field Type |
| ----------------------------------------------------- | ---------------------------------------- | ---------- |
| `mvu.expert.response_replicates_command_values_error` | Response replicates Command values error | Expert     |

### Dissector rules

#### Rules for `mvu.expert.response_replicates_command_values_error`

This field is inserted if any field in the response is not set to the same value as in the command.

###### Example

    ▼ Milan Vendor Unique (Response)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 1
        The following fields are not set to the same value as in the command (frame <n>): mvu.descriptor_index

## GET_STREAM_INPUT_INFO_EX command

### Expected information in the packet

> Same as [UNBIND_STREAM command](#unbind_stream-command)

### Dissector fields

> Same as [UNBIND_STREAM command](#unbind_stream-command)

### Dissector rules

> Same as [UNBIND_STREAM command](#unbind_stream-command)

## GET_STREAM_INPUT_INFO_EX response

### Expected information in the packet

| Field            | Description                                                    | MVU Protocol Version |
| ---------------- | -------------------------------------------------------------- | -------------------- |
| descriptor_type  | Descriptor type of the Listener's Stream Input                 | $\geqslant$ 1.2.10   |
| descriptor_index | Descriptor index of the Listener's Stream Input                | $\geqslant$ 1.2.10   |
| talker_entity_id | Entity ID of Talker if sink_state $\geqslant$ 1                | $\geqslant$ 1.2.10   |
| talker_stream_id | Index of Talker Stream Output                                  | $\geqslant$ 1.2.12   |
| pbsta            | Probing status of the Stream Input                             | $\geqslant$ 1.2.12   |
| acmpsta          | ACMP status of the Stream Input (when pbsta is PROBING_ACTIVE) | $\geqslant$ 1.2.12   |

### Dissector fields

| Field                              | Display name          | Field Type    |
| ---------------------------------- | --------------------- | ------------- |
| `mvu.descriptor_type`              | Descriptor Type       | Number (enum) |
| `mvu.descriptor_index`             | Descriptor Index      | Number        |
| `mvu.stream.talker_entity_id`      | Talker Entity ID      | Number (hex)  |
| `mvu.stream.talker_stream_id`      | Talker Stream ID      | Number        |
| `mvu.stream.probing_status`        | Probing Status        | Number (enum) |
| `mvu.stream.acmp_status`           | ACMP Status           | Number (enum) |
| `mvu.expert.descriptor_type_error` | Descriptor Type error | Expert        |

### Dissector rules

###### Example

    ▼ Milan Vendor Unique (Response)
        Command Type: GET_STREAM_INPUT_INFO_EX (0x00000007)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 0
        Talker Entity ID: 0x1d365f4b159e870a
        Talker Stream ID: 0
        Probing Status: PROBING_ACTIVE (2)
        ACMP Status: TALKER_DEST_MAC_FAIL (3)

#### Rules for `mvu.expert.descriptor_type_error`

This field is inserted when value of `mvu.descriptor_type` is not set to STREAM_INPUT (0x0005).

###### Example

    ▼ Milan Vendor Unique (Response)
        Command Type: GET_STREAM_INPUT_INFO_EX (0x00000007)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_OUTPUT (0x0006)
      ► The Descriptor Type shall be set to STREAM_INPUT (0x0005)

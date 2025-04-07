The sample capture files contain use cases for testing the results of the dissector in Wireshark

- [BIND_STREAM](#bind_stream)
  - [Case 1: no errors](#case-1-no-errors)
  - [Case 2: descriptor type error](#case-2-descriptor-type-error)
  - [Case 3: response does not contain the same values as the command](#case-3-response-does-not-contain-the-same-values-as-the-command)
- [UNBIND_STREAM](#unbind_stream)
  - [Case 1: no errors](#case-1-no-errors-1)
  - [Case 2: descriptor type error](#case-2-descriptor-type-error-1)
  - [Case 3: response does not contain the same values as the command](#case-3-response-does-not-contain-the-same-values-as-the-command-1)

# BIND_STREAM

## Case 1: no errors

### Capture content

    # BIND_STREAM command
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 06
    0010  00 24 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 05 00 01 00 05
    0030  00 03 00 00 00 00 00 00 00 04 00 05 00 00

    # BIND_STREAM response
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 07
    0010  00 24 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 05 00 01 00 05
    0030  00 03 00 00 00 00 00 00 00 04 00 05 00 00

### Expected packet trees in Wireshark

Packet 1

    Milan Vendor Unique (Command)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Stream Flags: 0x0001
        .... .... .... ...1 = STREAMING_WAIT: True
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3
        Talker Entity ID: 0x0000000000000004
        Talker Stream Index: 5

Packet 2

    Milan Vendor Unique (Response)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Stream Flags: 0x0001
        .... .... .... ...1 = STREAMING_WAIT: True
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3
        Talker Entity ID: 0x0000000000000004
        Talker Stream Index: 5

## Case 2: descriptor type error

### Capture content

    # BIND_STREAM command
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 06
    0010  00 24 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 05 00 01 00 06
    0030  00 03 00 00 00 00 00 00 00 04 00 05 00 00

    # BIND_STREAM response
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 07
    0010  00 24 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 05 00 01 00 07
    0030  00 03 00 00 00 00 00 00 00 04 00 05 00 00

### Expected packet trees in Wireshark

Packet 1

    Milan Vendor Unique (Command)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Stream Flags: 0x0001
        .... .... .... ...1 = STREAMING_WAIT: True
        Descriptor Type: STREAM_OUTPUT (0x0006)
        Descriptor Index: 3
        Talker Entity ID: 0x0000000000000004
        Talker Stream Index: 5
        The Descriptor Type shall be set to STREAM_INPUT (0x0005)
            [Expert Info (Error/Protocol): The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [Severity level: Error]
                [Group: Protocol]

Packet 2

    Milan Vendor Unique (Response)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Stream Flags: 0x0001
        .... .... .... ...1 = STREAMING_WAIT: True
        Descriptor Type: JACK_INPUT (0x0007)
        Descriptor Index: 3
        Talker Entity ID: 0x0000000000000004
        Talker Stream Index: 5
        The Descriptor Type shall be set to STREAM_INPUT (0x0005)
            [Expert Info (Error/Protocol): The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [Severity level: Error]
                [Group: Protocol]

## Case 3: response does not contain the same values as the command

### Capture content

    # BIND_STREAM command
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 06
    0010  00 24 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 05 00 01 00 05
    0030  00 03 00 00 00 00 00 00 00 04 00 05 00 00

    # BIND_STREAM response
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 07
    0010  00 24 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 05 00 01 00 05
    0030  00 03 00 00 00 00 01 00 00 04 00 05 00 00

### Expected packet trees in Wireshark

Packet 1

    Milan Vendor Unique (Command)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Stream Flags: 0x0001
        .... .... .... ...1 = STREAMING_WAIT: True
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3
        Talker Entity ID: 0x0000000000000004
        Talker Stream Index: 5

Packet 2

    Milan Vendor Unique (Response)
        Command Type: BIND_STREAM (0x00000005)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Stream Flags: 0x0001
        .... .... .... ...1 = STREAMING_WAIT: True
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3
        Talker Entity ID: 0x0000000000001004
        Talker Stream Index: 5
        The following fields are not set to the same value as in the command (frame 1): mvu.stream.talker_entity_id
            [Expert Info (Error/Protocol): The following fields are not set to the same value as in the command (frame 1): mvu.stream.talker_entity_id]
                [The following fields are not set to the same value as in the command (frame 1): mvu.stream.talker_entity_id]
                [Severity level: Error]
                [Group: Protocol]

# UNBIND_STREAM

## Case 1: no errors

### Capture content

    # UNBIND_STREAM command
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 06
    0010  00 18 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 06 00 01 00 05
    0030  00 03

    # UNBIND_STREAM response
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 07
    0010  00 18 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 06 00 00 00 05
    0030  00 03

### Expected packet trees in Wireshark

Packet 1

    Milan Vendor Unique (Command)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3

Packet 2

    Milan Vendor Unique (Response)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3

## Case 2: descriptor type error

### Capture content

    # UNBIND_STREAM command
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 06
    0010  00 18 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 06 00 01 00 06
    0030  00 03

    # UNBIND_STREAM response
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 07
    0010  00 18 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 06 00 00 00 07
    0030  00 03

### Expected packet trees in Wireshark

Packet 1

    Milan Vendor Unique (Command)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_OUTPUT (0x0006)
        Descriptor Index: 3
        The Descriptor Type shall be set to STREAM_INPUT (0x0005)
            [Expert Info (Error/Protocol): The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [Severity level: Error]
                [Group: Protocol]

Packet 2

    Milan Vendor Unique (Response)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: JACK_INPUT (0x0007)
        Descriptor Index: 3
        The Descriptor Type shall be set to STREAM_INPUT (0x0005)
            [Expert Info (Error/Protocol): The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [The Descriptor Type shall be set to STREAM_INPUT (0x0005)]
                [Severity level: Error]
                [Group: Protocol]

## Case 3: response does not contain the same values as the command

### Capture content

    # UNBIND_STREAM command
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 06
    0010  00 18 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 06 00 01 00 05
    0030  00 03

    # UNBIND_STREAM response
    0000  00 e0 4c 40 90 2a 00 1b 92 05 08 70 22 f0 fb 07
    0010  00 18 00 1b 92 ff ff 05 08 70 00 e0 4c 40 90 2a
    0020  00 01 00 01 00 1b c5 0a c1 00 00 06 00 00 00 05
    0030  00 04

### Expected packet trees in Wireshark

Packet 1

    Milan Vendor Unique (Command)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 3

Packet 2

    Milan Vendor Unique (Response)
        Command Type: UNBIND_STREAM (0x00000006)
        [Version 1.2.10]
        Status: SUCCESS (0x00)
        Descriptor Type: STREAM_INPUT (0x0005)
        Descriptor Index: 4
        The following fields are not set to the same value as in the command (frame 1): mvu.descriptor_index
            [Expert Info (Error/Protocol): The following fields are not set to the same value as in the command (frame 1): mvu.descriptor_index]
                [The following fields are not set to the same value as in the command (frame 1): mvu.descriptor_index]
                [Severity level: Error]
                [Group: Protocol]

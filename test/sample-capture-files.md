The sample capture files contain use cases for testing the results of the dissector in Wireshark

# BIND_STREAM

## Case 1: no errors

### Capture content

    # BIND_STREAM command
    2025-04-03T14:32:57+02:00
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

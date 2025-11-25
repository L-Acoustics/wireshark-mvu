# Diagnostic fields

## Commands

### associated_response_frame_number

#### Rule

directly implied by associated commands of responses

### is_retry_command

#### Rule

set to true if and only if at least one previous command exists

### is_unexpected_retry_command

#### Rule

set to true if at least one preceding command received a command in time (<= 250 ms)
or if a previous command exists and the timestamp difference with the previous command is lower than 250 ms

### has_missing_retry

#### Rule

set to true if and only if:

- the command has no associated response
- the command is not an unexpected retry command
- and there are no following commands

## Responses

### associated_command_frame_number

#### Rule

if n>0 exists so that the reponse is immediately preceded by a group of n+1 commands then n responses:

- set to frame number of last command in that group
- remap the n+1 commands and responses with 1:1 rule

elseif immediately preceded by a command:

- set to frame number of the immediately preceding command

else:

- set to nil

### is_unexpected_response

#### Rule

set to true if and only if:

- the response has no associated command
- and the command is associated to one of the following protocols: AEM, MVU
- and the Unsolicited Response flag is not set

## Conversations/Streams

A conversation, or a stream, is a collection of AECP messages that are related.

Messages are related if:

- they have the same Target Entity ID
- they have the same Controller Entity ID
- they have the same Sequence ID
- consecutive messages have a timestamp difference lower than 2 seconds

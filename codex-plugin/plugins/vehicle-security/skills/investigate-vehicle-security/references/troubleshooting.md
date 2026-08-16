# Troubleshooting and Fast Recovery

Classify a failure before changing tools.

| Class | Check | Recovery |
| --- | --- | --- |
| Input | hash, size, truncation, capture start/end, expected format | reacquire or compare with a known-good sample |
| Format | magic, byte order, framing, CAN FD flags, encapsulation | convert a copy, narrow the stream, inspect raw bytes |
| Environment | tool version, PATH, architecture, libraries, device state | record versions, select a compatible runtime or container |
| Permission | file access, device access, debugger attach, interface group | verify the exact resource and use the narrow required permission |
| Dependency | decoder, symbols, keys, DBC, updater, hardware | name the missing item and continue with independent evidence |
| Timeout/size | output truncation, huge database, broad search | scope by segment, ID, stream, time range, function, or file subset |
| Protocol state | session, security level, sequence, timing, addressing | reconstruct the timeline and record negative responses/state changes |
| Tool limitation | unsupported format, analysis disagreement, parser crash | use a second parser and preserve both outputs |
| Hypothesis failure | expected signal absent with adequate coverage | record counterevidence and rank the competing explanation |

Change one variable at a time. After two equivalent failures, stop retrying the same action. Switch representation or evidence source: capture to stream, stream to minimal bytes, bytes to parser, parser to code references, static to runtime, runtime to logs, or primary tool to a second implementation.

When asking for missing data, request the smallest item that changes the next decision, and state exactly which hypothesis it will distinguish.

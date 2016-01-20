# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | Technique |
|------|-----------|
| fastbin_dup.c | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. |
| fastbin_dup_into_stack.c | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. |

## Other resources

Some good heap exploitation resources are:

- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques

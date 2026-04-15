# AT Task Entry function

Date: 01-04-2026/04-04-2026
Address: 0x000dd4c6

## What it does (I think)

- It's the entry point for the AT command handling task.
- It enters an infinite loop where first waits for a message using receive_message().
- If the message is empty, break, if not, then process the message using process_message().
- After processing the message, it checks the message queue for more messages to process (the second while loop).
- After completing it frees the message each time.

## Important functions

- receive_message (0x00131c40) listens for incoming messages on the AT queue.
- process_message (0x000da7e0) processes incoming non-empty message.
- free (0x000d770e) frees a message after usage?

## Global variables

- message_head (DAT_0080be18) head of message in linked list.
- DAT_0080be07 some state that needs to be active in order to process messages in queue.
- DAT_0080be0d flag that needs to be equal to the 0 character in order to process messages in queue.
- DAT_0080be0e flag that needs to be equal to the 0 character in order to process messages in queue.

## Other notes

- Inner while loop goes over the entire linked list?
- Each message has a next pointer at +0 and its message data at +1.
- process_message is where AT command handling happens.

### Mapped out function from Ghidra
```
void at_task_entry(void)

{
  undefined4 uVar1;
  int in_r3;
  int local_18;
  undefined4 *message;
  undefined4 *message_data;
  
  local_18 = in_r3;
  uVar1 = FUN_000d7758();
  FUN_0012d348(0xaf,0x32ff,uVar1);
  uVar1 = FUN_00131c14(0xf);
  FUN_000d84e4(0xf,9,uVar1,0);
  DAT_00811b96 = 0;
  while( true ) {
                    /* not sure about this one, but looking at the pattern I guess it is related to
                       receiving a message, then check if its empty, if its not it processes it? */
    receive_message(uVar1,&local_18);
                    /* if message is empty, break */
    if (local_18 == 0) break;
                    /* do something when it receives a message */
    process_message();
                    /* message validation */
    while ((((DAT_0080be0d == '\0' && (message_head != NULL)) && (DAT_0080be0e == '\0')) &&
           (DAT_0080be07 == '\x01'))) {
      FUN_000dd548(2);
      message = message_head;
                    /* move pointer to next message in queue */
      message_data = message_head + 1;
      message_head = (void *)*message_head;
      process_message(*message_data);
                    /* not sure about this one, but most likely a free? */
      free(message);
    }
  }
  return;
}
```

# Process_message function

Date: 05-04-2026/ 06-04-2026
Address: 0x000da7e0

## Mapped out functions

- message_malloc (0x000d7c16) function for dynamically allocating memory.
- message_sprintf (0x000d872e) function for building the total character string.

## AT commands mapping
note: Command ID = corresponding hex code for the AT command
| Command ID | AT Command | Handler Function | Notes |
|------------|------------|------------------|-------|
| 0x1815     | +CFUN      | Inline           | reads message_data[2] and replaces value with 4 if its not either 0 or 1. The command sets the functional mode to different modes, where 1 = full functionality mode, but %XSYSTEMMODE needs to be set to its correct state first. FOund at: 0x000dab12. |
| 0x1a21     | %XNEWCID   | Inline           | Allocates 16 bytes and formats AT_string with message_data[2]. Found at: 0x000dacca. |
| 0x1a23     | %XGETPDNID | Inline           | Same as above. Found at: 0x000dacca. |
| 0x1849     | %XTEMP     | Inline           | Something related with meassuring the temperature. Found at: 0x000dae34. |

CFUN value:
line 30: command_ID = (uint)*message_data; (not sure if the command_ID is the first field of *message_data)
line 69: iVar3 = command_ID - 0x1839;
line 189: if (iVar3 == 0xff), so iVar must equal to 0xff in this case.

therefore: command_ID = 0xff + 0x1839 = 0x1815.

XTEMP:
line 340: else ... according to line 189 if (iVar3 != 0x10), so iVar3 == 0x10 in the else.
line 69: iVar3 = command_ID - 0x1839;

therefore: command_ID = 0x10 + 0x1839 = 0x1849.

## Potential vulnerabilities

message_buffer - derived since it uses a function with the value 0x1e, which is 30 in decimal. and is used in sprintf as the first variable, so if it is indeed the message buffer that would make sense since first parameter is the buffer.
message_sprintf (0x000dab12) - derived based on the function signature.

malloc locations worth looking into for potential buffer overflows:
- 0x000da892
- 0x000da8a4
- 0x000dab06
- 0x000daed6
- 0x000dacc2
- 0x000dace4
- 0x000dace4

### Fuzzing targets
**AFL -fuzz als fuzzer gebruiken in Unicorn**

- The primary fuzzing target is message_data structure that gets passed into process_messages().
<br>
- The fuzzer will need to bypass initial checks by using valid command_ID's, since it uses a switch case in process_message(). Any garbage command_ID will get caught as an error.
<br>
- Commands like CFUN require the LTE modem to be in a specific activated state (according to commands documentation). So fuzzer would have to first send some initialization commands with a SET command that sets AT%XSYSTEMMODE to some specific state, or else the fuzzer input will not reach far. At 0x00077d90 the System mode is set to GNSS ON: "AT%XSYSTEMMODE=0,0,1,0" (found with string search), which will make it so that we can reach CFUN=1 without getting rejected, but this would not work since we need <LTE_M_support> to at least be turned on. When we fuzz, we will modify AT%XSYSTEMMODE=0,0,1,0" sub-parameters to be at least: 1,0,0,0 or 1,1,0,0.
<br>
- Potential heap-based buffer overflows at the malloc locations.

### Deeper targets worth exploring as well inside process_message:

- FUN_00141afc (handles unrecognized commands)
- FUN_000db380 I found this function which concatenates strings, line 54 the function goes over the entire string until it reaches "\0" and increments, which is likely strlen() function. line 56 uses string lenght concatenation for malloc(), which could be a vulnerability maybe?
- FUN_000dca68
- FUN_000dcadc
- FUN_000dc2a0
- FUN_000dc50e
- FUN_000dc570
- FUN_000dbec4
- FUN_000dbe00
- FUN_000dc834
- FUN_000dc95c
- FUN_000dc8f4

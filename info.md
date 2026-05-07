# SVC-Handlers

There are multiple `svc` instructions in the firmware. These are somewhat similar to Linux' `syscalls` and are essentially a way to escalate priviliges from the running unpriviliged code to some priviliged functionality.

In ARMv8-M / other ARM cortex M processors, the SVC handler is located at index 11 in the exception handler table. The exception handler table starts at `0x00050404` with the `RESET` handler and indeed at index 11 == `0x00050404+11*4 -> 0x0050438` we can find a pointer to the `SVC` handler. 

Each `svc` instruction has an index as there are multiple priviliged operations the firmware might want to execute (scheduling another task/sleep/getting uuid etc). The actual instruction is encoded in `$r3`. The `SVC` handler retrieves this argument and uses it to branch to a function pointer in its svc handler table. See `0x0050438 -> 0x0005f9e8` with the svc handler table at `0x00060bf8` :
```
  if (param_1 == 0xb) {
    pcVar3 = (code *)(&svc_handlers)[*(int *)(param_2 + 0x34)];
    FUN_00066998(0xc,0x981,pcVar3);
    uVar2 = (*pcVar3)(*(undefined4 *)(param_2 + 0x28),*(undefined4 *)(param_2 + 0x2c),
                      *(undefined4 *)(param_2 + 0x30),param_2);
    *(undefined4 *)(param_2 + 0x28) = uVar2;
  }
```

So if you want to know what happens whenever the firmware executes a `svc` instruction you can always find the index in `$r3` and find the handler function in the svc handler table at `0x00060bf8 + 4*$r3`.

# Important Functions

We can also use this knowledge to reason about what certain functions might be doing:

## Pal_MsgSendTo (0x00131ce8) (We may need to hook this/accept that we cannot run this)

This function puts a message in a taks's queue and asks the OS to schedule that particular task; done in `0x000d7ebc` issuing an svc call with index 0x14.

When the full system is set up the OS would schedule the other task and the other task would continue its `while .. true` loop whilst checking its message queue. I would probably try to focus on other functions, but if needed we could always manually adjust the program counter (`$pc`) and try to save some local values (registers/stack etc).

## Sleep (0x000d7ee6) (This you should hook/probably skip if needed)

svc call with index 0x18. So anything that calls this function is a sleep-like function (sleep-ns/sleep-ms/sleep-etc). For example `0x000d8b84` is probably `sleep_ns`.


## Alloc (Needs to be hooked; returns a pointer)
This is important to hook as the firmware might use heap buffers. I would recommend to allocate a large memory pool before starting the emulator (with `mu.mem_map`) and keeping an internal iterator to keep on allocating memory chunks from this large pool when an alloc function is called. Some alloc are:
- `0x000d753e` (presumably this takes a type and number of that type as input args, so num = 4, type = 1 means 4 chars I think, but not sure)
- `0x000d7c16`
- `0x0005c0f4`


## Free
(do the inverse of alloc in a hook, but make sure to **hook**)
- `0x000d770e` (calls svc 0x9c if the allocation is in some memory region otherwise jumps to a function that seems to use a bitmap)



## Diag tracing functions (I think)

There are some functions that likely write something to a ring buffer (although not 100% sure). For now I would hook them and simply skip the functions (aka a hook where you overwrite PC with the LR or **maybe add a print to log them as well**):
- `0x0012d534`
- `0x0012d55e`
- `0x00066998`
- `0x0012d348`
- `0x0012cf40`
- `0x00066a24`


There are a bunch more, but they all have a similar structure to the ones above. They take some id in `$r0` and some buffer in `$r2` (`$r1` seems to be unused).

## Some nice to know functions, no need to hook these

### Memops
- `memcpy`
    - `0x000589ae`

- `memclr` (aka memset with \x00):
    - `0x00058aac`

- `snprintf`:
    - `0x0005ecbc`

Again there are probably more of these.

### get_qid (0x00131c14)

Get the queue id for a specific task, typically used for sending / receiving messages via the message queue.

### OS_TaskCreate

at `0x000d7e9c` issuing an svc with index 0x12. Jumps via the svc handler to `0x0005c9ac`.

### OS_getCurrentTask

at `0x000d7758` issuing an svc with index 0xc. Jumps via the svc handler to 

### Global Taskarray

This array (`0x0080a4e0`) contains the task structs of all the tasks in the firmware. Each struct consists of:
- `queueid` (the queue id; -1 at init)
- `unk1` (unknown)
- `name_ptr` (pointer to the task's name)
- `stacksize` (the task's stack size)
- `fn_ptr` (pointer to the task's entry function)
- `unk2` (unknown)
- `unk3` (unknown)


# Additional mapping

In the original readme there was some information about the memory included. Upon further inspection, there are some additions:
- In the `reset_handler` (`0x0005a918`) there seems to be a copy code snippet (1) that copies memory from `0x69658-0x69e20` to `0x800000-0x8007c8`. 
- At address `0x0005aef6` (called from the `reset_handler`) there seems to be a copy function (2) that copies the memory between `0x1bf238-0x1bf238` to `0x80a000-0x80be88`. 

To deal with the above, add another memory mapping entry in ghidra as follows:
    - Remove the `modem_m4_data_tcm` entry and add the following entries:
        - `modem_m4_data_tcm_copy_0x69658`, start_address = 0x800000, size = 0x7c8, initialized (file bytes), file_offset = 0x19658
        - `modem_m4_data_tcm1`, start_address = 0x8007c8, size = 0x9838, uninitialized
        - `modem_m4_data_tcm_copy_0x1bf238`, start_address = 0x80a000, size = 0x1e88, initialized (file bytes), file_offset = 0x16f238
        - `modem_m4_data_tcm2`, start_address = 0x80be88, size = 0x34178, uninitialized

(1)
```
  puVar2 = &DAT_00069658;
  for (puVar3 = (undefined4 *)&DAT_00800000; puVar3 < &DAT_008007c8; puVar3 = puVar3 + 1) {
    uVar4 = *puVar2;
    puVar2 = puVar2 + 1;
    *puVar3 = uVar4;
  }
```
(2)
```
void FUN_0005aef6(void)

{
  undefined *puVar1;
  undefined *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  puVar2 = PTR_DAT_0006a41c;
  for (puVar3 = (undefined4 *)PTR_DAT_0006a418; puVar1 = PTR_DAT_0006a414,
      puVar4 = (undefined4 *)PTR_DAT_0006a410, puVar5 = (undefined4 *)PTR_DAT_0006a40c,
      puVar3 < puVar2; puVar3 = puVar3 + 1) {
    *puVar3 = 0;
  }
  for (; puVar4 < puVar1; puVar4 = puVar4 + 1) {
    *puVar4 = *puVar5;
    puVar5 = puVar5 + 1;
  }
  FUN_0005ffa4();
  return;
}
```



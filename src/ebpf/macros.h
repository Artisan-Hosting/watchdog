#ifndef PT_REGS_PARM4
#if defined(__TARGET_ARCH_x86)
  // For x86_64, the 4th parameter is in rdx.
  #define PT_REGS_PARM4(ctx) ((ctx)->dx)
#elif defined(__TARGET_ARCH_arm64)
  // For arm64, parameters are in the regs array; parameter 3 is at index 2.
  #define PT_REGS_PARM4(ctx) ((ctx)->regs[3])
#else
  #error Unsupported target architecture!
#endif
#endif

#ifndef PT_REGS_PARM3
#if defined(__TARGET_ARCH_x86)
  // For x86_64, the 3rd parameter is in rdx.
  #define PT_REGS_PARM3(ctx) ((ctx)->dx)
#elif defined(__TARGET_ARCH_arm64)
  // For arm64, parameters are in the regs array; parameter 3 is at index 2.
  #define PT_REGS_PARM3(ctx) ((ctx)->regs[2])
#else
  #error Unsupported target architecture!
#endif
#endif

#ifndef PT_REGS_PARM2
#if defined(__TARGET_ARCH_x86)
  // For x86_64, the 2nd parameter is in rdx.
  #define PT_REGS_PARM2(ctx) ((ctx)->dx)
#elif defined(__TARGET_ARCH_arm64)
  // For arm64, parameters are in the regs array; parameter 3 is at index 2.
  #define PT_REGS_PARM2(ctx) ((ctx)->regs[1])
#else
  #error Unsupported target architecture!
#endif
#endif
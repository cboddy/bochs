
#ifndef __BX_LLVM__
#define __BX_LLVM__

#include "cpu/instr.h"

typedef struct {
  void (BX_CPU_C::*cpu_loop)(Bit32u);
  void (BX_CPU_C::*initialize)(void);
  void (BX_CPU_C::*sanity_checks)(void);
  void (BX_CPU_C::*register_state)(void);
  void (BX_CPU_C::*atexit)(void);
  void (BX_CPU_C::*after_restore_state)(void);
  bx_bool (BX_CPU_C::*SetCR0)(bx_address val) BX_CPP_AttrRegparmN(1);
  void (BX_CPU_C::*jump_protected)(bxInstruction_c *i, Bit16u cs, bx_address disp) BX_CPP_AttrRegparmN(3);
  void (BX_CPU_C::*handleCpuModeChange)(void);
  void (BX_CPU_C::*set_INTR)(bx_bool value);
  void (BX_CPU_C::*TLB_flush)(void);
  void (BX_CPU_C::*TLB_invlpg)(bx_address laddr);
  void (BX_CPU_C::*reset)(unsigned source);

  void (*apic_bus_deliver_smi)(void);
  int (*apic_bus_deliver_interrupt)(Bit8u vector, apic_dest_t dest, Bit8u delivery_mode, bx_bool logical_dest, bx_bool level, bx_bool trig_mode);
  void (*handleSMC)(bx_phy_address pAddr, Bit32u mask);

  bxPageWriteStampTable *pageWriteStampTable;
  void (bxPageWriteStampTable::*decWriteStamp1)(bx_phy_address pAddr);
  void (bxPageWriteStampTable::*decWriteStamp)(bx_phy_address pAddr, unsigned len);

} cpu_methods;

extern cpu_methods bx_cpu_methods;

#define BX_CPU_METHOD( xmeth ) (BX_CPU(0)->*bx_cpu_methods.xmeth )

#endif

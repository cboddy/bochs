// clang++ -I. -Iinstrument/stubs $(llvm-config --cxxflags ) fib.cpp -emit-llvm -c -o fib.bc

#include "bochs.h"
#include "cpu/cpu.h"
#include "llvm.h"

extern BOCHSAPI BX_CPU_C* bx_cpu_ptr;

extern "C" {

  void llvm_init() {
    bx_cpu_ptr = new BX_CPU_C();
    bx_cpu_methods.cpu_loop = &BX_CPU_C::cpu_loop;
    bx_cpu_methods.initialize = &BX_CPU_C::initialize;
    bx_cpu_methods.sanity_checks = &BX_CPU_C::sanity_checks;
    bx_cpu_methods.register_state = &BX_CPU_C::register_state;
    bx_cpu_methods.atexit = &BX_CPU_C::atexit;
    bx_cpu_methods.after_restore_state = &BX_CPU_C::after_restore_state;
    bx_cpu_methods.SetCR0 = &BX_CPU_C::SetCR0;
    bx_cpu_methods.jump_protected = &BX_CPU_C::jump_protected;
    bx_cpu_methods.handleCpuModeChange = &BX_CPU_C::handleCpuModeChange;
    bx_cpu_methods.set_INTR = &BX_CPU_C::set_INTR;
    bx_cpu_methods.TLB_flush = &BX_CPU_C::TLB_flush;
    bx_cpu_methods.TLB_invlpg = &BX_CPU_C::TLB_invlpg;
    bx_cpu_methods.reset = &BX_CPU_C::reset;
    
    bx_cpu_methods.apic_bus_deliver_interrupt = &apic_bus_deliver_interrupt;
    bx_cpu_methods.handleSMC = &handleSMC;
    bx_cpu_methods.pageWriteStampTable = &pageWriteStampTable;

    bx_cpu_methods.decWriteStamp1 = &bxPageWriteStampTable::decWriteStamp1;
    bx_cpu_methods.decWriteStamp = &bxPageWriteStampTable::decWriteStamp;

  }
}

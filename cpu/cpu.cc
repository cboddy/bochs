/////////////////////////////////////////////////////////////////////////
// $Id: cpu.cc,v 1.319 2011/01/26 11:48:13 sshwarts Exp $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2009  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

#include "iodev/iodev.h"
#include "sha1.h"

// Make code more tidy with a few macros.
#if BX_SUPPORT_X86_64==0
#define RIP EIP
#define RCX ECX
#endif

#define InstrumentICACHE 0

#if InstrumentICACHE
static unsigned iCacheLookups=0;
static unsigned iCacheMisses=0;

#define InstrICache_StatsMask 0xffffff

#define InstrICache_Stats() {\
  if ((iCacheLookups & InstrICache_StatsMask) == 0) { \
    BX_INFO(("ICACHE lookups: %u, misses: %u, hit rate = %6.2f%% ", \
          iCacheLookups, \
          iCacheMisses,  \
          (iCacheLookups-iCacheMisses) * 100.0 / iCacheLookups)); \
    iCacheLookups = iCacheMisses = 0; \
  } \
}
#define InstrICache_Increment(v) (v)++
#else
#define InstrICache_Stats()
#define InstrICache_Increment(v)
#endif

// The CHECK_MAX_INSTRUCTIONS macro allows cpu_loop to execute a few
// instructions and then return so that the other processors have a chance to
// run.  This is used by bochs internal debugger or when simulating
// multiple processors.
//
// If maximum instructions have been executed, return. The zero-count
// means run forever.
#if BX_SUPPORT_SMP || BX_DEBUGGER
  #define CHECK_MAX_INSTRUCTIONS(count) \
    if ((count) > 0) {                  \
      (count)--;                        \
      if ((count) == 0) return;         \
    }
#else
  #define CHECK_MAX_INSTRUCTIONS(count)
#endif

/*
egrep ' (process_measurement|kernel_read|kfree|security_file_mmap|kmem_cache_alloc_trace|kmalloc_caches|__destroy_inode|integrity_inode_free)$' build/System.map
c10ed600 T kfree
c10ed850 T kmem_cache_alloc_trace
c10f6690 T kernel_read
c11cc8f0 T security_file_mmap
c11e7910 t process_measurement
c19a91a0 B kmalloc_caches
*/

#if 0
// kernel 3.2.0-rc5+
#define PROCESS_MEASUREMENT_ADDR        0xc11e5aa0
#define KERNEL_READ_ADDR                0xc10f1e80
#define KFREE_ADDR                      0xc10e8930
#define SECURITY_FILE_MMAP_ADDR         0xc11ca1e0
#define KMEM_CACHE_ALLOC_TRACE_ADDR     0xc10e91c0
#define KMALLOC_CACHES_ADDR	        0xc1983120

// kernel 3.3.0-rc3
#define PROCESS_MEASUREMENT_ADDR        0xc11e7910
#define KERNEL_READ_ADDR                0xc10f6690
#define KFREE_ADDR                      0xc10ed600
#define SECURITY_FILE_MMAP_ADDR         0xc11cc8f0
#define KMEM_CACHE_ALLOC_TRACE_ADDR     0xc10ed850
#define KMALLOC_CACHES_ADDR	        0xc19a91a0
#endif

// kernel 3.3.0-rc4
// cat /home/larsr/System.map-3.3.0-rc4 | egrep ' (process_measurement|kernel_read|kfree|security_file_mmap|kmem_cache_alloc_trace|kmalloc_caches|__destroy_inode|integrity_inode_free)$' | awk '{printf("#define %-30s 0x%s\n",toupper($3 "_ADDR"),$1)}' | sort

#if 0  
 // read from file instead
#define __DESTROY_INODE_ADDR           0xc110a7d0
#define INTEGRITY_INODE_FREE_ADDR      0xc11e9e90
#define KERNEL_READ_ADDR               0xc10fb660
#define KFREE_ADDR                     0xc10f1030
#define KMALLOC_CACHES_ADDR            0xc1a14100
#define KMEM_CACHE_ALLOC_TRACE_ADDR    0xc10f1a40
#define PROCESS_MEASUREMENT_ADDR       0xc11ea7c0
#define SECURITY_FILE_MMAP_ADDR        0xc11d0700
#endif

extern bx_address process_measurement,kernel_read,kfree,security_file_mmap,kmem_cache_alloc_trace,kmalloc_caches,__destroy_inode,integrity_inode_free;
extern symbol_entry kernel_symbols[];



// TODO: also we must make sure the offsets when traversing data structures 
//       with LOOKUP and g2h are ok. Currently they are hard coded.

// Guest to host address translation
inline Bit8u* g2h(bx_address gaddr)  {
    bx_phy_address phys;
    bx_cpu_ptr -> dbg_xlate_linear2phy(gaddr, &phys, 0);
    Bit8u* haddr = BX_MEM(0)->get_vector(phys);
   return haddr;
  }

// fetch the 4 byte word at the guest address x
#define LOOKUP(x) (*(bx_address*)g2h(x))


typedef struct {
  bx_address esp ;
  int in_subfunction;
  bx_address save[3];

  bx_address file, rbuf, inode;
  long long offset; 
  char* fname;
  sha1_context ctx;
} save_record;


#define CHECKED_NUM 1000
int checked_size = 0;
bx_address checked[CHECKED_NUM];

// To dump, or not to dump a lot of debug info -- that is the question.
#if 1
#define BX_INFO2(x) genlog->info x
#else
#define BX_INFO2(x)
#undef BX_INFO
#define BX_INFO(x)
#endif 

int find_nearest_above(bx_address guest_inode) {
  int a = 0, b = checked_size, m;
  BX_INFO2(("find_nearest_above %x",  guest_inode));
  while(b - a > 1) {
    m = (a + b) >> 1;
    if(checked[m] < guest_inode) {
      a = m + 1;
    } else {
      b = m;
    }
  }
  if(checked[a] > guest_inode) { 
    BX_INFO2(("  returning a = %d",a));
    return a; 
  } else { 
    BX_INFO2(("  returning b = %d",b));
    return b; 
  }
}

int is_checked(bx_address guest_inode) {
  int j = find_nearest_above(guest_inode);
  if (j > 0 && guest_inode == checked[j-1]) {
    j -= 1;
  }
  return guest_inode == checked[j];
}


int add_checked(bx_address guest_inode) {
  // if node not in list, make room and insert it in order
  int j = find_nearest_above(guest_inode);
  if (j > 0 && guest_inode == checked[j-1]) {
    j -= 1;
  }
  if(checked_size >= CHECKED_NUM ) {
    BX_INFO2(( "Can't add inode %x. List is full.", guest_inode ));
    return 0;  // can't add. list is full
  } else if( guest_inode == checked[j]) {
    BX_INFO2(( "Can't add inode %x. Already in list at pos %d.", guest_inode, j ));
    return 0; // didn't add. node already in list;
  } else {
    int i;
    for(i = checked_size; i > j; i--) {
      checked[i] = checked[i-1];
    }
    checked[j] = guest_inode;
    checked_size += 1;
    BX_INFO2(( "Added inode %x at pos %d.", guest_inode, j ));
    return 1;
  }
}

void del_checked(bx_address guest_inode) {
  int j = find_nearest_above(guest_inode);
  if (j > 0 && guest_inode == checked[j-1]) {
    j -= 1;
  }
  if(checked[j] == guest_inode) {
    for(; j < checked_size-1; j++) {
      checked[j] = checked[j+1];
    }
    checked_size -= 1;
  }
}


int find_record(save_record* r, int n, bx_address esp) {
  int j = n;
  for(int i=0; i<n; i++, r++) {
    if(r->esp == esp) {
      return i;
    }
    if (r->esp == 0 && j ==n) {
      j = i; // found a free entry
    }
  }
  return j;  // returns n if no match was made and no free record was found
}

void BX_CPU_C::divert_execution(bx_address addr) {
  bxInstruction_c ii;
  Bit8u code[5];

  code[0]=0xe8;
  *(bx_address*)&code[1] = addr - RIP;
  fetchDecode32(code, &ii,sizeof(code));
  BX_CPU_CALL_METHOD(ii.execute, (&ii));
  // now we have pushed the return address (RIP) which is the SAME instruction, not the one after this instruction.
}

void BX_CPU_C::cpu_loop(Bit32u max_instr_count)
{
#if BX_DEBUGGER
  BX_CPU_THIS_PTR break_point = 0;
  BX_CPU_THIS_PTR magic_break = 0;
  BX_CPU_THIS_PTR stop_reason = STOP_NO_REASON;
#endif

  if (setjmp(BX_CPU_THIS_PTR jmp_buf_env)) {
    // only from exception function we can get here ...
    BX_INSTR_NEW_INSTRUCTION(BX_CPU_ID);
    BX_TICK1_IF_SINGLE_PROCESSOR();
#if BX_DEBUGGER || BX_GDBSTUB
    if (dbg_instruction_epilog()) return;
#endif
    CHECK_MAX_INSTRUCTIONS(max_instr_count);
#if BX_GDBSTUB
    if (bx_dbg.gdbstub_enabled) return;
#endif
  }

  // If the exception() routine has encountered a nasty fault scenario,
  // the debugger may request that control is returned to it so that
  // the situation may be examined.
#if BX_DEBUGGER
  if (bx_guard.interrupt_requested) return;
#endif

  // We get here either by a normal function call, or by a longjmp
  // back from an exception() call.  In either case, commit the
  // new EIP/ESP, and set up other environmental fields.  This code
  // mirrors similar code below, after the interrupt() call.
  BX_CPU_THIS_PTR prev_rip = RIP; // commit new EIP
  BX_CPU_THIS_PTR speculative_rsp = 0;
  BX_CPU_THIS_PTR EXT = 0;

  while (1) {

    // check on events which occurred for previous instructions (traps)
    // and ones which are asynchronous to the CPU (hardware interrupts)
    if (BX_CPU_THIS_PTR async_event) {
      if (handleAsyncEvent()) {
        // If request to return to caller ASAP.
        return;
      }
    }

    bxICacheEntry_c *entry = getICacheEntry();

    bxInstruction_c *i = entry->i;

#if BX_SUPPORT_TRACE_CACHE
    bxInstruction_c *last = i + (entry->tlen);

    for(;;) {
#endif

#if BX_DISASM
      if (BX_CPU_THIS_PTR trace) {
        // print the instruction that is about to be executed
        debug_disasm_instruction(BX_CPU_THIS_PTR prev_rip);
      }
#endif

//#define DONTRUN 1
#ifndef DONTRUN

/* from System.map
c11ca0e0 T security_file_permission
c11ca180 T security_file_alloc
c11ca1a0 T security_file_free
c11ca1c0 T security_file_ioctl
c11ca1e0 T security_file_mmap
c11ca230 T security_file_mprotect
c11ca250 T security_file_lock
c11ca270 T security_file_fcntl
c11ca290 T security_file_set_fowner
c11ca2b0 T security_file_send_sigiotask
c11ca2d0 T security_file_receive
*/      
#define N_SAVE_RECORDS 100
      static save_record records[N_SAVE_RECORDS];
      static int trace = 0;

      if(RIP == security_file_mmap) {

	BX_INFO( ("RIP == security_file_mmap") );
	/*
	  kmalloc(size, flags | __GFP_ZERO);
	  c10e9510 T __kmalloc
	  c10f1e80 T kernel_read
	  c10e8930 T kfree
	  file->f_dentry->d_name.name

	  rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	  offset = 0;
	  while((n = kernel_read(file, offset, rbuf, PAGE_SIZE)) > 0) {
	  offset += n;
	  // update crypto
	  }
	  kfree(rbuf);
	*/
      }

      if(RIP == integrity_inode_free) {
	if(!is_checked(EAX)) {
	  BX_INFO(("The inode is not in the checked list (integrity_inode_free)"));
	}
	BX_INFO(("removing inode %x from checked list.  (integrity_inode_free) ",EAX));
	del_checked(EAX);
      }
      else

      if(RIP == __destroy_inode) {
	if(!is_checked(EAX)) {
	  BX_INFO(("The inode is not in the checked list (__DESTROY_INODE)"));
	}
	BX_INFO(("removing inode %x from checked list.  (__DESTROY_INODE)",EAX));
	del_checked(EAX);
      }
      else
      if(RIP ==  process_measurement) {  

	int ri = find_record(records, N_SAVE_RECORDS, ESP);
	if( ri == N_SAVE_RECORDS ) {
	  BX_INFO (( "PANIC ERROR! No available save_records for injected call to kmem_cache_alloc_trace" ));
	  return;
	};
	save_record& r = records[ri];
	BX_INFO(("save_record %d",ri));

	BX_INFO( ("BEFORE EBX=%x ESI=%x EDI=%x, ESP=%x, EBP=%x", EBX, ESI, EDI, ESP, EBP) );

	/*
	for(int j = 0; j < N_SAVE_RECORDS; j++) {
	  if(records[j].esp != 0)  {
	    BX_INFO(("   records[%d] for '%s'", j, records[j].fname ));
	  }
	}
	*/

	if(r.esp == 0) { // initialize
	  r.esp = ESP;
	  r.in_subfunction = 0;

	  r.file = EAX;
	  r.fname = (char*)g2h(LOOKUP(LOOKUP(r.file+12)+28)); // file->dentry->d_iname
	  r.inode = LOOKUP(LOOKUP(r.file+12)+32); // file->f_path.dentry->d_inode

	  r.offset = 0;
	  r.rbuf = 0;
	  sha1_starts(&r.ctx);
	}

	BX_INFO( ("RIP == process_measurement %d '%s'", r.in_subfunction, r.fname) );

	// change the execution to call kzalloc,kernel_read,kfree
	// and then continue from this address

	
	int do_check = 1;

	if(r.in_subfunction == 0) { // decide whether to check this file or not.

	  unsigned int mode = LOOKUP(r.inode+0); // file->f_path.dentry->d_inode->mode
	  BX_INFO(("file->f_path.dentry->d_inode->mode = %x for %s", mode, r.fname));
	  int is_reg = ((mode & 00170000) == 0100000); 
	  if (!is_reg) {
	    BX_INFO(("is not regular file '%s'", r.fname));
	    do_check = 0;
	  }

	  // from linux/magic.h
#define PROC_SUPER_MAGIC 0x9fa0
#define SYSFS_MAGIC 0x62656572
#define DEBUGFS_MAGIC 0x64626720
#define TMPFS_MAGIC 0x01021994
#define SECURITYFS_MAGIC 0x73636673
#define SELINUX_MAGIC 0xf97cff8c
	  // from security/integrity/ima/ima.h
	  enum ima_hooks { FILE_CHECK = 1, FILE_MMAP, BPRM_CHECK };
	  // from linux/fs.h
#define MAY_EXEC                0x00000001
#define MAY_READ                0x00000004

	  unsigned int fsmagic = LOOKUP(LOOKUP(r.inode+0x1c)+0x34); // inode->i_sb->s_magic
	  int mask = ECX;
	  int func = LOOKUP(ESP+4);
	  int uid = 0;

	  BX_INFO(("fsmagic = %x mask = %x func = %x uid = %d, fname = '%s'",fsmagic, mask,func,uid, r.fname));

	  /* current_thread_info
	     THREAD_SIZE = (PAGE_SIZE << 1)
	     (ESP & ~(THREAD_SIZE - 1))

	  struct task_struct *tsk = (current_thread_info()->task);
	  uid = tsk->cred->uid;
	  */
	  // uid =  (ESP & ~(THREAD_SIZE - 1))->task->cred->uid;

	  // don't check if file is on one of the not checked file systems
	  if (fsmagic == PROC_SUPER_MAGIC || fsmagic == SYSFS_MAGIC ||
	      fsmagic == DEBUGFS_MAGIC    || fsmagic == TMPFS_MAGIC ||
	      fsmagic == SECURITYFS_MAGIC || fsmagic == SELINUX_MAGIC) {
	    BX_INFO(("file '%s' on not-checked filesystem with fsmagic %x",r.fname, fsmagic));
	    do_check = 0;
	  }
	  else if (func == FILE_MMAP  && mask == MAY_EXEC) {}	
	  else if (func == BPRM_CHECK && mask == MAY_EXEC) {}
	  else if (func == FILE_CHECK && mask == MAY_READ && uid == 0) {}
	  else {
	    BX_INFO(("file '%s' on not-checked because of mask %d func %d",r.fname, mask, func));
	    do_check = 0; 
	  }
	}

	if( ! do_check) {
	  BX_INFO(("not checking '%s' because of rules", r.fname));
	  r.esp = 0;

	} else if(is_checked(r.inode) && r.in_subfunction == 0) {
	  // we must be allowed do deallocate, thus only skip checkin when in_subfunction==0 (i.e. when first entering)
	  BX_INFO(("is already checked '%s' %x", r.fname, r.inode));
	  r.esp = 0;
	  
	} else if(r.in_subfunction == 0) {

	  BX_INFO( ("entering subfunction call to kmem_cache_alloc_trace '%s'", r.fname) );

	  // This is what we want to inject:
	  // rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	  //   0xc11e5e11:  mov    0xc1983150,%eax
	  //   ...
	  //   0xc11e5e1e:  mov    $0x1000,%ecx
	  //   0xc11e5e23:  mov    $0x80d0,%edx
	  //   0xc11e5e28:  call   0xc10e91c0    //   void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
	  //   0xc11e5e28:     0xe8    0x93    0x33    0xf0    0xff
	  //   0xfff03393 + 0xc11e5e28 + 5 == 0xc10e91c0

	  r.save[0] = EAX; r.save[1] = ECX; r.save[2] = EDX;

	  EAX = *(Bit32u*)g2h(kmalloc_caches + 4 * 12);   // kmalloc_caches[12] is the pointer to the kmem_cache for 4k blocks
	  ECX = 0x1000;
	  EDX = 0x80d0;
	  divert_execution(kmem_cache_alloc_trace);  // kmem_cache_alloc_trace

	  /*
#define KZALLOC_ADDR 0xc108ca10
	  EAX = 0x1000;
	  ECX = 0xd0;
	  divert_execution(KZALLOC_ADDR);  // kzalloc
	  */
	  trace = 1;

	  r.in_subfunction = 1;  // when we come back, to next step (at in_subfunction == 1)
	  
	} else if (r.in_subfunction == 1) {

	  BX_INFO( ("returning from subfunction call to kmem_cache_alloc_trace, EAX = %x", EAX) );
	  r.rbuf = EAX;

	  // while((n = kernel_read(file, offset, rbuf, PAGE_SIZE)) > 0) {
	  EAX = r.file;
	  ECX = r.offset >> 32;
	  EDX = r.offset & 0xffffffff;
	  
	  ESP -= 8;
	  *(Bit32u*)g2h(ESP) =  0x1000; // count
	  ESP -= 4;
	  *(Bit32u*)g2h(ESP) =  r.rbuf;
	  r.esp = ESP;

	  divert_execution(kernel_read);  // kernel_read

	  r.in_subfunction = 2;  // when we come back, to next step (at in_subfunction == 2)

	  BX_INFO( ("Calling kernel_read offset %lld file '%s'", r.offset, r.fname) );

	} else if ( r.in_subfunction == 2 ) {

	  ESP += 12;
	  r.esp = ESP;
	  
	  int n = EAX;  // save return value
	  BX_INFO( ("kernel_read read %d bytes at offset %lld in file '%s'", n, r.offset, r.fname) ) ;
	  r.offset += n;

	  char str[10*3+1];
	  int j=r.offset-n;
	  char* p = str;
	  char*c = (char*)g2h(r.rbuf); 
	  str[0] = '\0';
	  while(j<r.offset && j < r.offset - n + 10) {
	    unsigned char cc = *c;
	    sprintf(p,"%02x ", cc);
	    j++; 
	    p+=3; 
	    c++;
	  }
	  BX_INFO(("READ: %s",str));

	  if (n < 0) {
	    BX_INFO( ("kernel_read returned error %d",n));
	  }

	  if ( n > 0 ) {
	    unsigned char* rbuf = (unsigned char*)g2h(r.rbuf); 

	    sha1_update(&r.ctx, rbuf, n);

	    // while((n = kernel_read(file, offset, rbuf, PAGE_SIZE)) > 0) {
	    EAX = r.file;
	    ECX = r.offset >> 32;
	    EDX = r.offset & 0xffffffff;

	    ESP -= 8;
	    *(Bit32u*)g2h(ESP) =  0x1000; // count
	    ESP -= 4;
	    *(Bit32u*)g2h(ESP) =  r.rbuf;
	    r.esp = ESP;

	    divert_execution(kernel_read);  // kernel_read

	    r.in_subfunction = 2;  // when we come back, continue to read (at in_subfunction == 2)

	  } else {
	    
	    if( n == 0 ) {
	      unsigned char digest[20];
	      char adig[41];
	      int j;
	      sha1_finish(&r.ctx, digest);
	      for(j=0; j<20; j++) {
		sprintf(&adig[2*j],"%02x",digest[j]);
	      }
	      adig[40]='\0';
	      BX_INFO(("File '%s' at inode %x has digest '%s'", r.fname, r.inode, adig));
	      genlog->info("File '%s' at inode %x has digest '%s'", r.fname, r.inode, adig);

	      add_checked(r.inode);
	    }
	    // ok, the fun is over, call kfree with the pointer in EAX
	    BX_INFO( ("Calling kfree") );
	    // kfree(rbuf);
	    // c10e8930 T kfree
	    //    0xc11e5ecf:  call   0xc10e8930
	    //    0xc11e5ecf:     0xe8    0x5c    0x2a    0xf0    0xff

	    EAX = r.rbuf;
	    divert_execution(kfree);
	    r.in_subfunction = 3;  // when we come back, to next step (at in_subfunction == 3)
	    
	  }

	} else if (r.in_subfunction == 3) {
	  BX_INFO( ("returning from subfunction call to kfree. ") );
	  BX_INFO( ("Restoring registers") );
	  EAX = r.save[0]; ECX = r.save[1]; EDX = r.save[2];  // restore register values

	  r.esp = 0;
	  r.in_subfunction = 0;
	  trace = 0;
	}

	entry = getICacheEntry();
	i = entry->i;

      }

#endif // end of DONTRUN

      if(RIP ==  process_measurement) { 
	BX_INFO(("EIP = %x, EAX = %x",RIP, EAX));
	BX_INFO( ("AFTER  EBX=%x ESI=%x EDI=%x, ESP=%x, EBP=%x", EBX, ESI, EDI, ESP, EBP) );
      }
      if ( trace > 0 ) {
	BX_INFO( ("EIP = %x     trace=%d", EIP, trace) );
	trace--;
      }

      // instruction decoding completed -> continue with execution
      // want to allow changing of the instruction inside instrumentation callback
      BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, i);
      RIP += i->ilen();
      BX_CPU_CALL_METHOD(i->execute, (i)); // might iterate repeat instruction
      BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
      BX_INSTR_AFTER_EXECUTION(BX_CPU_ID, i);
      BX_TICK1_IF_SINGLE_PROCESSOR();

      // inform instrumentation about new instruction
      BX_INSTR_NEW_INSTRUCTION(BX_CPU_ID);

      // note instructions generating exceptions never reach this point
#if BX_DEBUGGER || BX_GDBSTUB
      if (dbg_instruction_epilog()) return;
#endif

      CHECK_MAX_INSTRUCTIONS(max_instr_count);

#if BX_SUPPORT_TRACE_CACHE
      if (BX_CPU_THIS_PTR async_event) {
        // clear stop trace magic indication that probably was set by repeat or branch32/64
        BX_CPU_THIS_PTR async_event &= ~BX_ASYNC_EVENT_STOP_TRACE;
        break;
      }

      if (++i == last) {
        entry = getICacheEntry();
        i = entry->i;
        last = i + (entry->tlen);
      }
    }
#endif
  }  // while (1)
}

bxICacheEntry_c* BX_CPU_C::getICacheEntry(void)
{
  bx_address eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;

  if (eipBiased >= BX_CPU_THIS_PTR eipPageWindowSize) {
    prefetch();
    eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;
  }

  bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrPage + eipBiased;
  bxICacheEntry_c *entry = BX_CPU_THIS_PTR iCache.get_entry(pAddr, BX_CPU_THIS_PTR fetchModeMask);

  InstrICache_Increment(iCacheLookups);
  InstrICache_Stats();

  if (entry->pAddr != pAddr)
  {
    // iCache miss. No validated instruction with matching fetch parameters
    // is in the iCache.
    InstrICache_Increment(iCacheMisses);
    serveICacheMiss(entry, (Bit32u) eipBiased, pAddr);
  }

  return entry;
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat(bxInstruction_c *i, BxExecutePtr_tR execute)
{
  // non repeated instruction
  if (! i->repUsedL()) {
    BX_CPU_CALL_METHOD(execute, (i));
    return;
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 0;
#endif

#if BX_SUPPORT_X86_64
  if (i->as64L()) {
    while(1) {
      if (RCX != 0) {
        BX_CPU_CALL_METHOD(execute, (i));
        BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
        RCX --;
      }
      if (RCX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_TICK1_IF_SINGLE_PROCESSOR();
    }
  }
  else
#endif
  if (i->as32L()) {
    while(1) {
      if (ECX != 0) {
        BX_CPU_CALL_METHOD(execute, (i));
        BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
        RCX = ECX - 1;
      }
      if (ECX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_TICK1_IF_SINGLE_PROCESSOR();
    }
  }
  else  // 16bit addrsize
  {
    while(1) {
      if (CX != 0) {
        BX_CPU_CALL_METHOD(execute, (i));
        BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
        CX --;
      }
      if (CX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_TICK1_IF_SINGLE_PROCESSOR();
    }
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 1;
#endif

  RIP = BX_CPU_THIS_PTR prev_rip; // repeat loop not done, restore RIP

#if BX_SUPPORT_TRACE_CACHE
  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
#endif
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat_ZF(bxInstruction_c *i, BxExecutePtr_tR execute)
{
  unsigned rep = i->repUsedValue();

  // non repeated instruction
  if (! rep) {
    BX_CPU_CALL_METHOD(execute, (i));
    return;
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 0;
#endif

  if (rep == 3) { /* repeat prefix 0xF3 */
#if BX_SUPPORT_X86_64
    if (i->as64L()) {
      while(1) {
        if (RCX != 0) {
          BX_CPU_CALL_METHOD(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX --;
        }
        if (! get_ZF() || RCX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_TICK1_IF_SINGLE_PROCESSOR();
      }
    }
    else
#endif
    if (i->as32L()) {
      while(1) {
        if (ECX != 0) {
          BX_CPU_CALL_METHOD(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX = ECX - 1;
        }
        if (! get_ZF() || ECX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_TICK1_IF_SINGLE_PROCESSOR();
      }
    }
    else  // 16bit addrsize
    {
      while(1) {
        if (CX != 0) {
          BX_CPU_CALL_METHOD(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          CX --;
        }
        if (! get_ZF() || CX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_TICK1_IF_SINGLE_PROCESSOR();
      }
    }
  }
  else {          /* repeat prefix 0xF2 */
#if BX_SUPPORT_X86_64
    if (i->as64L()) {
      while(1) {
        if (RCX != 0) {
          BX_CPU_CALL_METHOD(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX --;
        }
        if (get_ZF() || RCX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_TICK1_IF_SINGLE_PROCESSOR();
      }
    }
    else
#endif
    if (i->as32L()) {
      while(1) {
        if (ECX != 0) {
          BX_CPU_CALL_METHOD(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX = ECX - 1;
        }
        if (get_ZF() || ECX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_TICK1_IF_SINGLE_PROCESSOR();
      }
    }
    else  // 16bit addrsize
    {
      while(1) {
        if (CX != 0) {
          BX_CPU_CALL_METHOD(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          CX --;
        }
        if (get_ZF() || CX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_TICK1_IF_SINGLE_PROCESSOR();
      }
    }
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 1;
#endif

  RIP = BX_CPU_THIS_PTR prev_rip; // repeat loop not done, restore RIP

#if BX_SUPPORT_TRACE_CACHE
  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
#endif
}

unsigned BX_CPU_C::handleAsyncEvent(void)
{
  //
  // This area is where we process special conditions and events.
  //
  if (BX_CPU_THIS_PTR activity_state) {
    // For one processor, pass the time as quickly as possible until
    // an interrupt wakes up the CPU.
    while (1)
    {
      if ((BX_CPU_INTR && (BX_CPU_THIS_PTR get_IF() || 
          (BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_MWAIT_IF))) ||
           BX_CPU_THIS_PTR pending_NMI || BX_CPU_THIS_PTR pending_SMI || BX_CPU_THIS_PTR pending_INIT)
      {
        // interrupt ends the HALT condition
#if BX_SUPPORT_MONITOR_MWAIT
        if (BX_CPU_THIS_PTR activity_state >= BX_ACTIVITY_STATE_MWAIT)
          BX_CPU_THIS_PTR monitor.reset_monitor();
#endif
        BX_CPU_THIS_PTR activity_state = 0;
        BX_CPU_THIS_PTR inhibit_mask = 0; // clear inhibits for after resume
        break;
      }

      if (BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_ACTIVE) {
        BX_INFO(("handleAsyncEvent: reset detected in HLT state"));
        break;
      }

      if (BX_HRQ && BX_DBG_ASYNC_DMA) {
        // handle DMA also when CPU is halted
        DEV_dma_raise_hlda();
      }

      // for multiprocessor simulation, even if this CPU is halted we still
      // must give the others a chance to simulate.  If an interrupt has
      // arrived, then clear the HALT condition; otherwise just return from
      // the CPU loop with stop_reason STOP_CPU_HALTED.
#if BX_SUPPORT_SMP
      if (BX_SMP_PROCESSORS > 1) {
        // HALT condition remains, return so other CPUs have a chance
#if BX_DEBUGGER
        BX_CPU_THIS_PTR stop_reason = STOP_CPU_HALTED;
#endif
        return 1; // Return to caller of cpu_loop.
      }
#endif

#if BX_DEBUGGER
      if (bx_guard.interrupt_requested)
        return 1; // Return to caller of cpu_loop.
#endif

      BX_TICKN(10); // when in HLT run time faster for single CPU
    }
  } else if (bx_pc_system.kill_bochs_request) {
    // setting kill_bochs_request causes the cpu loop to return ASAP.
    return 1; // Return to caller of cpu_loop.
  }

  // VMLAUNCH/VMRESUME cannot be executed with interrupts inhibited.
  // Save inhibit interrupts state into shadow bits after clearing
  BX_CPU_THIS_PTR inhibit_mask = (BX_CPU_THIS_PTR inhibit_mask << 2) & 0xF;

  // Priority 1: Hardware Reset and Machine Checks
  //   RESET
  //   Machine Check
  // (bochs doesn't support these)

  // Priority 2: Trap on Task Switch
  //   T flag in TSS is set
  if (BX_CPU_THIS_PTR debug_trap & BX_DEBUG_TRAP_TASK_SWITCH_BIT)
    exception(BX_DB_EXCEPTION, 0); // no error, not interrupt

  // Priority 3: External Hardware Interventions
  //   FLUSH
  //   STOPCLK
  //   SMI
  //   INIT
  if (BX_CPU_THIS_PTR pending_SMI && ! BX_CPU_THIS_PTR smm_mode())
  {
    // clear SMI pending flag and disable NMI when SMM was accepted
    BX_CPU_THIS_PTR pending_SMI = 0;
    enter_system_management_mode();
  }

  if (BX_CPU_THIS_PTR pending_INIT && ! BX_CPU_THIS_PTR disable_INIT) {
#if BX_SUPPORT_VMX
    if (BX_CPU_THIS_PTR in_vmx_guest) {
      BX_ERROR(("VMEXIT: INIT pin asserted"));
      VMexit(0, VMX_VMEXIT_INIT, 0);
    }
#endif
    // reset will clear pending INIT
    BX_CPU_THIS_PTR reset(BX_RESET_SOFTWARE);
  }

  // Priority 4: Traps on Previous Instruction
  //   Breakpoints
  //   Debug Trap Exceptions (TF flag set or data/IO breakpoint)
  if (BX_CPU_THIS_PTR debug_trap &&
       !(BX_CPU_THIS_PTR inhibit_mask & BX_INHIBIT_DEBUG_SHADOW))
  {
    // A trap may be inhibited on this boundary due to an instruction
    // which loaded SS.  If so we clear the inhibit_mask below
    // and don't execute this code until the next boundary.
    exception(BX_DB_EXCEPTION, 0); // no error, not interrupt
  }

  // Priority 5: External Interrupts
  //   NMI Interrupts
  //   Maskable Hardware Interrupts
  if (BX_CPU_THIS_PTR inhibit_mask & BX_INHIBIT_INTERRUPTS_SHADOW) {
    // Processing external interrupts is inhibited on this
    // boundary because of certain instructions like STI.
    // inhibit_mask is cleared below, in which case we will have
    // an opportunity to check interrupts on the next instruction
    // boundary.
  }
#if BX_SUPPORT_VMX
  else if (! BX_CPU_THIS_PTR disable_NMI && BX_CPU_THIS_PTR in_vmx_guest && 
       VMEXIT(VMX_VM_EXEC_CTRL2_NMI_WINDOW_VMEXIT))
  {
    // NMI-window exiting
    BX_ERROR(("VMEXIT: NMI window exiting"));
    VMexit(0, VMX_VMEXIT_NMI_WINDOW, 0);
  }
#endif
  else if (BX_CPU_THIS_PTR pending_NMI && ! BX_CPU_THIS_PTR disable_NMI) {
    BX_CPU_THIS_PTR pending_NMI = 0;
    BX_CPU_THIS_PTR disable_NMI = 1;
    BX_CPU_THIS_PTR EXT = 1; /* external event */
#if BX_SUPPORT_VMX
    VMexit_Event(0, BX_NMI, 2, 0, 0);
#endif
    BX_INSTR_HWINTERRUPT(BX_CPU_ID, 2, BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
    interrupt(2, BX_NMI, 0, 0);
  }
#if BX_SUPPORT_VMX
  else if (BX_CPU_THIS_PTR vmx_interrupt_window && BX_CPU_THIS_PTR get_IF()) {
    // interrupt-window exiting
    BX_ERROR(("VMEXIT: interrupt window exiting"));
    VMexit(0, VMX_VMEXIT_INTERRUPT_WINDOW, 0);
  }
#endif
  else if (BX_CPU_INTR && BX_DBG_ASYNC_INTR && 
          (BX_CPU_THIS_PTR get_IF()
#if BX_SUPPORT_VMX
       || (BX_CPU_THIS_PTR in_vmx_guest && PIN_VMEXIT(VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT))
#endif
          ))
  {
    Bit8u vector;
#if BX_SUPPORT_VMX
    VMexit_ExtInterrupt();
#endif
    // NOTE: similar code in ::take_irq()
#if BX_SUPPORT_APIC
    if (BX_CPU_THIS_PTR lapic.INTR)
      vector = BX_CPU_THIS_PTR lapic.acknowledge_int();
    else
#endif
      // if no local APIC, always acknowledge the PIC.
      vector = DEV_pic_iac(); // may set INTR with next interrupt
    BX_CPU_THIS_PTR EXT = 1; /* external event */
#if BX_SUPPORT_VMX
    VMexit_Event(0, BX_EXTERNAL_INTERRUPT, vector, 0, 0);
#endif
    BX_INSTR_HWINTERRUPT(BX_CPU_ID, vector,
        BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, RIP);
    interrupt(vector, BX_EXTERNAL_INTERRUPT, 0, 0);
    // Set up environment, as would be when this main cpu loop gets
    // invoked.  At the end of normal instructions, we always commmit
    // the new EIP.  But here, we call interrupt() much like
    // it was a sofware interrupt instruction, and need to effect the
    // commit here.  This code mirrors similar code above.
    BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
    BX_CPU_THIS_PTR EXT = 0;
  }
  else if (BX_HRQ && BX_DBG_ASYNC_DMA) {
    // NOTE: similar code in ::take_dma()
    // assert Hold Acknowledge (HLDA) and go into a bus hold state
    DEV_dma_raise_hlda();
  }

  // Priority 6: Faults from fetching next instruction
  //   Code breakpoint fault
  //   Code segment limit violation (priority 7 on 486/Pentium)
  //   Code page fault (priority 7 on 486/Pentium)
  // (handled in main decode loop)

  // Priority 7: Faults from decoding next instruction
  //   Instruction length > 15 bytes
  //   Illegal opcode
  //   Coprocessor not available
  // (handled in main decode loop etc)

  // Priority 8: Faults on executing an instruction
  //   Floating point execution
  //   Overflow
  //   Bound error
  //   Invalid TSS
  //   Segment not present
  //   Stack fault
  //   General protection
  //   Data page fault
  //   Alignment check
  // (handled by rest of the code)

  // Now we can handle things which are synchronous to instruction
  // execution.
  if (BX_CPU_THIS_PTR get_RF()) {
    BX_CPU_THIS_PTR clear_RF();
  }
#if BX_X86_DEBUGGER
  else {
    // only bother comparing if any breakpoints enabled and
    // debug events are not inhibited on this boundary.
    if (! (BX_CPU_THIS_PTR inhibit_mask & BX_INHIBIT_DEBUG_SHADOW) && ! BX_CPU_THIS_PTR in_repeat) {
      if (BX_CPU_THIS_PTR dr7 & 0x000000ff) {
        bx_address iaddr = get_laddr(BX_SEG_REG_CS, BX_CPU_THIS_PTR prev_rip);
        Bit32u dr6_bits = hwdebug_compare(iaddr, 1, BX_HWDebugInstruction, BX_HWDebugInstruction);
        if (dr6_bits) {
          // Add to the list of debug events thus far.
          BX_CPU_THIS_PTR debug_trap |= dr6_bits;
          BX_ERROR(("#DB: x86 code breakpoint catched"));
          exception(BX_DB_EXCEPTION, 0); // no error, not interrupt
        }
      }
    }
  }
#endif

  if (BX_CPU_THIS_PTR get_TF())
  {
    // TF is set before execution of next instruction.  Schedule
    // a debug trap (#DB) after execution.  After completion of
    // next instruction, the code above will invoke the trap.
    BX_CPU_THIS_PTR debug_trap |= BX_DEBUG_SINGLE_STEP_BIT;
  }

  if (!((BX_CPU_INTR && BX_CPU_THIS_PTR get_IF()) ||
        BX_CPU_THIS_PTR debug_trap ||
//      BX_CPU_THIS_PTR get_TF() // implies debug_trap is set
        BX_HRQ
#if BX_SUPPORT_VMX
     || BX_CPU_THIS_PTR vmx_interrupt_window || BX_CPU_THIS_PTR inhibit_mask
#endif
#if BX_X86_DEBUGGER
       // any debug code breakpoint is set
     || ((BX_CPU_THIS_PTR dr7 & 0xff) &&
           (((BX_CPU_THIS_PTR dr7 >> 16) & 3) == 0 ||
            ((BX_CPU_THIS_PTR dr7 >> 20) & 3) == 0 ||
            ((BX_CPU_THIS_PTR dr7 >> 24) & 3) == 0 ||
            ((BX_CPU_THIS_PTR dr7 >> 28) & 3) == 0))
#endif
        ))
    BX_CPU_THIS_PTR async_event = 0;

  return 0; // Continue executing cpu_loop.
}


// boundaries of consideration:
//
//  * physical memory boundary: 1024k (1Megabyte) (increments of...)
//  * A20 boundary:             1024k (1Megabyte)
//  * page boundary:            4k
//  * ROM boundary:             2k (dont care since we are only reading)
//  * segment boundary:         any

void BX_CPU_C::prefetch(void)
{
  bx_address laddr;
  unsigned pageOffset;

#if BX_SUPPORT_X86_64
  if (long64_mode()) {
    if (! IsCanonical(RIP)) {
      BX_ERROR(("prefetch: #GP(0): RIP crossed canonical boundary"));
      exception(BX_GP_EXCEPTION, 0);
    }

    // linear address is equal to RIP in 64-bit long mode
    pageOffset = PAGE_OFFSET(EIP);
    laddr = RIP;

    // Calculate RIP at the beginning of the page.
    BX_CPU_THIS_PTR eipPageBias = pageOffset - RIP;
    BX_CPU_THIS_PTR eipPageWindowSize = 4096;
  }
  else
#endif
  {
    BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RIP); /* avoid 32-bit EIP wrap */
    laddr = BX_CPU_THIS_PTR get_laddr32(BX_SEG_REG_CS, EIP);
    pageOffset = PAGE_OFFSET(laddr);

    // Calculate RIP at the beginning of the page.
    BX_CPU_THIS_PTR eipPageBias = (bx_address) pageOffset - EIP;

    Bit32u limit = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.limit_scaled;
    if (EIP > limit) {
      BX_ERROR(("prefetch: EIP [%08x] > CS.limit [%08x]", EIP, limit));
      exception(BX_GP_EXCEPTION, 0);
    }

    BX_CPU_THIS_PTR eipPageWindowSize = 4096;
    if (limit + BX_CPU_THIS_PTR eipPageBias < 4096) {
      BX_CPU_THIS_PTR eipPageWindowSize = (Bit32u)(limit + BX_CPU_THIS_PTR eipPageBias + 1);
    }
  }

  bx_address lpf = LPFOf(laddr);
  unsigned TLB_index = BX_TLB_INDEX_OF(lpf, 0);
  bx_TLB_entry *tlbEntry = &BX_CPU_THIS_PTR TLB.entry[TLB_index];
  Bit8u *fetchPtr = 0;

  if ((tlbEntry->lpf == lpf) && !(tlbEntry->accessBits & (0x4 | USER_PL))) {
    BX_CPU_THIS_PTR pAddrPage = tlbEntry->ppf;
    fetchPtr = (Bit8u*) tlbEntry->hostPageAddr;
  }  
  else {
    bx_phy_address pAddr = translate_linear(laddr, CPL, BX_EXECUTE);
    BX_CPU_THIS_PTR pAddrPage = PPFOf(pAddr);
  }

  if (fetchPtr) {
    BX_CPU_THIS_PTR eipFetchPtr = fetchPtr;
  }
  else {
    BX_CPU_THIS_PTR eipFetchPtr = (const Bit8u*) getHostMemAddr(BX_CPU_THIS_PTR pAddrPage, BX_EXECUTE);

    // Sanity checks
    if (! BX_CPU_THIS_PTR eipFetchPtr) {
      bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrPage + pageOffset;
      if (pAddr >= BX_MEM(0)->get_memory_len()) {
        BX_PANIC(("prefetch: running in bogus memory, pAddr=0x" FMT_PHY_ADDRX, pAddr));
      }
      else {
        BX_PANIC(("prefetch: getHostMemAddr vetoed direct read, pAddr=0x" FMT_PHY_ADDRX, pAddr));
      }
    }
  }
}

void BX_CPU_C::deliver_SIPI(unsigned vector)
{
  if (BX_CPU_THIS_PTR activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
    BX_CPU_THIS_PTR activity_state = BX_ACTIVITY_STATE_ACTIVE;
    RIP = 0;
    load_seg_reg(&BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS], vector*0x100);
    BX_CPU_THIS_PTR disable_INIT = 0; // enable INIT pin back
    BX_INFO(("CPU %d started up at %04X:%08X by APIC",
                   BX_CPU_THIS_PTR bx_cpuid, vector*0x100, EIP));
  } else {
    BX_INFO(("CPU %d started up by APIC, but was not halted at the time", BX_CPU_THIS_PTR bx_cpuid));
  }
}

void BX_CPU_C::deliver_INIT(void)
{
  if (! BX_CPU_THIS_PTR disable_INIT) {
    BX_CPU_THIS_PTR pending_INIT = 1;
    BX_CPU_THIS_PTR async_event = 1;
  }
}

void BX_CPU_C::deliver_NMI(void)
{
  BX_CPU_THIS_PTR pending_NMI = 1;
  BX_CPU_THIS_PTR async_event = 1;
}

void BX_CPU_C::deliver_SMI(void)
{
  BX_CPU_THIS_PTR pending_SMI = 1;
  BX_CPU_THIS_PTR async_event = 1;
}

void BX_CPU_C::set_INTR(bx_bool value)
{
  BX_CPU_THIS_PTR INTR = value;
  BX_CPU_THIS_PTR async_event = 1;
}

#if BX_DEBUGGER || BX_GDBSTUB
bx_bool BX_CPU_C::dbg_instruction_epilog(void)
{
#if BX_DEBUGGER
  Bit64u tt = bx_pc_system.time_ticks();
  bx_address debug_eip = RIP;
  Bit16u cs = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value;

  BX_CPU_THIS_PTR guard_found.icount++;
  BX_CPU_THIS_PTR guard_found.cs  = cs;
  BX_CPU_THIS_PTR guard_found.eip = debug_eip;
  BX_CPU_THIS_PTR guard_found.laddr = BX_CPU_THIS_PTR get_laddr(BX_SEG_REG_CS, debug_eip);
  BX_CPU_THIS_PTR guard_found.code_32_64 = BX_CPU_THIS_PTR fetchModeMask;

  //
  // Take care of break point conditions generated during instruction execution
  //

  // Check if we hit read/write or time breakpoint
  if (BX_CPU_THIS_PTR break_point) {
    switch (BX_CPU_THIS_PTR break_point) {
    case BREAK_POINT_TIME:
      BX_INFO(("[" FMT_LL "d] Caught time breakpoint", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_TIME_BREAK_POINT;
      return(1); // on a breakpoint
    case BREAK_POINT_READ:
      BX_INFO(("[" FMT_LL "d] Caught read watch point", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_READ_WATCH_POINT;
      return(1); // on a breakpoint
    case BREAK_POINT_WRITE:
      BX_INFO(("[" FMT_LL "d] Caught write watch point", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_WRITE_WATCH_POINT;
      return(1); // on a breakpoint
    default:
      BX_PANIC(("Weird break point condition"));
    }
  }

  if (BX_CPU_THIS_PTR magic_break) {
    BX_INFO(("[" FMT_LL "d] Stopped on MAGIC BREAKPOINT", bx_pc_system.time_ticks()));
    BX_CPU_THIS_PTR stop_reason = STOP_MAGIC_BREAK_POINT;
    return(1); // on a breakpoint
  }

  // convenient point to see if user requested debug break or typed Ctrl-C
  if (bx_guard.interrupt_requested) {
    return(1);
  }

  // support for 'show' command in debugger
  extern unsigned dbg_show_mask;
  if(dbg_show_mask) {
    int rv = bx_dbg_show_symbolic();
    if (rv) return(rv);
  }

  // Just committed an instruction, before fetching a new one
  // see if debugger is looking for iaddr breakpoint of any type
  if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_ALL) {
#if (BX_DBG_MAX_VIR_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_VIR) {
      for (unsigned n=0; n<bx_guard.iaddr.num_virtual; n++) {
        if (bx_guard.iaddr.vir[n].enabled &&
           (bx_guard.iaddr.vir[n].cs  == cs) &&
           (bx_guard.iaddr.vir[n].eip == debug_eip))
        {
          BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_VIR;
          BX_CPU_THIS_PTR guard_found.iaddr_index = n;
          BX_CPU_THIS_PTR guard_found.time_tick = tt;
          return(1); // on a breakpoint
        }
      }
    }
#endif
#if (BX_DBG_MAX_LIN_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_LIN) {
      for (unsigned n=0; n<bx_guard.iaddr.num_linear; n++) {
        if (bx_guard.iaddr.lin[n].enabled &&
           (bx_guard.iaddr.lin[n].addr == BX_CPU_THIS_PTR guard_found.laddr))
        {
          BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_LIN;
          BX_CPU_THIS_PTR guard_found.iaddr_index = n;
          BX_CPU_THIS_PTR guard_found.time_tick = tt;
          return(1); // on a breakpoint
        }
      }
    }
#endif
#if (BX_DBG_MAX_PHY_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_PHY) {
      bx_phy_address phy;
      bx_bool valid = dbg_xlate_linear2phy(BX_CPU_THIS_PTR guard_found.laddr, &phy);
      if (valid) {
        for (unsigned n=0; n<bx_guard.iaddr.num_physical; n++) {
          if (bx_guard.iaddr.phy[n].enabled && (bx_guard.iaddr.phy[n].addr == phy))
          {
            BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_PHY;
            BX_CPU_THIS_PTR guard_found.iaddr_index = n;
            BX_CPU_THIS_PTR guard_found.time_tick = tt;
            return(1); // on a breakpoint
          }
        }
      }
    }
#endif
  }
#endif

#if BX_GDBSTUB
  if (bx_dbg.gdbstub_enabled) {
    unsigned reason = bx_gdbstub_check(EIP);
    if (reason != GDBSTUB_STOP_NO_REASON) return(1);
  }
#endif

  return(0);
}
#endif // BX_DEBUGGER || BX_GDBSTUB

#if BX_DEBUGGER

void BX_CPU_C::dbg_take_irq(void)
{
  // NOTE: similar code in ::cpu_loop()

  if (BX_CPU_INTR && BX_CPU_THIS_PTR get_IF()) {
    if (setjmp(BX_CPU_THIS_PTR jmp_buf_env) == 0) {
      // normal return from setjmp setup
      unsigned vector = DEV_pic_iac(); // may set INTR with next interrupt
      BX_CPU_THIS_PTR EXT = 1; // external event
      BX_CPU_THIS_PTR async_event = 1; // set in case INTR is triggered
      interrupt(vector, BX_EXTERNAL_INTERRUPT, 0, 0);
    }
  }
}

void BX_CPU_C::dbg_force_interrupt(unsigned vector)
{
  // Used to force simulator to take an interrupt, without
  // regard to IF

  if (setjmp(BX_CPU_THIS_PTR jmp_buf_env) == 0) {
    // normal return from setjmp setup
    BX_CPU_THIS_PTR EXT = 1; // external event
    BX_CPU_THIS_PTR async_event = 1; // probably don't need this
    interrupt(vector, BX_EXTERNAL_INTERRUPT, 0, 0);
  }
}

void BX_CPU_C::dbg_take_dma(void)
{
  // NOTE: similar code in ::cpu_loop()
  if (BX_HRQ) {
    BX_CPU_THIS_PTR async_event = 1; // set in case INTR is triggered
    DEV_dma_raise_hlda();
  }
}

#endif  // #if BX_DEBUGGER

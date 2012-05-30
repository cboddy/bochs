#include "bochs.h"

#include <string>
#include <memory>
#include <iostream>

#include <llvm/LLVMContext.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/ExecutionEngine/JIT.h>

#include <llvm/ADT/OwningPtr.h>


#include "llvm/Support/system_error.h"

using namespace std;
using namespace llvm;



#include "bochs.h"
#include "cpu/cpu.h"

#include "llvm.h"

cpu_methods bx_cpu_methods;

ExecutionEngine* ee;
LLVMContext context;

int llvm_main(int n)
{
  InitializeNativeTarget();
  llvm_start_multithreaded();

  OwningPtr<MemoryBuffer> buffer;

  cout << "Loading and JIT-compiling llvmcpu.bc." << endl;
  if (error_code ec = MemoryBuffer::getFile("llvmcpu.bc", buffer)) {
  } else {
    std::string ParseErrorMessage;
    Module* m = ParseBitcodeFile(buffer.get(), context, &ParseErrorMessage);
    if(m) {
      ee = ExecutionEngine::create(m);
      Function* func = ee->FindFunctionNamed("llvm_init");

      if(func) {
	typedef void (*PFN2)(void);
	PFN2 llvm_init = reinterpret_cast<PFN2>(ee->getPointerToFunction(func));
	llvm_init();
	cout << "Done." << endl;
	return 0;
      } 
    }
  }
  cout << "ERROR" << endl;
  return 1;
}


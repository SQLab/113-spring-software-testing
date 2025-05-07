#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;
namespace {

    struct LLVMPass : public PassInfoMixin<LLVMPass> {
      PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        //to get the LLVM context
        LLVMContext &Context = M.getContext();

        Function *MainFunction = M.getFunction("main");
        if (!MainFunction || MainFunction->arg_size() < 2) 
          return PreservedAnalyses::all();

        Function::arg_iterator ArgsIterator = MainFunction->arg_begin();
        Argument *ArgcArgument = &*ArgsIterator++;
        Argument *ArgvArgument = &*ArgsIterator;

        BasicBlock &EntryBlock = MainFunction->getEntryBlock();
        Instruction *FirstInstruction = &*EntryBlock.getFirstInsertionPt();
        IRBuilder<> Builder(FirstInstruction);

        //prep debug(48763)
        Type *Int32Type = Type::getInt32Ty(Context);
        ConstantInt *DebugValue = ConstantInt::get(Int32Type, 48763);

        FunctionType *DebugFunctionType =
          FunctionType::get(Type::getVoidTy(Context), {Int32Type}, false);
        FunctionCallee DebugFunction = M.getOrInsertFunction("debug", DebugFunctionType);
        
        //insert call debug(48763)
        Builder.CreateCall(DebugFunction, {DebugValue});

        // replace all uses of argc with 48763
        if (!ArgcArgument->use_empty()) {
          ArgcArgument->replaceAllUsesWith(DebugValue);
        }

        Value *hayakuString =
        Builder.CreateGlobalStringPtr("hayaku... motohayaku!");


        Value *Index1 = ConstantInt::get(Int32Type, 1);
        Value *Argv1Pointer = Builder.CreateGEP(
          ArgvArgument->getType()->getPointerElementType(),
          ArgvArgument,
          Index1
        );

        //stores the string in argv[1]
        Builder.CreateStore(hayakuString, Argv1Pointer);
    
        return PreservedAnalyses::none();

      }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM,
          ArrayRef<PassBuilder::PipelineElement>) {
         if (Name == "llvm-pass") {
           MPM.addPass(LLVMPass());
           return true;
         }
         return false;
       });
    }
  };
}


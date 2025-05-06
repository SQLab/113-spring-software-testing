#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass>
{
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM)
{
    LLVMContext &Ctx = M.getContext();
    IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
    PointerType *Int8PtrTy = Type::getInt8PtrTy(Ctx);

    
    FunctionCallee debug_func = M.getOrInsertFunction("debug", Int32Ty);
    ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

    // find main
    for (Function &F : M)
    {
        if (F.getName() != "main")
            continue;

        // Entry block 
        BasicBlock &EntryBB = F.getEntryBlock();
        IRBuilder<> Builder(&*EntryBB.getFirstInsertionPt());

        // debug(48763)
        Builder.CreateCall(debug_func, {debug_arg});

        // argc  argv
        if (F.arg_size() >= 2)
        {
            auto ArgIt = F.arg_begin();
            Argument *Argc = ArgIt++;
            Argument *Argv = ArgIt;

            // argc replace into 48763
            Argc->replaceAllUsesWith(debug_arg);

            // argv[1] = "hayaku... motohayaku!"
            Constant *Str = Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "hayaku_str");
            Value *One = ConstantInt::get(Int32Ty, 1);
            // argv get argv[1]
            Value *GEP = Builder.CreateGEP(Int8PtrTy, Argv, One, "argv1_ptr");
            Builder.CreateStore(Str, GEP);
        }

        break; 
    }

    return PreservedAnalyses::none();
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
      [](PassBuilder &PB)
      {
        PB.registerOptimizerLastEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel OL)
            {
                MPM.addPass(LLVMPass());
            });
      }};
}

// llvm-pass.so.cc
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

// ================= Legacy FunctionPass =================
namespace {
  struct Lab6PassLegacy : FunctionPass {
    static char ID;
    Lab6PassLegacy() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      if (F.getName() != "main") return false;
      LLVMContext &Ctx = F.getContext();
      Module *M = F.getParent();
      IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());

      // constants
      Type    *Int32Ty = Type::getInt32Ty(Ctx);
      Constant *ConstID = ConstantInt::get(Int32Ty, 48763);
      Constant *Const1  = ConstantInt::get(Int32Ty, 1);

      // 1) debug(48763)
      FunctionCallee debugFn = M->getOrInsertFunction(
        "debug",
        FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false)
      );
      B.CreateCall(debugFn, {ConstID});

      // 2) argc = 48763
      Argument *Argc = F.getArg(0);
      for (auto UI = Argc->use_begin(), UE = Argc->use_end(); UI != UE; ) {
        Use &U = *UI++;
        U.set(ConstID);
      }

      // 3) argv[1] = "hayaku... motohayaku!"
      Constant *NewStr = B.CreateGlobalStringPtr("hayaku... motohayaku!");
      Argument *Argv = F.getArg(1);
      Value *GEP = B.CreateInBoundsGEP(
        Argv->getType()->getPointerElementType(),
        Argv,
        Const1
      );
      B.CreateStore(NewStr, GEP);

      return true;
    }
  };
}
char Lab6PassLegacy::ID = 0;
static RegisterPass<Lab6PassLegacy> LegacyReg("lab6pass",
                                              "Lab6 legacy FunctionPass",
                                              false, false);

// ============ New PassManager ModulePass ============
namespace {
  struct Lab6ModulePass : PassInfoMixin<Lab6ModulePass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
      Function *F = M.getFunction("main");
      if (!F) return PreservedAnalyses::all();

      LLVMContext &Ctx = M.getContext();
      IRBuilder<> B(&*F->getEntryBlock().getFirstInsertionPt());

      // constants
      Type    *Int32Ty = Type::getInt32Ty(Ctx);
      Constant *ConstID = ConstantInt::get(Int32Ty, 48763);
      Constant *Const1  = ConstantInt::get(Int32Ty, 1);

      // 1) debug(48763)
      FunctionCallee debugFn = M.getOrInsertFunction(
        "debug",
        FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false)
      );
      B.CreateCall(debugFn, {ConstID});

      // 2) argc = 48763
      Argument *Argc = F->getArg(0);
      for (auto UI = Argc->use_begin(), UE = Argc->use_end(); UI != UE; ) {
        Use &U = *UI++;
        U.set(ConstID);
      }

      // 3) argv[1] = "hayaku... motohayaku!"
      Constant *NewStr = B.CreateGlobalStringPtr("hayaku... motohayaku!");
      Argument *Argv = F->getArg(1);
      Value *GEP = B.CreateInBoundsGEP(
        Argv->getType()->getPointerElementType(),
        Argv,
        Const1
      );
      B.CreateStore(NewStr, GEP);

      return PreservedAnalyses::none();
    }
  };
}

// Plugin entrypoint: register both legacy and new-PM passes
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "lab6pass",
    LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      // Allow -passes=lab6pass in opt's new-PM
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM,
           ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "lab6pass") {
            MPM.addPass(Lab6ModulePass());
            return true;
          }
          return false;
        }
      );
      // Inject our ModulePass at the start of every new-PM pipeline
      PB.registerPipelineStartEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(Lab6ModulePass());
        }
      );
    }
  };
}


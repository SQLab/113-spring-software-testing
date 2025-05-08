#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *I32 = IntegerType::getInt32Ty(Ctx);

  FunctionCallee DebugFn = M.getOrInsertFunction(
      "debug", FunctionType::get(Type::getVoidTy(Ctx), {I32}, false));
  Constant *Cst48763 = ConstantInt::get(I32, 48763);

  for (auto &F : M) {
    if (F.getName() != "main")
      continue;                        /* 只處理 main */

    BasicBlock &Entry = F.getEntryBlock();

    /* 1️⃣ debug(48763) */
    IRBuilder<> IR(&*Entry.getFirstInsertionPt());
    IR.CreateCall(DebugFn, {Cst48763});

    /* ---------- 找出 argc 與 argv 的 alloca ---------- */
    AllocaInst *ArgcA = nullptr;
    AllocaInst *ArgvA = nullptr;
    for (Instruction &I : Entry) {
      AllocaInst *AI = dyn_cast<AllocaInst>(&I);
      if (!AI)
        continue;
      if (AI->getAllocatedType()->isIntegerTy(32))
        ArgcA = AI;
      else if (AI->getAllocatedType()->isPointerTy() &&
               AI->getAllocatedType()->getPointerElementType()->isPointerTy())
        ArgvA = AI;
    }

    /* ---------- 覆寫 argc alloca ---------- */
    if (ArgcA) {
      for (Instruction *P = ArgcA->getNextNode(); P; P = P->getNextNode()) {
        StoreInst *SI = dyn_cast<StoreInst>(P);
        if (SI && SI->getPointerOperand() == ArgcA) {
          IRBuilder<> B(P->getNextNode());
          B.CreateStore(Cst48763, ArgcA);
          break;
        }
      }
    }

    /* ---------- 覆寫 argv[1] ---------- */
    if (ArgvA) {
      Instruction *StorePos = nullptr;
      for (Instruction *P = ArgvA->getNextNode(); P; P = P->getNextNode()) {
        StoreInst *SI = dyn_cast<StoreInst>(P);
        if (SI && SI->getPointerOperand() == ArgvA) {
          StorePos = P;
          break;
        }
      }
      if (StorePos) {
        IRBuilder<> B(StorePos->getNextNode());
        Value *Argv = B.CreateLoad(ArgvA->getAllocatedType(), ArgvA); // i8**
        Value *Idx1 = ConstantInt::get(I32, 1);
        Value *ElemPtr = B.CreateGEP(
            ArgvA->getAllocatedType()->getPointerElementType(), Argv, Idx1);
        Value *StrPtr = B.CreateGlobalStringPtr("hayaku... motohayaku!");
        B.CreateStore(StrPtr, ElemPtr);
      }
    }
  }
  return PreservedAnalyses::none();    /* IR 已修改 */
}

/* ---------- Plug-in 註冊 ---------- */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(LLVMPass());
                });
          }};
}

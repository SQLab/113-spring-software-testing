#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);

  /*─── debug(int) ────────────────────────────────────────*/
  FunctionType  *DebugTy = FunctionType::get(Int32Ty, {Int32Ty}, false);
  FunctionCallee DebugFn = M.getOrInsertFunction("debug", DebugTy);
  ConstantInt   *Val48763 = ConstantInt::get(Int32Ty, 48763);

  /*─── 遍歷所有函式，鎖定 main ─────────────────────────────*/
  for (Function &F : M) {
    if (F.getName() != "main") continue;

    /* ① 插入 call debug(48763) ────────────────────────*/
    BasicBlock &Entry = F.getEntryBlock();
    IRBuilder<> IB(&*Entry.getFirstInsertionPt());
    IB.CreateCall(DebugFn, {Val48763});

    /* ② 把 argc 覆寫成 48763 ───────────────────────────*/
    for (Instruction &I : Entry) {
      if (auto *SI = dyn_cast<StoreInst>(&I)) {
        // store i32 %argc, i32* %argc.addr  ?
        if (SI->getValueOperand() == F.getArg(0)) {
          Value *ArgcAlloca = SI->getPointerOperand();          // %argc.addr
          IRBuilder<> AfterSI(SI->getNextNode());               // 插在下一行
          AfterSI.CreateStore(Val48763, ArgcAlloca);            // 覆寫
          break;                                                // 找到就離開內層 loop
        }
      }
    }
    /* 覆寫 argv[1] */
    Argument *argvArg = F.getArg(1);
    ConstantInt *Idx1 = ConstantInt::get(Int32Ty, 1);
    Value *Argv1Ptr   = IB.CreateInBoundsGEP(
                          argvArg->getType()->getPointerElementType(),
                          argvArg,
                          Idx1,
                          "argv1_ptr");
    Value *HayakuStr  = IB.CreateGlobalStringPtr("hayaku... motohayaku!", "hayaku_str");
    IB.CreateStore(HayakuStr, Argv1Ptr);
    break;   // main() 處理完即可離開函式迴圈
  }

  return PreservedAnalyses::none();   // 告訴 LLVM：IR 被修改過
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
    [](PassBuilder &PB) {
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel OL) {
          MPM.addPass(LLVMPass());
        });
    }};
}


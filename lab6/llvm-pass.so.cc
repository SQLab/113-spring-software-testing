// llvm-pass.so.cc
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include <vector>
using namespace llvm;

struct LLVMPass : PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &Ctx    = M.getContext();
    IntegerType *i32Ty  = Type::getInt32Ty(Ctx);
    PointerType *i8PtrTy= Type::getInt8PtrTy(Ctx);

    // 1) debug(int)
    FunctionCallee debugFn = M.getOrInsertFunction(
      "debug",
      FunctionType::get(Type::getVoidTy(Ctx), {i32Ty}, false)
    );
    Constant *debugArg = ConstantInt::get(i32Ty, 48763);

    // 2) 準備常量字串
    Constant *strData = ConstantDataArray::getString(
      Ctx, "hayaku... motohayaku!", true);
    GlobalVariable *gvStr = new GlobalVariable(
      M, strData->getType(), true,
      GlobalValue::PrivateLinkage, strData, "lab6_str");
    Value *strPtr = ConstantExpr::getBitCast(gvStr, i8PtrTy);

    // 找 main 函式
    if (Function *mainF = M.getFunction("main")) {
      // 在 EntryBlock 首個插入點呼叫 debug(48763)
      IRBuilder<> B(&*mainF->getEntryBlock().getFirstInsertionPt());
      B.CreateCall(debugFn, { debugArg });

      // 取出 main(argc, argv) 的參數
      Argument *argcArg = nullptr, *argvArg = nullptr;
      auto it = mainF->arg_begin();
      if (it != mainF->arg_end()) argcArg = &*it++;
      if (it != mainF->arg_end()) argvArg = &*it;

      // 搜集所有要移除的 LoadInst
      std::vector<Instruction*> toErase;

      // 遍历所有指令
      for (auto &BB : *mainF) {
        for (auto &I : BB) {
          // (a) 替换所有使用 argcArg 的地方
          for (unsigned u = 0; u < I.getNumOperands(); ++u) {
            if (I.getOperand(u) == argcArg)
              I.setOperand(u, debugArg);
          }

          // (b) 找到 load argv[1] 的 LoadInst，替换它的所有使用

          if (auto *LI = dyn_cast<LoadInst>(&I)) {
                        // 把所有 index==1 的 GEP 载入都替换
                        Value *ptr = LI->getPointerOperand()->stripPointerCasts();
                        if (auto *G = dyn_cast<GetElementPtrInst>(ptr)) {
                          if (G->getNumIndices() == 1) {
                            if (auto *CI = dyn_cast<ConstantInt>(G->getOperand(1))) {
                              if (CI->equalsInt(1)) {
                                LI->replaceAllUsesWith(strPtr);
                                toErase.push_back(LI);
                              }
                            }
                          }
                        }
                      }

          // (c) 用 arg_size() 替换 strcmp 的第一個參數
          if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (Function *callee = CI->getCalledFunction()) {
              if (callee->getName() == "strcmp" && CI->arg_size() >= 2) {
                CI->setArgOperand(0, strPtr);
              }
            }
          }
        }
      }

      // 真正刪除那些已被替換的 LoadInst
      for (auto *I : toErase)
        I->eraseFromParent();
    }

    return PreservedAnalyses::none();
  }
};

// 註冊為 LLVM Plugin
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "Lab6Pass", "v1.0",
    [](PassBuilder &PB) {
    //   PB.registerOptimizerLastEPCallback(
    //     [](ModulePassManager &MPM, OptimizationLevel) {
    //       MPM.addPass(LLVMPass());
    //     });
    // }
     // 無論 -O0 還是 -O1/O2，都在 pipeline 一開始插入 LLVMPass
      PB.registerPipelineStartEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(LLVMPass());
      });
    }
  };
}

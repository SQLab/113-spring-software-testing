#include "llvm/Passes/PassBuilder.h" // 引入新版Pass Manager的PassBuilder，用於註冊Pass
#include "llvm/Passes/PassPlugin.h"  // 引入Pass插件API，用於定義插件入口點
#include "llvm/IR/Module.h"          // 提供Module類，代表整個程式模組
#include "llvm/IR/Function.h"        // 提供Function類，代表單個函數
#include "llvm/IR/BasicBlock.h"      // 提供BasicBlock類，代表函數中的基本塊
#include "llvm/IR/IRBuilder.h"       // 提供IRBuilder類，用於生成LLVM IR指令
#include "llvm/IR/Instructions.h"    // 提供指令類，如CallInst、StoreInst等
#include "llvm/IR/Type.h"            // 提供類型定義，如IntegerType、PointerType
#include "llvm/IR/Constants.h"       // 提供常數類，如ConstantInt、ConstantDataArray
#include "llvm/Support/raw_ostream.h" // 提供輸出流，支援LLVM內部除錯（本程式未使用）

using namespace llvm; // 使用llvm命名空間，避免重複寫llvm::

namespace { // 匿名命名空間，限制類和函數的範圍僅在本檔案內

// 定義LLVMPass結構，繼承PassInfoMixin以適配新版Pass Manager
struct LLVMPass : public PassInfoMixin<LLVMPass> {
  // run方法：Pass的核心邏輯，處理模組並執行插樁
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    // 獲取LLVM上下文，用於創建IR物件（如類型、常數）
    LLVMContext &Ctx = M.getContext();
    // 定義32位整數類型（i32），用於argc和debug參數
    IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
    // 定義void類型，用於debug函數的回傳值
    Type *VoidTy = Type::getVoidTy(Ctx);
    // 定義指向8位整數的指標類型（i8*），用於字串指標（char*）
    Type *Int8PtrTy = Type::getInt8PtrTy(Ctx);

    // 需求1：準備debug函數和參數
    // 定義debug函數的簽名：void debug(i32)
    FunctionType *DebugFnTy = FunctionType::get(VoidTy, {Int32Ty}, false);
    // 獲取或插入debug函數的宣告，若不存在則創建原型
    FunctionCallee DebugFunc = M.getOrInsertFunction("debug", DebugFnTy);
    // 創建常數48763（i32），作為debug函數的參數
    ConstantInt *DebugArg = ConstantInt::get(Int32Ty, 48763);

    // 需求2：創建全域字串常數"hayaku... motohayaku!"
    // 生成字串常數，true表示添加結束符\0
    Constant *StrConst = ConstantDataArray::getString(Ctx, "hayaku... motohayaku!", true);
    // 創建全域變數儲存字串，常數且僅模組內可見
    GlobalVariable *StrGlobal = new GlobalVariable(
        M, StrConst->getType(), true, GlobalVariable::InternalLinkage, StrConst, "");
    // 創建常數0（i32），用於計算字串地址
    ConstantInt *Zero = ConstantInt::get(Int32Ty, 0);
    // 計算字串的起始地址（i8*），用於存入argv[1]
    Value *StrPtr = ConstantExpr::getGetElementPtr(StrConst->getType(), StrGlobal, Zero);

    // 遍歷模組中的所有函數
    for (Function &F : M) {
      // 檢查是否為main函數
      if (F.getName() == "main") {
        // 獲取main函數的入口基本塊
        BasicBlock &EntryBB = F.getEntryBlock();
        // 創建IRBuilder，插入點設為基本塊的第一條指令
        IRBuilder<> IRB(&EntryBB, EntryBB.getFirstInsertionPt());

        // 需求1：插入對debug(48763)的呼叫
        IRB.CreateCall(DebugFunc, {DebugArg});

        // 需求2：將argv[1]設為"hayaku... motohayaku!"
        // 獲取argv（main的第二個參數，char**）
        Value *Argv = F.getArg(1);
        // 計算argv[1]的地址（char*），索引1
        Value *Argv1Ptr = IRB.CreateGEP(Int8PtrTy, Argv, ConstantInt::get(Int32Ty, 1));
        // 將全域字串的地址存入argv[1]
        IRB.CreateStore(StrPtr, Argv1Ptr);

        // 需求3：將argc設為48763
        // 獲取argc（main的第一個參數，i32）
        Value *Argc = F.getArg(0);
        // 創建常數48763（i32）
        ConstantInt *NewArgc = ConstantInt::get(Int32Ty, 48763);
        // 將argc的所有使用替換為48763
        Argc->replaceAllUsesWith(NewArgc);
      }
    }

    // 回傳PreservedAnalyses::none()，表示可能影響所有分析
    return PreservedAnalyses::none();
  }
};

} // 結束匿名命名空間

// 定義插件入口點，告訴LLVM如何載入此Pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, // 插件API版本
    "LLVMPass",              // 插件名稱
    "v0.1",                  // 插件版本
    [](PassBuilder &PB) {    // 插件初始化回調
      // 註冊到優化管線末尾，自動執行Pass
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(LLVMPass());
          return true;
        });
      // 也支援顯式調用（-passes=llvm-pass）
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "llvm-pass") {
            MPM.addPass(LLVMPass());
            return true;
          }
          return false;
        });
    }};
}
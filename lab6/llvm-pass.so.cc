#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"

namespace {
using namespace llvm;

class CustomModulePass : public PassInfoMixin<CustomModulePass> {
public:
  PreservedAnalyses run(Module &Module, ModuleAnalysisManager &AnalysisManager);
};

PreservedAnalyses CustomModulePass::run(Module &Module, ModuleAnalysisManager &AnalysisManager) {
  LLVMContext &Context = Module.getContext();
  
  // Create types
  auto *I32Type = Type::getInt32Ty(Context);
  
  // Setup debug function
  FunctionType *DebugFunctionType = FunctionType::get(Type::getVoidTy(Context), {I32Type}, false);
  FunctionCallee DebugFunction = Module.getOrInsertFunction("debug", DebugFunctionType);
  
  // Magic number constant
  ConstantInt *MagicNumber = ConstantInt::get(I32Type, 48763);
  
  // Process functions in module
  for (Function &CurrentFunction : Module) {
    // Skip non-main functions and declarations
    if (CurrentFunction.getName() != "main" || CurrentFunction.isDeclaration())
      continue;
      
    errs() << "Processing function: " << CurrentFunction.getName() << "\n";
    
    // Get function arguments
    auto ArgIterator = CurrentFunction.arg_begin();
    Argument *ArgCount = &*ArgIterator++;
    Argument *ArgVector = &*ArgIterator;
    
    // Insert at the beginning of function entry block
    IRBuilder<> IRB(&*CurrentFunction.getEntryBlock().begin());
    
    // Insert call to debug function
    IRB.CreateCall(DebugFunction, {MagicNumber});
    
    // Replace all uses of argc with magic number
    for (BasicBlock &Block : CurrentFunction) {
      for (Instruction &Inst : Block) {
        for (unsigned OpIdx = 0; OpIdx < Inst.getNumOperands(); ++OpIdx) {
          if (Inst.getOperand(OpIdx) == ArgCount) {
            Inst.setOperand(OpIdx, MagicNumber);
          }
        }
      }
    }
    
    // Modify argv[1]
    Value *IndexOne = ConstantInt::get(I32Type, 1);
    Value *SecondArgPtr = IRB.CreateInBoundsGEP(ArgVector->getType()->getPointerElementType(), 
                                                ArgVector, IndexOne);
    Value *MessagePtr = IRB.CreateGlobalStringPtr("hayaku... motohayaku!");
    IRB.CreateStore(MessagePtr, SecondArgPtr);
  }
  
  return PreservedAnalyses::none();
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
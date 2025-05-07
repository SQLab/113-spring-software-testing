#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/Support/raw_ostream.h"

namespace {

// Module transformation to modify main function
class ModuleTransform : PassInfoMixin<ModuleTransform> {
public:
  PreservedAnalyses run(llvm::Module& Module, llvm::ModuleAnalysisManager& AM) {
    // Debug constant value
    const uint32_t DEBUG_MAGIC = 48763;
    
    // Get necessary types
    auto& Context = Module.getContext();
    auto* Int32Type = llvm::Type::getInt32Ty(Context);
    auto* CharPtrType = llvm::Type::getInt8PtrTy(Context);
    
    // Create debug function declaration
    auto* DebugFuncType = llvm::FunctionType::get(
      llvm::Type::getVoidTy(Context), 
      {Int32Type}, 
      false
    );
    auto DebugFunction = Module.getOrInsertFunction("debug", DebugFuncType);
    
    // Create magic number constant
    auto* MagicNumber = llvm::ConstantInt::get(Int32Type, DEBUG_MAGIC);
    
    // Create string constant
    auto* HiddenMessage = llvm::ConstantDataArray::getString(
      Context, 
      "hayaku... motohayaku!", 
      true
    );
    
    // Create global variable for the string
    auto* StringGlobal = new llvm::GlobalVariable(
      Module,
      HiddenMessage->getType(),
      true,
      llvm::GlobalValue::PrivateLinkage,
      HiddenMessage,
      ".str.hayaku"
    );
    
    // Create GEP indices for string pointer
    auto* ZeroIndex = llvm::ConstantInt::get(Int32Type, 0);
    llvm::Constant* Indices[2] = {ZeroIndex, ZeroIndex};
    
    // Get pointer to string
    auto* StringPointer = llvm::ConstantExpr::getGetElementPtr(
      HiddenMessage->getType(), 
      StringGlobal, 
      Indices
    );
    
    // Find and instrument main function
    for (auto& Func : Module) {
      if (Func.getName() != "main")
        continue;
        
      llvm::errs() << "Found and instrumenting: " << Func.getName() << "\n";
      
      // Create builder at entry point
      llvm::IRBuilder<> Builder(&Func.getEntryBlock().front());
      
      // Insert debug call
      Builder.CreateCall(DebugFunction, {MagicNumber});
      
      // Get function args
      auto Args = Func.arg_begin();
      auto* ArgCount = Args++;
      auto* ArgVector = Args;
      
      // Modify argv[1] to point to our string
      auto* SecondArgPtr = Builder.CreateGEP(CharPtrType, ArgVector, 
                                           llvm::ConstantInt::get(Int32Type, 1));
      Builder.CreateStore(StringPointer, SecondArgPtr);
      
      // Replace all uses of argc with our magic value
      ArgCount->replaceAllUsesWith(MagicNumber);
    }
    
    // Mark all analyses as invalidated
    return PreservedAnalyses::none();
  }
};

} // anonymous namespace

// Plugin registration
extern "C" LLVM_ATTRIBUTE_WEAK 
::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "ModuleInstrumenter",  // plugin name
    "v1.0",                // plugin version
    [](llvm::PassBuilder &PB) {
      PB.registerOptimizerLastEPCallback(
        [](llvm::ModulePassManager &MPM, llvm::OptimizationLevel Level) {
          MPM.addPass(ModuleTransform());
        }
      );
    }
  };
}
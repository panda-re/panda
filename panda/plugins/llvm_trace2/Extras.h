

#include <vector>



namespace llvm {

/// Given an LLVM value, insert a cast expressions or cast instructions as
/// necessary to make the value the specified type.
///
/// \param V - The value which needs to be of the specified type.
/// \param Ty - The type to which V should be casted (if necessary).
/// \param Name - The name to assign the new casted value (if one is created).
/// \param InsertPt - The point where a cast instruction should be inserted
/// \return An LLVM value of the desired type, which may be the original value
///         passed into the function, a constant cast expression of the passed
///         in value, or an LLVM cast instruction.
static inline Value *castTo(Value *V,
                            Type *Ty,
                            Twine Name,
                            Instruction *InsertPt) {
  // Assert that we're not trying to cast a NULL value.
  assert (V && "castTo: trying to cast a NULL Value!\n");

  // Don't bother creating a cast if it's already the correct type.
  if (V->getType() == Ty)
    return V;

  // If it's a constant, just create a constant expression.
  if (Constant *C = dyn_cast<Constant>(V)) {
    Constant *CE = ConstantExpr::getZExtOrBitCast(C, Ty);
    return CE;
  }

  // Otherwise, insert a cast instruction.
  return CastInst::CreateZExtOrBitCast(V, Ty, Name, InsertPt);
}
/// make_vector - Helper function which is useful for building temporary vectors
/// to pass into type construction of CallInst ctors.  This turns a null
/// terminated list of pointers (or other value types) into a real live vector.
///
template<typename T>
inline std::vector<T> make_vector(T A, ...) {
  va_list Args;
  va_start(Args, A);
  std::vector<T> Result;
  Result.push_back(A);
  while (T Val = va_arg(Args, T))
    Result.push_back(Val);
  va_end(Args);
  return Result;
}

}

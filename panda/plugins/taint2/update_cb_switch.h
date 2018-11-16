/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

/*
 * This file is the contents of the switch statement in the update_cb function
 * in the taint_ops file.  It is separated out like this so it is possible to
 * write test code for the bit twiddling in the switch statement without
 * actually running a replay or slowing the already slow taint propagation
 * process down even further by adding a function that update_cb calls.
 * Don't forget to put the include statements in the file where this file is
 * included, nor to declare the variables this code snippet requires.  For
 * guidance, see update_cb in the taint_ops.cpp file, or the test code in the
 * update_cb_switch folder of the taint2 tests subfolder.
 */

 
    switch (opcode) {
        // Totally reversible cases.
        case llvm::Instruction::Sub:
            if (literals[1] == ~0UL) {
                tassert(last_literal != ~0UL);
                // first operand is a variable. so negate.
                // throw out ones/zeroes info.
                // FIXME: handle better.
                one_mask = zero_mask = 0;
                break;
            } // otherwise fall through.
        case llvm::Instruction::Add:
            tassert(last_literal != ~0UL);
            
            // can't use the standard __builtin_clz, because its argument is an
            // unsigned int, which may not be 64 bits on this machine
            log2 = 64 - clz64(last_literal);
            // FIXME: this isn't quite right. for example, if all bits ones,
            // adding one makes all bits zero.
            if (log2 < 64)
            {
                // darned compiler does bit twiddling in 32 bits even though all
                // the variables are uint64_t, so have to force it to 64 bits or
                // answers will be wrong in some cases
                one_mask &= ~(((uint64_t)1 << log2) - 1);
                zero_mask &= ~(((uint64_t)1 << log2) - 1);
            }
            else
            {
                one_mask = 0;
                zero_mask = 0;
            }
            break;

        case llvm::Instruction::Xor:
            one_mask &= ~last_literal;
            one_mask |= last_literal & orig_zero_mask;
            zero_mask &= ~last_literal;
            zero_mask |= last_literal & orig_one_mask;
            break;

        case llvm::Instruction::ZExt:
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::PtrToInt:
        case llvm::Instruction::BitCast:
        // This one copies the existing bits and adds non-controllable bits.
        // One and zero masks too complicated to compute. Bah.
        case llvm::Instruction::SExt:
        // Copies. These we ignore (the copy will copy the CB data for us)
        case llvm::Instruction::Store:
        case llvm::Instruction::Load:
        case llvm::Instruction::ExtractValue:
        case llvm::Instruction::InsertValue:
            break;

        case llvm::Instruction::Trunc:
            // explicitly cast or will get wrong answer when size=4
            if (size < 8)
            {
                cb_mask &= ((uint64_t)1 << (size * 8)) - 1;
                one_mask &= ((uint64_t)1 << (size * 8)) - 1;
                zero_mask &= ((uint64_t)1 << (size * 8)) - 1;
            }
            // if truncating to 8 bytes, not really truncating, as largest
            // number we can handle (currently) is 64 bits - thus no change
            break;

        case llvm::Instruction::Mul:
        { //TODO can implement this through strength reduction to shift and sub
            tassert(last_literal != ~0UL);
            // Powers of two in last_literal destroy reversibility.
            uint64_t trailing_zeroes = ctz64(last_literal);
            cb_mask <<= trailing_zeroes;
            // cast so works on large numbers too, or any shift over 31 not
            // handled properly
            zero_mask = ((uint64_t)1 << trailing_zeroes) - 1;
            one_mask = 0;
            break;
        }

        case llvm::Instruction::URem:
        case llvm::Instruction::SRem:
            tassert(last_literal != ~0UL);
            tassert(last_literal != 0UL);  // /0 makes these LLVM ops undefined
            log2 = 64 - clz64(last_literal);
            if (log2 < 64)
            {
                cb_mask &= ((uint64_t)1 << log2) - 1;
            }
            // if no leading zeros, then keep the whole mask - no-op
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::UDiv:
        case llvm::Instruction::SDiv:
            tassert(last_literal != ~0UL);
            log2 = 64 - clz64(last_literal);
            if (log2 < 64)
            {
                cb_mask >>= log2;
            }
            else
            {
                cb_mask = 0;
            }
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::And:
            tassert(last_literal != ~0UL);
            // Bits not in the bit mask are no longer controllable
            cb_mask &= last_literal;
            zero_mask |= ~last_literal;
            one_mask &= last_literal;
            break;

        case llvm::Instruction::Or:
            tassert(last_literal != ~0UL);
            // Bits in the bit mask are no longer controllable
            cb_mask &= ~last_literal;
            one_mask |= last_literal;
            zero_mask &= ~last_literal;
            break;

        case llvm::Instruction::Shl:
            tassert(last_literal != ~0UL);
            
            // assuming the item being shifted by LShr is at most 64 bits, as
            // the masks can't handle anything larger
            tassert(last_literal < 64);
            
            cb_mask <<= last_literal;
            one_mask <<= last_literal;
            zero_mask <<= last_literal;
            zero_mask |= ((uint64_t)1 << last_literal) - 1;
            break;

        case llvm::Instruction::LShr:
            tassert(last_literal != ~0UL);

            // if not really shifting, should be getting back what started with
            if (last_literal != 0)
            {
                cb_mask >>= last_literal;
                one_mask >>= last_literal;
                zero_mask >>= last_literal;
            
                // (size * 8) is the number of bits in the item LLVM is shifting
                zero_mask |= ~(((uint64_t)1 << ((size * 8) - last_literal)) - 1);
            }
            break;

        case llvm::Instruction::AShr: // High bits not really controllable.
            tassert(last_literal != ~0UL);
            
            // if not really shifting, should be getting back what started with
            if (last_literal != 0)
            {
                cb_mask >>= last_literal;
                one_mask >>= last_literal;
                zero_mask >>= last_literal;

                // See if high bit is a last_literal
                if (orig_one_mask & ((uint64_t)1 << ((size * 8) - 1))) {
                    one_mask |= ~(((uint64_t)1 << ((size * 8) - last_literal)) - 1);
                } else if (orig_zero_mask & ((uint64_t)1 << ((size * 8) - 1))) {
                    zero_mask |= ~(((uint64_t)1 << ((size * 8) - last_literal)) - 1);
               }
            }
            break;

        // Totally irreversible cases. Erase and bail.
        case llvm::Instruction::FAdd:
        case llvm::Instruction::FSub:
        case llvm::Instruction::FMul:
        case llvm::Instruction::FDiv:
        case llvm::Instruction::FRem:
        case llvm::Instruction::Call:
        case llvm::Instruction::ICmp:
        case llvm::Instruction::FCmp:
            cb_mask = 0;
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::GetElementPtr:
        {
            llvm::GetElementPtrInst *GEPI =
                llvm::dyn_cast<llvm::GetElementPtrInst>(I);
            tassert(GEPI);
            one_mask = 0;
            zero_mask = 0;
            // Constant indices => fully reversible
            if (GEPI->hasAllConstantIndices()) break;
            // Otherwise we know nothing.
            cb_mask = 0;
            break;
        }

        default:
            printf("Unknown instruction in update_cb: ");
            I->dump();
            fflush(stdout);
            return;
    }

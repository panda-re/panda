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

    bool validate_last_literal = true;

    switch (opcode) {
        // Totally reversible cases.
        case llvm::Instruction::Sub:
            if (literals[1] == NOT_LITERAL) {
                tassert(last_literal != NOT_LITERAL);
                // first operand is a variable. so negate.
                // throw out ones/zeroes info.
                // FIXME: handle better.
                one_mask = zero_mask = 0;
                break;
            } // otherwise fall through.
        case llvm::Instruction::Add:
            tassert(last_literal != NOT_LITERAL);

            log2 = CB_WIDTH - last_literal.countLeadingZeros();
            // FIXME: this isn't quite right. for example, if all bits ones,
            // adding one makes all bits zero.
            if (log2 < CB_WIDTH) {
                llvm::APInt mask = ~((llvm::APInt(CB_WIDTH, 1ul) << log2) - 1);
                one_mask &= mask;
                zero_mask &= mask;
            } else {
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
            validate_last_literal = false;
            break;

        case llvm::Instruction::Trunc:
            // explicitly cast or will get wrong answer when size=4
            if (size < (CB_WIDTH / 8)) {
                llvm::APInt mask =
                    (llvm::APInt(CB_WIDTH, 1ul) << (size * 8)) - 1;
                cb_mask &= mask;
                one_mask &= mask;
                zero_mask &= mask;
            }
            // if truncating to (CB_WIDTH / 8) bytes, not really truncating, as
            // largest number we can handle is CB_WIDTH bits - thus no change
            validate_last_literal = false;
            break;

        case llvm::Instruction::Mul:
        { //TODO can implement this through strength reduction to shift and sub
            tassert(last_literal != NOT_LITERAL);
            // Powers of two in last_literal destroy reversibility.
            int trailing_zeroes = last_literal.countTrailingZeros();
            cb_mask <<= trailing_zeroes;
            // cast so works on large numbers too, or any shift over 31 not
            // handled properly
            zero_mask = (llvm::APInt(CB_WIDTH, 1) << trailing_zeroes) - 1;
            one_mask = 0;
            break;
        }

        case llvm::Instruction::URem:
        case llvm::Instruction::SRem:
            tassert(last_literal != NOT_LITERAL);
            tassert(last_literal != 0UL);  // /0 makes these LLVM ops undefined
            log2 = CB_WIDTH - last_literal.countLeadingZeros();
            if (log2 < CB_WIDTH) {
                cb_mask &= (llvm::APInt(CB_WIDTH, 1) << log2) - 1;
            }
            // if no leading zeros, then keep the whole mask - no-op
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::UDiv:
        case llvm::Instruction::SDiv:
            tassert(last_literal != NOT_LITERAL);
            log2 = CB_WIDTH - last_literal.countLeadingZeros();
            if (log2 < CB_WIDTH) {
                cb_mask = cb_mask.lshr(log2);
            } else {
                cb_mask = 0;
            }
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::And:
            tassert(last_literal != NOT_LITERAL);
            // Bits not in the bit mask are no longer controllable
            cb_mask &= last_literal;
            zero_mask |= ~last_literal;
            one_mask &= last_literal;
            break;

        case llvm::Instruction::Or:
            tassert(last_literal != NOT_LITERAL);
            // Bits in the bit mask are no longer controllable
            cb_mask &= ~last_literal;
            one_mask |= last_literal;
            zero_mask &= ~last_literal;
            break;

        case llvm::Instruction::Shl:
            tassert(last_literal != NOT_LITERAL);

            // assuming the item being shifted by Shl is at most CB_WIDTH bits,
            // as the masks can't handle anything larger
            if (last_literal.getZExtValue() > CB_WIDTH) {
                // Preserve previous behavior
                cb_mask = 0;
                one_mask = 0;
                zero_mask = 0;
            } else {
                cb_mask <<= last_literal.getZExtValue();
                one_mask <<= last_literal.getZExtValue();
                zero_mask <<= last_literal.getZExtValue();
                zero_mask |= (llvm::APInt(CB_WIDTH, 1ul)
                              << last_literal.getZExtValue()) -
                             1;
            }
            break;

        case llvm::Instruction::LShr:
            tassert(last_literal != NOT_LITERAL);

            // if not really shifting, should be getting back what started with
            if (last_literal != 0)
            {
                cb_mask = cb_mask.lshr(last_literal);
                one_mask = one_mask.lshr(last_literal);
                zero_mask = zero_mask.lshr(last_literal);

                // (size * 8) is the number of bits in the item LLVM is shifting
                if ((size * 8) - last_literal.getZExtValue() > CB_WIDTH) {
                    zero_mask |= llvm::APInt(CB_WIDTH, 0ul);
                } else {
                    zero_mask |=
                        ~((llvm::APInt(CB_WIDTH, 1ul)
                           << ((size * 8) - last_literal.getZExtValue())) -
                          1);
                }
            }
            break;

        case llvm::Instruction::AShr: // High bits not really controllable.
            tassert(last_literal != NOT_LITERAL);

            // if not really shifting, should be getting back what started with
            if (last_literal.getZExtValue() > CB_WIDTH) {
                cb_mask = 0;
                one_mask = 0;
                zero_mask = 0;
            } else if (last_literal != 0) {
                cb_mask = cb_mask.lshr(last_literal);
                one_mask = one_mask.lshr(last_literal);
                zero_mask = zero_mask.lshr(last_literal);

                // See if high bit is a last_literal
                llvm::APInt orig_mask = llvm::APInt(CB_WIDTH, 1ul)
                                        << ((size * 8) - 1);
                llvm::APInt mask =
                    ~((llvm::APInt(CB_WIDTH, 1ul)
                       << ((size * 8) - last_literal.getZExtValue())) -
                      1);
                if ((orig_one_mask & orig_mask).ugt(0)) {
                    one_mask |= mask;
                } else if ((orig_zero_mask & orig_mask).ugt(0)) {
                    zero_mask |= mask;
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
            validate_last_literal = false;
            break;

        case llvm::Instruction::GetElementPtr:
        {
            validate_last_literal = false;
            one_mask = 0;
            zero_mask = 0;
            // Constant indices => fully reversible
            if (instruction_flags & INSTRUCTION_FLAG_GEP_HAS_CONSTANT_INDICES) break;
            // Otherwise we know nothing.
            cb_mask = 0;
            break;
        }

        default:
            printf("Unknown instruction in update_cb: ");
            //dump only available if LLVM compiled with dump enabled
            //I->dump();
            fflush(stdout);
            return;
    }

    static int warning_count = 0;
    if (validate_last_literal && (10 > warning_count) && (NOT_LITERAL == last_literal)) {
        fprintf(stderr,
                "%sWARNING: Could not find last literal value, control "
                "bits may be incorrect.\n",
                PANDA_MSG);
        warning_count++;
        if (warning_count == 10) {
            fprintf(stderr,
                    "%sLast literal warning emitted %d times, suppressing "
                    "warning.\n",
                    PANDA_MSG, warning_count);
        }
    }

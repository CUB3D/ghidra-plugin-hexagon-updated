/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PackedEncode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

public class HexagonParallelInstructionLanguageHelper implements ParallelInstructionLanguageHelper {
	@Override
	public String getMnemonicPrefix(Instruction instr) {
		Program program = instr.getProgram();
		BigInteger pkt_start = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("pkt_start"), instr.getAddress(), false);
		if (pkt_start == null || pkt_start.intValue() == 0) {
			// not yet analyzed
			return null;
		}
		if (pkt_start.equals(instr.getAddress().getOffsetAsBigInteger())) {
			// start of packet
			return "{";
		}
		// middle of packet
		return null;
	}

	@Override
	public boolean isParallelInstruction(Instruction instr) {
		BigInteger pkt_start = startPacket(instr);
		if (pkt_start == null) {
			// not yet analyzed
			return false;
		}
		// if this inst is after start then yes
		return instr.getAddress().add(instr.getLength()).getOffsetAsBigInteger().compareTo(pkt_start) > 0;
	}

	public static BigInteger nextPacket(Instruction instr) {
		Program program = instr.getProgram();
		BigInteger pkt_next = program.getProgramContext().getValue(program.getProgramContext().getRegister("pkt_next"),
				instr.getAddress(), false);
		if (pkt_next == null || pkt_next.intValue() == 0) {
			// not yet analyzed
			return null;
		}
		return pkt_next;
	}

	BigInteger startPacket(Instruction instr) {
		Program program = instr.getProgram();
		BigInteger pkt_start = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("pkt_start"), instr.getAddress(), false);
		if (pkt_start == null || pkt_start.intValue() == 0) {
			// not yet analyzed
			return null;
		}
		return pkt_start;
	}

	@Override
	public boolean isEndOfParallelInstructionGroup(Instruction instr) {
		BigInteger pkt_next = nextPacket(instr);
		if (pkt_next == null) {
			// not yet analyzed
			return false;
		}
		return instr.getAddress().add(instr.getLength()).getOffsetAsBigInteger().equals(pkt_next);
	}

	// called via reflection
	public void getPcodePacked(PackedEncode enc, Program program, InstructionContext context)
			throws UnknownInstructionException {
		HexagonPcodeEmitPacked emit = new HexagonPcodeEmitPacked(program, true);
		emit.getPcodePacked(context, enc, new UniqueAddressFactoryRevived(program.getAddressFactory(), program.getLanguage()));
	}

	// called via reflection
	public FlowType getFlowType(Instruction instr) {
		Program program = instr.getProgram();

		BigInteger pkt_start = startPacket(instr);
		if (pkt_start == null) {
			// not yet analyzed
			return RefType.INVALID;
		}
		BigInteger pkt_next = nextPacket(instr);
		if (pkt_next == null) {
			// not yet analyzed
			return RefType.INVALID;
		}

		AddressSet addrSet = new AddressSet(
				program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_start.longValue()),
				program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_next.longValue() - 1));
		InstructionIterator insnIter = program.getListing().getInstructions(addrSet, true);

		FlowType ret = RefType.FALL_THROUGH;
		while (insnIter.hasNext()) {
			Instruction inst = insnIter.next();
			if (inst.getFlowType() != RefType.FALL_THROUGH) {
				if (ret != RefType.FALL_THROUGH) {
					// More than one flow type results in RefType.FLOW
					// TODO: is this right? SimpleBlockModel says to return FlowType.UNKNOWN but it
					// no longer (?) exists
					return RefType.FLOW;
				}
				ret = inst.getFlowType();
			}
		}
		return ret;
	}

}

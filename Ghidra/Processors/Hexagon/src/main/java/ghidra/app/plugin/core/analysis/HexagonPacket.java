package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

public class HexagonPacket {

	Program program;
	HexagonAnalysisState state;
	boolean dirty;

	Register pktStartRegister;
	Register pktNextRegister;

	AddressSet addrSet;

	HexagonPacket(Program program, HexagonAnalysisState state) {
		this.program = program;
		this.state = state;
		this.addrSet = new AddressSet();
		this.dirty = false;

		pktStartRegister = program.getProgramContext().getRegister("pkt_start");
		pktNextRegister = program.getProgramContext().getRegister("pkt_next");
	}

	boolean isTerminated() {
		int curValue = state.getParseBits(getMaxAddress());
		return curValue == 0b00 || curValue == 0b11;
	}

	public void addInstructionToEndOfPacket(Instruction instr) {
		if (this.addrSet.getNumAddresses() > 0) {
			if (isTerminated()) {
				throw new IllegalArgumentException("Instruction appended to already-terminated packet");
			}
			if (!getMaxAddress().add(4).equals(instr.getMinAddress())) {
				throw new IllegalArgumentException("Instruction appended to packet is not immediately after packet");
			}
		}
		dirty = true;
		addrSet.add(instr.getMinAddress());
	}

	public void addInstructionToBegOfPacket(Instruction instr) {
		if (this.addrSet.getNumAddresses() > 0) {
			if (!getMinAddress().subtract(4).equals(instr.getMaxAddress())) {
				throw new IllegalArgumentException("Instruction prepended to packet is not immediately before packet");
			}
		}
		dirty = true;
		addrSet.add(instr.getMinAddress());
	}

	Address getMinAddress() {
		return addrSet.getMinAddress();
	}

	Address getMaxAddress() {
		return addrSet.getMaxAddress();
	}

	boolean containsAddress(Address address) {
		return addrSet.contains(address);
	}

	boolean hasEndLoop() {
		throw new NotYetImplementedException("NYI");
	}

	int getEndLoop() {
		throw new NotYetImplementedException("NYI");
	}
	
	void setFallthrough() {
		boolean terminated = isTerminated();
		
		Address addr = getMinAddress();
		
		//
		// If the packet is terminated, then set fallthrough for all but the
		// last instruction in the packet
		//
		// This is required by ParallelInstructionLanguageHelper
		//
		// However, if the packet isn't terminated, we want to set fallthrough
		// for the last instruction as well
		//
		Address stop = getMaxAddress();
		if (!terminated) {
			stop = stop.add(4);
		}
		
		while (!addr.equals(stop)) {
			Instruction instr = program.getListing().getInstructionAt(addr);
			addr = addr.add(4);
			instr.setFallThrough(addr);
		}

		// TODO: for terminated packets analyze pcode and determine whether the
		// last packet should fall through
		
	}

	void redoPacket(TaskMonitor monitor) {
		if (addrSet.getNumAddresses() == 0) {
			throw new IllegalArgumentException("No instructions in packet");
		}

		if (!isTerminated()) {
			throw new IllegalArgumentException("Packet is not terminated");
		}

		if (!dirty) {
			return;
		}

		program.getListing().clearCodeUnits(getMinAddress(), getMaxAddress(), false);

		BigInteger pktStart = BigInteger.valueOf(getMinAddress().getOffset());
		BigInteger pktNext = BigInteger.valueOf(getMaxAddress().add(4).getOffset());
		try {
			program.getProgramContext().setValue(pktStartRegister, getMinAddress(), getMaxAddress(), pktStart);
			program.getProgramContext().setValue(pktNextRegister, getMinAddress(), getMaxAddress(), pktNext);
		} catch (ContextChangeException e) {
			Msg.error(this, "Unexpected Exception", e);
		}

		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		dis.disassemble(addrSet, addrSet, false);
		
		setFallthrough();

		dirty = false;
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{ ");
		AddressIterator iter = addrSet.getAddresses(true);
		while (iter.hasNext()) {
			Instruction instr = program.getListing().getInstructionAt(iter.next());
			sb.append(instr.toString());
			if (iter.hasNext()) {
				sb.append(" ; ");
			}
		}
		sb.append(" } @ ");
		sb.append(addrSet.getMinAddress().toString());
		return sb.toString();
	}
}

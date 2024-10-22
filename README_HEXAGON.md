## Ghidra Hexagon

Original fork branched from 10.2 at 436bb4873e8571b87a4d785bb828d9bf772b4867
We are on 10.4, producing identical pcode and dissassembly (within reason)

### Building
```shell
nix develop -c ./build-nix.sh
```
results in ./build/dist/ghidra_10.4_DEV_*.zip


changes are:
Ghidra/Processors/Hexagon added


/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/disassemble/Disassembler.java - done
/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileCallback.java - done
/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/block/BasicBlockModel.java - done
/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/block/SimpleBlockModel.java - done
/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/block/SimpleDestReferenceIterator.java - done
/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/lang/ParallelInstructionLanguageHelper.java - no change, use reflection
/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Features/FunctionGraph/src/main/java/ghidra/app/plugin/core/functiongraph/mvc/FGController.java: - done
					else if (fieldFactory.getFieldName().equals("Parallel ||")) {
						fieldFactory.setWidth(37);
						formatModel.updateRow(row);
					}

/home/cub3d/Desktop/new-ghid-hex/ghidra-plugin-hexagon/Ghidra/Features/Base/src/main/java/ghidra/program/database/ProgramBuilder.java - not in 10.4?

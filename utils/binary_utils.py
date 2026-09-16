from __future__ import annotations

import logging
import os
import subprocess
from typing import Optional, Dict, List, Any

l = logging.getLogger(__name__)

# Default source directories for OP-TEE TAs
DEFAULT_SOURCE_DIRS = [
    "/images/projects/internships/sym-exec-optee-2025/angr-trustzone/linaro_toolchain/optee_os",
    "/images/projects/internships/sym-exec-optee-2025/angr-trustzone/linaro_toolchain/optee_ftpm",
    "/images/projects/internships/sym-exec-optee-2025/angr-trustzone/linaro_toolchain/ms-tpm-20-ref"
]


def get_default_source_dirs() -> List[str]:
    """
    Get the default source directories for OP-TEE TA source code.
    
    Returns:
        List of directory paths to search for source code
    """
    return DEFAULT_SOURCE_DIRS.copy()


def extract_function_source(
    function_name: str,
    source_dirs: List[str] = None,
    timeout: int = 5,
    max_function_lines: int = 500
) -> Optional[Dict[str, Any]]:
    """
    Extract the complete source code of a C function from source directories.
    
    Searches for the function definition using grep, then extracts the complete
    function body by tracking braces.
    
    Args:
        function_name: Name of the function to find
        source_dirs: List of directories to search (defaults to DEFAULT_SOURCE_DIRS)
        timeout: Timeout in seconds for grep search
        max_function_lines: Maximum lines to extract for a single function
        
    Returns:
        Dict with keys:
        - 'file_path': Path to the source file
        - 'source_code': Complete function source code
        - 'start_line': Starting line number (1-indexed)
        - 'end_line': Ending line number (1-indexed)
        - 'line_count': Number of lines in the function
        
        Returns None if function not found
    """
    if not function_name or function_name == "<unknown>":
        return None
    
    if source_dirs is None:
        source_dirs = DEFAULT_SOURCE_DIRS
    
    for source_dir in source_dirs:
        if not os.path.exists(source_dir):
            continue
        
        try:
            # Search for function definition in C/H files
            # Use --include to only search C/H files and -m to limit matches
            result = subprocess.run(
                ['grep', '-rn', '--include=*.c', '--include=*.h', '-m', '5',
                 f'{function_name}(', source_dir],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 3:
                            file_path = parts[0]
                            try:
                                start_line_num = int(parts[1])
                            except ValueError:
                                continue
                            
                            # Read the file and extract the complete function
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    file_lines = f.readlines()
                                
                                # Find the function definition line
                                func_start = start_line_num - 1  # Convert to 0-indexed
                                
                                # Bounds check
                                if func_start < 0 or func_start >= len(file_lines):
                                    continue
                                
                                # Look backwards for function attributes/decorators
                                while func_start > 0 and (
                                    file_lines[func_start - 1].strip().startswith('__') or 
                                    file_lines[func_start - 1].strip().startswith('static') or
                                    file_lines[func_start - 1].strip().startswith('inline')
                                ):
                                    func_start -= 1
                                
                                # Find the end of the function by tracking braces
                                brace_count = 0
                                func_end = func_start
                                started = False
                                
                                for i in range(func_start, min(len(file_lines), func_start + max_function_lines)):
                                    line = file_lines[i]
                                    
                                    # Count braces
                                    for char in line:
                                        if char == '{':
                                            brace_count += 1
                                            started = True
                                        elif char == '}':
                                            brace_count -= 1
                                    
                                    func_end = i
                                    
                                    # If we've closed all braces after starting, we're done
                                    if started and brace_count == 0:
                                        break
                                
                                # Extract the complete function
                                function_lines = file_lines[func_start:func_end + 1]
                                source_code = ''.join(function_lines)
                                
                                return {
                                    'file_path': file_path,
                                    'source_code': source_code,
                                    'start_line': func_start + 1,  # Convert back to 1-indexed
                                    'end_line': func_end + 1,
                                    'line_count': len(function_lines)
                                }
                                
                            except Exception as e:
                                l.warning(f"[binary_utils] Error reading file {file_path}: {e}")
                                continue
                                
        except subprocess.TimeoutExpired:
            l.debug(f"[binary_utils] Timeout searching for {function_name} in {source_dir}")
        except Exception as e:
            l.warning(f"[binary_utils] Error searching for {function_name}: {e}")
    
    return None


def extract_function_assembly(
    project,
    function_addr: int,
    mem_base: int = 0
) -> Optional[Dict[str, Any]]:
    """
    Extract assembly code for a function from an angr project.
    
    Args:
        project: The angr project
        function_addr: Address of the function
        mem_base: Base address for memory (default 0 for TAs)
        
    Returns:
        Dict with keys:
        - 'function_address': Hex address of the function
        - 'function_offset': Hex offset from mem_base
        - 'num_blocks': Number of basic blocks
        - 'num_instructions': Total number of instructions
        - 'instructions': List of instruction dicts with:
            - 'address': Hex address
            - 'offset': Hex offset from mem_base
            - 'mnemonic': Instruction mnemonic
            - 'op_str': Operand string
            - 'bytes': Hex bytes
            - 'size': Instruction size
            - 'full_insn': Complete instruction string
            
        Returns None if function not found or error occurs
    """
    try:
        # Get the function from the knowledge base
        function = project.kb.functions.get(function_addr)
        if not function:
            l.warning(f"[binary_utils] Function at {hex(function_addr)} not found in knowledge base")
            return None
        
        assembly_lines = []
        
        # Iterate through all blocks in the function
        for block_addr in sorted(function.block_addrs):
            try:
                # Get the block
                block = project.factory.block(block_addr)
                
                # Get disassembly
                for insn in block.capstone.insns:
                    assembly_lines.append({
                        'address': hex(insn.address),
                        'offset': hex(insn.address - mem_base),
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'bytes': insn.bytes.hex(),
                        'size': insn.size,
                        'full_insn': f"{insn.mnemonic} {insn.op_str}"
                    })
            except Exception as e:
                l.warning(f"[binary_utils] Error disassembling block at {hex(block_addr)}: {e}")
                continue
        
        return {
            'function_address': hex(function_addr),
            'function_offset': hex(function_addr - mem_base),
            'num_blocks': len(function.block_addrs),
            'num_instructions': len(assembly_lines),
            'instructions': assembly_lines
        }
        
    except Exception as e:
        l.warning(f"[binary_utils] Error extracting assembly for function at {hex(function_addr)}: {e}")
        return None


def extract_block_assembly(
    project,
    block_addr: int,
    mem_base: int = 0
) -> Optional[Dict[str, Any]]:
    """
    Extract assembly code for a single basic block.
    
    This is a fallback when the full function cannot be found.
    
    Args:
        project: The angr project
        block_addr: Address of the block
        mem_base: Base address for memory (default 0 for TAs)
        
    Returns:
        Dict with keys:
        - 'block_address': Hex address of the block
        - 'block_offset': Hex offset from mem_base
        - 'num_instructions': Number of instructions
        - 'instructions': List of instruction dicts (same format as extract_function_assembly)
        
        Returns None if block not found or error occurs
    """
    try:
        block = project.factory.block(block_addr)
        assembly_lines = []
        
        for insn in block.capstone.insns:
            assembly_lines.append({
                'address': hex(insn.address),
                'offset': hex(insn.address - mem_base),
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': insn.bytes.hex(),
                'size': insn.size,
                'full_insn': f"{insn.mnemonic} {insn.op_str}"
            })
        
        return {
            'block_address': hex(block_addr),
            'block_offset': hex(block_addr - mem_base),
            'num_instructions': len(assembly_lines),
            'instructions': assembly_lines
        }
        
    except Exception as e:
        l.warning(f"[binary_utils] Error disassembling block at {hex(block_addr)}: {e}")
        return None


def resolve_function_name(
    binary_path: str,
    address: int,
    mem_base: int = 0
) -> Optional[str]:
    """
    Resolve an address to a function name using symbol information.
    
    Args:
        binary_path: Path to the binary file
        address: Address to resolve (loaded address, will be adjusted by mem_base)
        mem_base: Base address where binary is loaded (default 0 for TAs)
        
    Returns:
        Function name if found, None otherwise
    """
    from reporting.symbol_resolver import get_symbol_resolver
    
    resolver = get_symbol_resolver(binary_path)
    if not resolver:
        return None
    
    # Convert from loaded address to binary offset
    offset = address - mem_base
    return resolver.resolve_address(offset)


def get_function_at_address(project, address: int):
    """
    Get the function object containing a given address.
    
    Args:
        project: The angr project
        address: Address to look up
        
    Returns:
        angr Function object or None if not found
    """
    try:
        return project.kb.functions.floor_func(address)
    except Exception:
        return None


import angr
import os
from typing import Type, Dict

from utils.logging_config import get_logger

logger = get_logger(__name__)

# Global registry of OS hook classes
# Maps OS name (lowercase) -> OS hook class (SimProcedure subclass)
OS_HOOKS_REGISTRY: Dict[str, Type] = {}


def os_hook(name: str):
    """
    Decorator to register a class as an OS hook handler.
    
    Classes decorated with @os_hook(name) will be added to the global
    OS_HOOKS_REGISTRY and can be used during SVC instruction handling.
    
    The decorated class should be a SimProcedure subclass that implements
    the `run` method to handle syscalls for that OS.
    
    Example:
        @os_hook("optee")
        class OPTEEHooks(SimProcedure):
            def run(self, _argc, _argv):
                # Handle OP-TEE syscalls
                ...
    
    Args:
        name: The OS name to register (e.g., "optee", "trusty")
        
    Returns:
        Decorator function that registers the class
    """
    def decorator(cls: Type) -> Type:
        OS_HOOKS_REGISTRY[name.lower()] = cls
        return cls
    return decorator


def install_os_hooks(project: angr.Project, binary_path: str, os_hook_name: str):
    """
    Install the OS hooks for syscalls into the angr project.
    
    Args:
        project: The angr project to install the hooks into
        binary_path: The path to the binary being analyzed
        os_hook_name: The name of the OS to install hooks from
    """
    os_hook_name_lower = os_hook_name.lower()
    
    if os_hook_name_lower not in OS_HOOKS_REGISTRY:
        available = ', '.join(OS_HOOKS_REGISTRY.keys()) if OS_HOOKS_REGISTRY else 'none'
        raise ValueError(
            f"Invalid OS hook name: {os_hook_name}. "
            f"Available: {available}"
        )

    logger.info(f"Using {os_hook_name} hooks")
    os_hook_class = OS_HOOKS_REGISTRY[os_hook_name_lower]

    svc_addrs = []
    
    # Check if we have a .ta file (ELF format)
    if binary_path.endswith(".ta") or binary_path.endswith(".elf"):
        # For ELF files, read segments from the file and scan for SVC instructions
        logger.debug("Detected ELF file, scanning loaded sections for SVC instructions")
        cs = project.arch.capstone
        
        # Get all loaded segments/sections from the main object
        main_object = project.loader.main_object
        
        with open(binary_path, "rb") as elf_file:
            for segment in main_object.segments:
                # Only scan executable segments
                if segment.is_executable and segment.filesize > 0:
                    try:
                        # Read the segment data from file using file offset
                        elf_file.seek(segment.offset)
                        segment_data = elf_file.read(segment.filesize)
                        
                        # Disassemble at the segment's virtual address
                        for insn in cs.disasm(segment_data, segment.vaddr):
                            if insn.mnemonic.lower().startswith("svc"):
                                svc_addrs.append(insn.address)
                    except Exception as e:
                        logger.debug(f"Error scanning segment at {hex(segment.vaddr)}: {e}")
                        continue
    else:
        # For raw binary files, read and disassemble directly
        logger.debug("Detected raw binary file, scanning for SVC instructions")
        with open(binary_path, "rb") as blob:
            cs = project.arch.capstone
            binary = blob.read()
            for insn in cs.disasm(binary, 0x0):
                if insn.mnemonic.lower().startswith("svc"):
                    svc_addrs.append(insn.address)

    # Remove duplicates and sort
    svc_addrs = sorted(set(svc_addrs))

    for svc_addr in svc_addrs:
        logger.info(f"Adding OS hook at {hex(svc_addr)}")
        project.hook(svc_addr, os_hook_class(), 4)
    
    logger.info(f"Installed {len(svc_addrs)} OS hooks")


# Import built-in OS hooks to trigger their registration
# This must be at the end of the file to avoid circular imports
from . import optee_hooks

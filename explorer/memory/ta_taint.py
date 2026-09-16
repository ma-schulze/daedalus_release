import angr
import claripy
from claripy.annotation import UninitializedAnnotation

class TA_Trusted_Annotation(claripy.Annotation):
    """
    Taint annotation for memory originating from a trusted source.
    This may for example include memory retrieved from a system call.
    These annotations may be used by analysis plugins to detect bugs in the TA.
    """
    name = "None"

    def set_name(self, name: str):
        """
        Set the name of the annotation.

        Args:
            name: The name of the annotation
        """
        self.name = name

    def __str__(self):
        """
        Return a string representation of the annotation.

        Returns:
            A string representation of the annotation
        """
        return f'TA_Trusted_Annotation<{self.name}>'

    def eliminatable(self):  
        """
        Whether the annotation can be eliminated.
        We must always propagate these annotations, so they cannot be eliminated.

        Returns:
            False
        """
        return False  

    @property
    def relocatable(self):  
        """
        Whether the annotation can be relocated.
        We must always propagate these annotations, so they can be relocated.

        Returns:
            True
        """
        return True

    def relocate(self, src: claripy.ast.base.Base, dst: claripy.ast.base.Base):  
        """
        Relocate the annotation from the source to the destination. 
        If the src contains a TA_Trusted_Annotation, we will copy it to the dst.

        Args:
            src: The source expression of the annotation
            dst: The destination expression of the annotation

        Returns:
            The new annotation

        """
        if any(isinstance(a, TA_Trusted_Annotation) for a in src.annotations):
            new_annotation = self
            if any(isinstance(a, TA_Trusted_Annotation) for a in dst.annotations):
                new_annotation = None
        else:
            raise ValueError(f'Relocating TA_Trusted_Annotation annotation not in src {src.annotations}')

        return new_annotation


class TA_Taint_Annotation(claripy.Annotation):
    """
    Taint annotation for memory originating from an attacker.
    This may for example include memory read from the NW.
    These annotations may be used by analysis plugins to detect bugs in the TA.
    """
    name = "None"

    def set_name(self, name: str):
        """
        Set the name of the annotation.

        Args:
            name: The name of the annotation
        """
        self.name = name

    def __str__(self):
        """
        Return a string representation of the annotation.

        Returns:
            A string representation of the annotation
        """
        return f'TA_Taint_Annotation<{self.name}>'

    def eliminatable(self):  
        """
        Whether the annotation can be eliminated.
        We must always propagate these annotations, so they cannot be eliminated.

        Returns:
            False
        """
        return False  

    @property
    def relocatable(self):  
        """
        Whether the annotation can be relocated.
        We must always propagate these annotations, so they can be relocated.

        Returns:
            True
        """
        return True

    def relocate(self, src: claripy.ast.base.Base, dst: claripy.ast.base.Base):  
        """
        Relocate the annotation from the source to the destination.
        If the src contains a TA_Taint_Annotation, we will copy it to the dst.

        Args:
            src: The source expression of the annotation
            dst: The destination expression of the annotation

        Returns:
            The new annotation
        """
        if any(isinstance(a, TA_Taint_Annotation) for a in src.annotations):
            new_annotation = self
            if any(isinstance(a, TA_Taint_Annotation) for a in dst.annotations):
                new_annotation = None
        else:
            raise ValueError(f'Relocating TA_Taint_Annotation annotation not in src {src.annotations}')

        return new_annotation


def get_trusted_mem_bits(state: angr.SimState, size: int, annotations: list[claripy.Annotation] = None) -> claripy.BVS:
    """
    Get the trusted memory bits.

    Args:
        state: The state of the analysis
        size: The size of the memory
        annotations: The annotations to add to the memory
    
    Returns:
        A symbolic variable representing the trusted memory bits with the given size and annotations
    """
    trusted_taint = TA_Trusted_Annotation()
    trusted_taint.set_name('trusted_memory')
    if annotations:
        annotations.append(trusted_taint)
    else:
        annotations = [trusted_taint]

    annotations.append(UninitializedAnnotation())
    return claripy.BVS('trusted_mem', size,
                            annotations=annotations)

def get_tainted_mem_bits(state: angr.SimState, size: int, annotations: list[claripy.Annotation] = None, name: str = 'attacker_mem') -> claripy.BVS:
    """
    Get the tainted memory bits.

    Args:
        state: The state of the analysis
        size: The size of the memory
        annotations: The annotations to add to the memory
    
    Returns:
        A symbolic variable representing the tainted memory bits with the given size and annotations
    """
    attacker_taint = TA_Taint_Annotation()
    attacker_taint.set_name('memory')
    if annotations:
        annotations.append(attacker_taint)
    else:
        annotations = [attacker_taint]

    annotations.append(UninitializedAnnotation())
    return claripy.BVS(name, size,
                            annotations=annotations)


def add_taint(bvv: claripy.BVV) -> claripy.BVV:
    """
    Add a taint annotation to a bitvector.

    Args:
        bvv: The bitvector to add the annotation to

    Returns:
        The bitvector with the annotation added
    """
    return bvv.append_annotation(TA_Taint_Annotation())

def is_trusted(expr: claripy.ast.base.Base) -> bool:
    """
    Check if a bitvector is trusted.

    Args:
        expr: The bitvector to check

    Returns:
        True if trusted, False if not
    """
    if type(expr) is int:
        return False
    elif _has_taint_annotation(expr, TA_Trusted_Annotation):
        return True

    return False

def is_tainted(expr: claripy.ast.base.Base) -> bool:
    """
    Check if a bitvector is tainted.

    Args:
        expr: The bitvector to check

    Returns:
        True if tainted, False if not
    """
    if type(expr) is int:
        return False
    elif _has_taint_annotation(expr, TA_Taint_Annotation):
        return True

    return False


def _has_taint_annotation(expr: claripy.ast.base.Base, taint: claripy.Annotation) -> bool:
    """
    Check if a bitvector has a taint annotation.

    Args:
        expr: The bitvector to check
        taint: The taint annotation to check for

    Returns:
        True if the bitvector has the taint annotation, False if not
    """
    return _is_immediately_tainted(expr, taint) or any(_is_immediately_tainted(v, taint) for v in expr.leaf_asts())


def _is_immediately_tainted(ast: claripy.ast.base.Base, taint: claripy.Annotation) -> bool:
    """
    Check if a bitvector is immediately tainted.

    Args:
        ast: The bitvector to check
        taint: The taint annotation to check for

    Returns:
        True if the bitvector is immediately tainted, False if not
    """
    if ast is None:
        return False
    else:
        return any(isinstance(a, taint) for a in ast.annotations)

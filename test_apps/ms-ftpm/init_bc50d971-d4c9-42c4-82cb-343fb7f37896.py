from test_apps.utils import place_sym_value_param, init_params
import angr
import claripy
import time
from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.hooks.function_hooks.func_hooks import ta_function_hook


@ta_function_hook("GetClosestCommandIndex", "ftpm")
class get_closest_command_index_symbolic(angr.SimProcedure):
    """
    Symbolic implementation of the GetClosestCommandIndex function as an angr SimProcedure.
    
    This function returns an index into the command table (s_commandAttributes).
    The mapping was extracted from the s_ccAttr array in the fTPM ELF binary.
    
    For unimplemented commands, returns UNIMPLEMENTED_COMMAND_INDEX (0xFFFF).
    """
    
    # Command code to array index mapping extracted from s_ccAttr @ 0x61ee0
    # Total: 116 library commands + 1 vendor command
    COMMAND_INDEX_MAP = {
        0x011F: 0,   # TPM_CC_NV_UndefineSpaceSpecial
        0x0120: 1,   # TPM_CC_EvictControl
        0x0121: 2,   # TPM_CC_HierarchyControl
        0x0122: 3,   # TPM_CC_NV_UndefineSpace
        0x0124: 4,   # TPM_CC_ChangeEPS
        0x0125: 5,   # TPM_CC_ChangePPS
        0x0126: 6,   # TPM_CC_Clear
        0x0127: 7,   # TPM_CC_ClearControl
        0x0128: 8,   # TPM_CC_ClockSet
        0x0129: 9,   # TPM_CC_HierarchyChangeAuth
        0x012A: 10,  # TPM_CC_NV_DefineSpace
        0x012B: 11,  # TPM_CC_PCR_Allocate
        0x012C: 12,  # TPM_CC_PCR_SetAuthPolicy
        0x012D: 13,  # TPM_CC_PP_Commands
        0x012E: 14,  # TPM_CC_SetPrimaryPolicy
        # 0x012F: NOT IMPLEMENTED (FieldUpgradeStart)
        0x0130: 15,  # TPM_CC_ClockRateAdjust
        0x0131: 16,  # TPM_CC_CreatePrimary
        0x0132: 17,  # TPM_CC_NV_GlobalWriteLock
        0x0133: 18,  # TPM_CC_GetCommandAuditDigest
        0x0134: 19,  # TPM_CC_NV_Increment
        0x0135: 20,  # TPM_CC_NV_SetBits
        0x0136: 21,  # TPM_CC_NV_Extend
        0x0137: 22,  # TPM_CC_NV_Write
        0x0138: 23,  # TPM_CC_NV_WriteLock
        0x0139: 24,  # TPM_CC_DictionaryAttackLockReset
        0x013A: 25,  # TPM_CC_DictionaryAttackParameters
        0x013B: 26,  # TPM_CC_NV_ChangeAuth
        0x013C: 27,  # TPM_CC_PCR_Event
        0x013D: 28,  # TPM_CC_PCR_Reset
        0x013E: 29,  # TPM_CC_SequenceComplete
        0x013F: 30,  # TPM_CC_SetAlgorithmSet
        0x0140: 31,  # TPM_CC_SetCommandCodeAuditStatus
        # 0x0141: NOT IMPLEMENTED (FieldUpgradeData)
        0x0142: 32,  # TPM_CC_IncrementalSelfTest
        0x0143: 33,  # TPM_CC_SelfTest
        0x0144: 34,  # TPM_CC_Startup
        0x0145: 35,  # TPM_CC_Shutdown
        0x0146: 36,  # TPM_CC_StirRandom
        0x0147: 37,  # TPM_CC_ActivateCredential
        0x0148: 38,  # TPM_CC_Certify
        0x0149: 39,  # TPM_CC_PolicyNV
        0x014A: 40,  # TPM_CC_CertifyCreation
        0x014B: 41,  # TPM_CC_Duplicate
        0x014C: 42,  # TPM_CC_GetTime
        0x014D: 43,  # TPM_CC_GetSessionAuditDigest
        0x014E: 44,  # TPM_CC_NV_Read
        0x014F: 45,  # TPM_CC_NV_ReadLock
        0x0150: 46,  # TPM_CC_ObjectChangeAuth
        0x0151: 47,  # TPM_CC_PolicySecret
        0x0152: 48,  # TPM_CC_Rewrap
        0x0153: 49,  # TPM_CC_Create
        0x0154: 50,  # TPM_CC_ECDH_ZGen
        0x0155: 51,  # TPM_CC_HMAC / TPM_CC_MAC
        0x0156: 52,  # TPM_CC_Import
        0x0157: 53,  # TPM_CC_Load
        0x0158: 54,  # TPM_CC_Quote
        0x0159: 55,  # TPM_CC_RSA_Decrypt
        # 0x015A: gap
        0x015B: 56,  # TPM_CC_HMAC_Start / TPM_CC_MAC_Start
        0x015C: 57,  # TPM_CC_SequenceUpdate
        0x015D: 58,  # TPM_CC_Sign
        0x015E: 59,  # TPM_CC_Unseal
        # 0x015F: gap
        0x0160: 60,  # TPM_CC_PolicySigned
        0x0161: 61,  # TPM_CC_ContextLoad
        0x0162: 62,  # TPM_CC_ContextSave
        0x0163: 63,  # TPM_CC_ECDH_KeyGen
        0x0164: 64,  # TPM_CC_EncryptDecrypt
        0x0165: 65,  # TPM_CC_FlushContext
        # 0x0166: gap
        0x0167: 66,  # TPM_CC_LoadExternal
        0x0168: 67,  # TPM_CC_MakeCredential
        0x0169: 68,  # TPM_CC_NV_ReadPublic
        0x016A: 69,  # TPM_CC_PolicyAuthorize
        0x016B: 70,  # TPM_CC_PolicyAuthValue
        0x016C: 71,  # TPM_CC_PolicyCommandCode
        0x016D: 72,  # TPM_CC_PolicyCounterTimer
        0x016E: 73,  # TPM_CC_PolicyCpHash
        0x016F: 74,  # TPM_CC_PolicyLocality
        0x0170: 75,  # TPM_CC_PolicyNameHash
        0x0171: 76,  # TPM_CC_PolicyOR
        0x0172: 77,  # TPM_CC_PolicyTicket
        0x0173: 78,  # TPM_CC_ReadPublic
        0x0174: 79,  # TPM_CC_RSA_Encrypt
        # 0x0175: gap
        0x0176: 80,  # TPM_CC_StartAuthSession
        0x0177: 81,  # TPM_CC_VerifySignature
        0x0178: 82,  # TPM_CC_ECC_Parameters
        # 0x0179: NOT IMPLEMENTED (FirmwareRead)
        0x017A: 83,  # TPM_CC_GetCapability
        0x017B: 84,  # TPM_CC_GetRandom
        0x017C: 85,  # TPM_CC_GetTestResult
        0x017D: 86,  # TPM_CC_Hash
        0x017E: 87,  # TPM_CC_PCR_Read
        0x017F: 88,  # TPM_CC_PolicyPCR
        0x0180: 89,  # TPM_CC_PolicyRestart
        0x0181: 90,  # TPM_CC_ReadClock
        0x0182: 91,  # TPM_CC_PCR_Extend
        0x0183: 92,  # TPM_CC_PCR_SetAuthValue
        0x0184: 93,  # TPM_CC_NV_Certify
        0x0185: 94,  # TPM_CC_EventSequenceComplete
        0x0186: 95,  # TPM_CC_HashSequenceStart
        0x0187: 96,  # TPM_CC_PolicyPhysicalPresence
        0x0188: 97,  # TPM_CC_PolicyDuplicationSelect
        0x0189: 98,  # TPM_CC_PolicyGetDigest
        0x018A: 99,  # TPM_CC_TestParms
        0x018B: 100, # TPM_CC_Commit
        0x018C: 101, # TPM_CC_PolicyPassword
        0x018D: 102, # TPM_CC_ZGen_2Phase
        0x018E: 103, # TPM_CC_EC_Ephemeral
        0x018F: 104, # TPM_CC_PolicyNvWritten
        0x0190: 105, # TPM_CC_PolicyTemplate
        0x0191: 106, # TPM_CC_CreateLoaded
        0x0192: 107, # TPM_CC_PolicyAuthorizeNV
        0x0193: 108, # TPM_CC_EncryptDecrypt2
        0x0194: 109, # TPM_CC_AC_GetCapability
        0x0195: 110, # TPM_CC_AC_Send
        0x0196: 111, # TPM_CC_Policy_AC_SendSelect
        0x0197: 112, # TPM_CC_CertifyX509
        0x0198: 113, # TPM_CC_ACT_SetTimeout
        0x0199: 114, # TPM_CC_ECC_Encrypt
        0x019A: 115, # TPM_CC_ECC_Decrypt
        # Vendor command
        0x20000000: 116, # TPM_CC_Vendor_TCG_Test
    }
    
    UNIMPLEMENTED_COMMAND_INDEX = 0xFFFF
    LIBRARY_COMMAND_ARRAY_SIZE = 116

    def run(self):
        state = self.state
        cmd_code = state.regs.x0
        
        # Try to get concrete value
        if state.solver.symbolic(cmd_code):
            # If symbolic, we need to handle it carefully
            # For now, just try to evaluate it
            try:
                cmd_code_val = state.solver.eval_one(cmd_code)
            except:
                # Can't determine - return UNIMPLEMENTED
                print(f"[GetClosestCommandIndex] Symbolic command code, returning UNIMPLEMENTED")
                return claripy.BVV(self.UNIMPLEMENTED_COMMAND_INDEX, 32)
        else:
            cmd_code_val = state.solver.eval(cmd_code)
        
        # Look up in the map
        if cmd_code_val in self.COMMAND_INDEX_MAP:
            index = self.COMMAND_INDEX_MAP[cmd_code_val]
            print(f"[GetClosestCommandIndex] cmd_code=0x{cmd_code_val:X} -> index={index}")
            return claripy.BVV(index, 32)
        else:
            print(f"[GetClosestCommandIndex] cmd_code=0x{cmd_code_val:X} -> UNIMPLEMENTED")
            return claripy.BVV(self.UNIMPLEMENTED_COMMAND_INDEX, 32)


@ta_function_hook("CommandCodeToCommandIndex", "ftpm")
class command_code_to_command_index_symbolic(angr.SimProcedure):
    """
    Hook for CommandCodeToCommandIndex to return the exact command index.
    
    This function maps TPM command codes to command table indices.
    Uses the same mapping as get_closest_command_index_symbolic.
    Returns UNIMPLEMENTED_COMMAND_INDEX (0xFFFF) for unknown commands.
    """
    def run(self):
        state = self.state
        cmd_code = state.regs.x0
        
        # Use the mapping from get_closest_command_index_symbolic
        COMMAND_INDEX_MAP = get_closest_command_index_symbolic.COMMAND_INDEX_MAP
        UNIMPLEMENTED = get_closest_command_index_symbolic.UNIMPLEMENTED_COMMAND_INDEX
        
        # Try to get concrete value
        if state.solver.symbolic(cmd_code):
            try:
                cmd_code_val = state.solver.eval_one(cmd_code)
            except:
                print(f"[CommandCodeToCommandIndex] Symbolic command code, returning UNIMPLEMENTED")
                return claripy.BVV(UNIMPLEMENTED, 32)
        else:
            cmd_code_val = state.solver.eval(cmd_code)
        
        # Look up in the map
        if cmd_code_val in COMMAND_INDEX_MAP:
            index = COMMAND_INDEX_MAP[cmd_code_val]
            print(f"[CommandCodeToCommandIndex] cmd_code=0x{cmd_code_val:X} -> index={index}")
            return claripy.BVV(index, 32)
        else:
            print(f"[CommandCodeToCommandIndex] cmd_code=0x{cmd_code_val:X} -> UNIMPLEMENTED")
            return claripy.BVV(UNIMPLEMENTED, 32)



########################################################
# Input Commands 
########################################################
"""
#define TPM_CC_NV_UndefineSpaceSpecial      (TPM_CC)(0x0000011F)
#define TPM_CC_EvictControl                 (TPM_CC)(0x00000120)
#define TPM_CC_HierarchyControl             (TPM_CC)(0x00000121)
#define TPM_CC_NV_UndefineSpace             (TPM_CC)(0x00000122)
#define TPM_CC_ChangeEPS                    (TPM_CC)(0x00000124)
#define TPM_CC_ChangePPS                    (TPM_CC)(0x00000125)
#define TPM_CC_Clear                        (TPM_CC)(0x00000126)
#define TPM_CC_ClearControl                 (TPM_CC)(0x00000127)
#define TPM_CC_ClockSet                     (TPM_CC)(0x00000128)
#define TPM_CC_HierarchyChangeAuth          (TPM_CC)(0x00000129)
#define TPM_CC_NV_DefineSpace               (TPM_CC)(0x0000012A)
#define TPM_CC_PCR_Allocate                 (TPM_CC)(0x0000012B)
#define TPM_CC_PCR_SetAuthPolicy            (TPM_CC)(0x0000012C)
#define TPM_CC_PP_Commands                  (TPM_CC)(0x0000012D)
#define TPM_CC_SetPrimaryPolicy             (TPM_CC)(0x0000012E)
#define TPM_CC_FieldUpgradeStart            (TPM_CC)(0x0000012F)
#define TPM_CC_ClockRateAdjust              (TPM_CC)(0x00000130)
#define TPM_CC_CreatePrimary                (TPM_CC)(0x00000131)
#define TPM_CC_NV_GlobalWriteLock           (TPM_CC)(0x00000132)
#define TPM_CC_GetCommandAuditDigest        (TPM_CC)(0x00000133)
#define TPM_CC_NV_Increment                 (TPM_CC)(0x00000134)
#define TPM_CC_NV_SetBits                   (TPM_CC)(0x00000135)
#define TPM_CC_NV_Extend                    (TPM_CC)(0x00000136)
#define TPM_CC_NV_Write                     (TPM_CC)(0x00000137)
#define TPM_CC_NV_WriteLock                 (TPM_CC)(0x00000138)
#define TPM_CC_DictionaryAttackLockReset    (TPM_CC)(0x00000139)
#define TPM_CC_DictionaryAttackParameters   (TPM_CC)(0x0000013A)
#define TPM_CC_NV_ChangeAuth                (TPM_CC)(0x0000013B)
#define TPM_CC_PCR_Event                    (TPM_CC)(0x0000013C)
#define TPM_CC_PCR_Reset                    (TPM_CC)(0x0000013D)
#define TPM_CC_SequenceComplete             (TPM_CC)(0x0000013E)
#define TPM_CC_SetAlgorithmSet              (TPM_CC)(0x0000013F)
#define TPM_CC_SetCommandCodeAuditStatus    (TPM_CC)(0x00000140)
#define TPM_CC_FieldUpgradeData             (TPM_CC)(0x00000141)
#define TPM_CC_IncrementalSelfTest          (TPM_CC)(0x00000142)
#define TPM_CC_SelfTest                     (TPM_CC)(0x00000143)
#define TPM_CC_Startup                      (TPM_CC)(0x00000144)
#define TPM_CC_Shutdown                     (TPM_CC)(0x00000145)
#define TPM_CC_StirRandom                   (TPM_CC)(0x00000146)
#define TPM_CC_ActivateCredential           (TPM_CC)(0x00000147)
#define TPM_CC_Certify                      (TPM_CC)(0x00000148)
#define TPM_CC_PolicyNV                     (TPM_CC)(0x00000149)
#define TPM_CC_CertifyCreation              (TPM_CC)(0x0000014A)
#define TPM_CC_Duplicate                    (TPM_CC)(0x0000014B)
#define TPM_CC_GetTime                      (TPM_CC)(0x0000014C)
#define TPM_CC_GetSessionAuditDigest        (TPM_CC)(0x0000014D)
#define TPM_CC_NV_Read                      (TPM_CC)(0x0000014E)
#define TPM_CC_NV_ReadLock                  (TPM_CC)(0x0000014F)
#define TPM_CC_ObjectChangeAuth             (TPM_CC)(0x00000150)
#define TPM_CC_PolicySecret                 (TPM_CC)(0x00000151)
#define TPM_CC_Rewrap                       (TPM_CC)(0x00000152)
#define TPM_CC_Create                       (TPM_CC)(0x00000153)
#define TPM_CC_ECDH_ZGen                    (TPM_CC)(0x00000154)
#define TPM_CC_HMAC                         (TPM_CC)(0x00000155)
#define TPM_CC_MAC                          (TPM_CC)(0x00000155)
#define TPM_CC_Import                       (TPM_CC)(0x00000156)
#define TPM_CC_Load                         (TPM_CC)(0x00000157)
#define TPM_CC_Quote                        (TPM_CC)(0x00000158)
#define TPM_CC_RSA_Decrypt                  (TPM_CC)(0x00000159)
#define TPM_CC_HMAC_Start                   (TPM_CC)(0x0000015B)
#define TPM_CC_MAC_Start                    (TPM_CC)(0x0000015B)
#define TPM_CC_SequenceUpdate               (TPM_CC)(0x0000015C)
#define TPM_CC_Sign                         (TPM_CC)(0x0000015D)
#define TPM_CC_Unseal                       (TPM_CC)(0x0000015E)
#define TPM_CC_PolicySigned                 (TPM_CC)(0x00000160)
#define TPM_CC_ContextLoad                  (TPM_CC)(0x00000161)
#define TPM_CC_ContextSave                  (TPM_CC)(0x00000162)
#define TPM_CC_ECDH_KeyGen                  (TPM_CC)(0x00000163)
#define TPM_CC_EncryptDecrypt               (TPM_CC)(0x00000164)
#define TPM_CC_FlushContext                 (TPM_CC)(0x00000165)
#define TPM_CC_LoadExternal                 (TPM_CC)(0x00000167)
#define TPM_CC_MakeCredential               (TPM_CC)(0x00000168)
#define TPM_CC_NV_ReadPublic                (TPM_CC)(0x00000169)
#define TPM_CC_PolicyAuthorize              (TPM_CC)(0x0000016A)
#define TPM_CC_PolicyAuthValue              (TPM_CC)(0x0000016B)
#define TPM_CC_PolicyCommandCode            (TPM_CC)(0x0000016C)
#define TPM_CC_PolicyCounterTimer           (TPM_CC)(0x0000016D)
#define TPM_CC_PolicyCpHash                 (TPM_CC)(0x0000016E)
#define TPM_CC_PolicyLocality               (TPM_CC)(0x0000016F)
#define TPM_CC_PolicyNameHash               (TPM_CC)(0x00000170)
#define TPM_CC_PolicyOR                     (TPM_CC)(0x00000171)
#define TPM_CC_PolicyTicket                 (TPM_CC)(0x00000172)
#define TPM_CC_ReadPublic                   (TPM_CC)(0x00000173)
#define TPM_CC_RSA_Encrypt                  (TPM_CC)(0x00000174)
#define TPM_CC_StartAuthSession             (TPM_CC)(0x00000176)
#define TPM_CC_VerifySignature              (TPM_CC)(0x00000177)
#define TPM_CC_ECC_Parameters               (TPM_CC)(0x00000178)
#define TPM_CC_FirmwareRead                 (TPM_CC)(0x00000179)
#define TPM_CC_GetCapability                (TPM_CC)(0x0000017A)
#define TPM_CC_GetRandom                    (TPM_CC)(0x0000017B)
#define TPM_CC_GetTestResult                (TPM_CC)(0x0000017C)
#define TPM_CC_Hash                         (TPM_CC)(0x0000017D)
#define TPM_CC_PCR_Read                     (TPM_CC)(0x0000017E)
#define TPM_CC_PolicyPCR                    (TPM_CC)(0x0000017F)
#define TPM_CC_PolicyRestart                (TPM_CC)(0x00000180)
#define TPM_CC_ReadClock                    (TPM_CC)(0x00000181)
#define TPM_CC_PCR_Extend                   (TPM_CC)(0x00000182)
#define TPM_CC_PCR_SetAuthValue             (TPM_CC)(0x00000183)
#define TPM_CC_NV_Certify                   (TPM_CC)(0x00000184)
#define TPM_CC_EventSequenceComplete        (TPM_CC)(0x00000185)
#define TPM_CC_HashSequenceStart            (TPM_CC)(0x00000186)
#define TPM_CC_PolicyPhysicalPresence       (TPM_CC)(0x00000187)
#define TPM_CC_PolicyDuplicationSelect      (TPM_CC)(0x00000188)
#define TPM_CC_PolicyGetDigest              (TPM_CC)(0x00000189)
#define TPM_CC_TestParms                    (TPM_CC)(0x0000018A)
#define TPM_CC_Commit                       (TPM_CC)(0x0000018B)
#define TPM_CC_PolicyPassword               (TPM_CC)(0x0000018C)
#define TPM_CC_ZGen_2Phase                  (TPM_CC)(0x0000018D)
#define TPM_CC_EC_Ephemeral                 (TPM_CC)(0x0000018E)
#define TPM_CC_PolicyNvWritten              (TPM_CC)(0x0000018F)
#define TPM_CC_PolicyTemplate               (TPM_CC)(0x00000190)
#define TPM_CC_CreateLoaded                 (TPM_CC)(0x00000191)
#define TPM_CC_PolicyAuthorizeNV            (TPM_CC)(0x00000192)
#define TPM_CC_EncryptDecrypt2              (TPM_CC)(0x00000193)
#define TPM_CC_AC_GetCapability             (TPM_CC)(0x00000194)
#define TPM_CC_AC_Send                      (TPM_CC)(0x00000195)
#define TPM_CC_Policy_AC_SendSelect         (TPM_CC)(0x00000196)
#define TPM_CC_CertifyX509                  (TPM_CC)(0x00000197)
#define TPM_CC_ACT_SetTimeout               (TPM_CC)(0x00000198)
#define TPM_CC_ECC_Encrypt                  (TPM_CC)(0x00000199)
#define TPM_CC_ECC_Decrypt                  (TPM_CC)(0x0000019A)
#define CC_VEND                             0x20000000
#define TPM_CC_Vendor_TCG_Test              (TPM_CC)(0x20000000)
"""



def _generic_tpm_command_inputs(state: angr.SimState, command_code: int):
    state.regs.x0 = get_tainted_mem_bits(state, 64)  # session_id, unused
    state.regs.x1 = claripy.BVV(0, 64)  # command_id; TA_FTPM_SUBMIT_COMMAND
    state.regs.x2 = claripy.BVV(0x75, 64)  # Param_types
    params = state.heap.allocate(64)
    state.regs.x3 = params

    # TPM commands use big-endian (network byte order) for all multi-byte fields
    BE = 'Iend_BE'

    p1_sym_ptr = state.heap.allocate(64)
    p1_sym_size = get_tainted_mem_bits(state, 64)
    state.solver.add(p1_sym_size < 64)
    # TPMI_ST_COMMAND_TAG: TPM_ST_NO_SESSIONS (0x8001) or TPM_ST_SESSIONS (0x8002)
    tag = get_tainted_mem_bits(state, 16)
    state.solver.add(claripy.Or(tag == 0x8001, tag == 0x8002))
    state.memory.store(p1_sym_ptr, tag, size=2, endness=BE) 
    # UINT32 commandSize -> Symbolic 
    command_size = get_tainted_mem_bits(state, 32)  
    state.memory.store(p1_sym_ptr + 2, command_size, size=4, endness=BE)   
    # TPM_CC commandCode
    command_code = claripy.BVV(command_code, 32)
    state.memory.store(p1_sym_ptr + 6, command_code, size=4, endness=BE) 
    # Fill arguments 
    p1_args = get_tainted_mem_bits(state, 54*8) 
    state.memory.store(p1_sym_ptr + 10, p1_args, size=64 - 10, endness=state.arch.memory_endness)

    p2_sym_ptr = state.heap.allocate(64)
    p2_sym_size = get_tainted_mem_bits(state, 64)
    state.solver.add(p2_sym_size < 64)
    p2_sym_val = get_tainted_mem_bits(state, 64 * 8)
    
    p3_sym_ptr = state.heap.allocate(64)
    p3_sym_size = get_tainted_mem_bits(state, 64)
    state.solver.add(p3_sym_size < 64)
    p3_sym_val = get_tainted_mem_bits(state, 64 * 8)
    
    p4_sym_ptr = state.heap.allocate(64)
    p4_sym_size = get_tainted_mem_bits(state, 64)
    state.solver.add(p4_sym_size < 64)
    p4_sym_val = get_tainted_mem_bits(state, 64 * 8)

    state.memory.store(p2_sym_ptr, p2_sym_val, size=64, endness=state.arch.memory_endness)
    state.memory.store(p3_sym_ptr, p3_sym_val, size=64, endness=state.arch.memory_endness)
    state.memory.store(p4_sym_ptr, p4_sym_val, size=64, endness=state.arch.memory_endness)

    state.memory.store(params, p1_sym_ptr, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 8, p1_sym_size, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 16, p2_sym_ptr, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 24, p2_sym_size, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 32, p3_sym_ptr, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 40, p3_sym_size, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 48, p4_sym_ptr, size=8, endness=state.arch.memory_endness)
    state.memory.store(params + 56, p4_sym_size, size=8, endness=state.arch.memory_endness)

    state.globals['return_buffer'] = p2_sym_ptr

    return state


########################################################
# TPM2 Command Dependency Chains
# ==============================
# Commands are annotated with next_funcs based on TPM 2.0 spec dependency chains:
# - Commands that start sequences specify their possible continuation/completion commands
# - Commands that create handles specify commands that can use those handles
# - Commands without chain dependencies have no next_funcs (random successor selection)
#
# Chain Categories:
# 1. Sequence Operations: HashSequenceStart/HMAC_Start -> SequenceUpdate -> SequenceComplete
# 2. Key Lifecycle: CreatePrimary/Create -> Load -> crypto operations
# 3. Session Management: StartAuthSession -> Policy* commands -> FlushContext
# 4. NV Operations: NV_DefineSpace -> NV_Read/Write/etc -> NV_UndefineSpace
# 5. Context Management: ContextSave -> ContextLoad
# 6. Credential: MakeCredential -> ActivateCredential
# 7. Key Migration: Duplicate -> Import/Rewrap
########################################################

# --- NV Operations: Requires TPM2_NV_DefineSpace first ---
# Terminal command in NV chain (requires NV_DefineSpace)
@ta_init_function  # No successors - terminal in chain
def init_TPM2_NV_UndefineSpaceSpecial(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x11F)

# --- Key Lifecycle: Requires loaded key ---
# Terminal command (operates on loaded keys)
@ta_init_function  # No successors - management operation
def init_TPM2_EvictControl(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x120)

# --- Hierarchy Management: No chain dependencies ---
@ta_init_function  # No successors - standalone
def init_TPM2_HierarchyControl(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x121)

# --- NV Operations: Requires TPM2_NV_DefineSpace first ---
# Terminal command in NV chain
@ta_init_function  # No successors - terminal in chain
def init_TPM2_NV_UndefineSpace(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x122)

# --- Hierarchy Management: No chain dependencies ---
@ta_init_function  # No successors - standalone
def init_TPM2_ChangeEPS(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x124)

@ta_init_function  # No successors - standalone
def init_TPM2_ChangePPS(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x125)

@ta_init_function  # No successors - standalone (clears TPM)
def init_TPM2_Clear(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x126)

@ta_init_function  # No successors - standalone
def init_TPM2_ClearControl(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x127)

@ta_init_function  # No successors - standalone
def init_TPM2_ClockSet(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x128)

@ta_init_function  # No successors - standalone
def init_TPM2_HierarchyChangeAuth(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x129)

# --- NV Operations: TPM2_NV_DefineSpace starts NV chain ---
@ta_init_function(next_funcs=[
    "TPM2_NV_Write", "TPM2_NV_Read", "TPM2_NV_Increment", "TPM2_NV_Extend",
    "TPM2_NV_SetBits", "TPM2_NV_WriteLock", "TPM2_NV_ReadLock", "TPM2_NV_ChangeAuth",
    "TPM2_NV_Certify", "TPM2_NV_UndefineSpace", "TPM2_NV_ReadPublic",
    "TPM2_PolicyNV", "TPM2_PolicyAuthorizeNV", "TPM2_NV_GlobalWriteLock"
])
def init_TPM2_NV_DefineSpace(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x12A)

# --- PCR Operations: No strict chain dependencies ---
@ta_init_function  # No successors - standalone
def init_TPM2_PCR_Allocate(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x12B)

@ta_init_function  # No successors - standalone
def init_TPM2_PCR_SetAuthPolicy(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x12C)

@ta_init_function  # No successors - standalone
def init_TPM2_PP_Commands(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x12D)

@ta_init_function  # No successors - standalone
def init_TPM2_SetPrimaryPolicy(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x12E)

# --- Field Upgrade: FieldUpgradeStart -> FieldUpgradeData chain ---
@ta_init_function(next_funcs=["TPM2_FieldUpgradeData"])
def init_TPM2_FieldUpgradeStart(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x12F)

@ta_init_function  # No successors - standalone
def init_TPM2_ClockRateAdjust(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x130)

# --- Key Lifecycle: TPM2_CreatePrimary creates and loads primary key ---
# Primary key is already loaded, can be used for crypto ops or to create child keys
@ta_init_function(next_funcs=[
    "TPM2_Create", "TPM2_Sign", "TPM2_RSA_Encrypt", "TPM2_RSA_Decrypt",
    "TPM2_ECDH_KeyGen", "TPM2_ECDH_ZGen", "TPM2_EncryptDecrypt", "TPM2_EncryptDecrypt2",
    "TPM2_Unseal", "TPM2_Certify", "TPM2_CertifyCreation", "TPM2_CertifyX509",
    "TPM2_Quote", "TPM2_Duplicate", "TPM2_ContextSave", "TPM2_FlushContext",
    "TPM2_ReadPublic", "TPM2_ObjectChangeAuth", "TPM2_Commit", "TPM2_ZGen_2Phase",
    "TPM2_ECC_Encrypt", "TPM2_ECC_Decrypt", "TPM2_HMAC", "TPM2_HMAC_Start",
    "TPM2_NV_Certify", "TPM2_EvictControl", "TPM2_MakeCredential"
])
def init_TPM2_CreatePrimary(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x131)

# --- NV Operations: Requires TPM2_NV_DefineSpace first ---
@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_GlobalWriteLock(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x132)

# --- Attestation: Requires loaded signing key ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_GetCommandAuditDigest(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x133)

# --- NV Operations: Requires TPM2_NV_DefineSpace first (counter type) ---
@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_Increment(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x134)

@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_SetBits(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x135)

@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_Extend(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x136)

@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_Write(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x137)

@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_WriteLock(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x138)

# --- Dictionary Attack: No chain dependencies ---
@ta_init_function  # No successors - standalone
def init_TPM2_DictionaryAttackLockReset(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x139)

@ta_init_function  # No successors - standalone
def init_TPM2_DictionaryAttackParameters(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x13A)

# --- NV Operations: Requires TPM2_NV_DefineSpace first ---
@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_ChangeAuth(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x13B)

# --- PCR Operations: Can be followed by PCR_Read or Quote ---
@ta_init_function(next_funcs=["TPM2_PCR_Read", "TPM2_Quote"])
def init_TPM2_PCR_Event(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x13C)

@ta_init_function  # No successors - standalone
def init_TPM2_PCR_Reset(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x13D)

# --- Sequence Operations: Terminal - requires HashSequenceStart/HMAC_Start/MAC_Start ---
@ta_init_function  # No successors - terminal in sequence chain
def init_TPM2_SequenceComplete(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x13E)

@ta_init_function  # No successors - standalone
def init_TPM2_SetAlgorithmSet(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x13F)

@ta_init_function  # No successors - standalone
def init_TPM2_SetCommandCodeAuditStatus(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x140)

# --- Field Upgrade: Requires TPM2_FieldUpgradeStart first ---
@ta_init_function  # No successors - continues field upgrade
def init_TPM2_FieldUpgradeData(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x141)

# --- Self Test: Can be followed by GetTestResult ---
@ta_init_function(next_funcs=["TPM2_GetTestResult"])
def init_TPM2_IncrementalSelfTest(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x142)

@ta_init_function(next_funcs=["TPM2_GetTestResult"])
def init_TPM2_SelfTest(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x143)

# --- TPM Lifecycle: Startup enables operations, Shutdown prepares for restart ---
@ta_init_function(next_funcs=["TPM2_Shutdown"])  # Normal operation follows startup
def init_TPM2_Startup(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x144)

@ta_init_function(next_funcs=["TPM2_Startup"])  # Startup follows shutdown
def init_TPM2_Shutdown(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x145)

@ta_init_function  # No successors - standalone
def init_TPM2_StirRandom(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x146)

# --- Credential: Requires MakeCredential first and loaded key ---
@ta_init_function  # No successors - terminal in credential chain
def init_TPM2_ActivateCredential(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x147)

# --- Attestation: Requires loaded object and signing key ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_Certify(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x148)

# --- Policy: Requires StartAuthSession and NV_DefineSpace ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyNV(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x149)

# --- Attestation: Requires Create (for creationTicket) and Load ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_CertifyCreation(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x14A)

# --- Key Migration: Duplicate -> Import or Rewrap ---
@ta_init_function(next_funcs=["TPM2_Import", "TPM2_Rewrap"])
def init_TPM2_Duplicate(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x14B)

# --- Attestation: Requires loaded signing key ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_GetTime(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x14C)

# --- Session: Requires StartAuthSession with audit attribute ---
@ta_init_function  # No successors - terminal
def init_TPM2_GetSessionAuditDigest(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x14D)

# --- NV Operations: Requires TPM2_NV_DefineSpace first ---
@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_Read(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x14E)

@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_ReadLock(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x14F)

# --- Key Lifecycle: Requires loaded key ---
@ta_init_function  # No successors - terminal
def init_TPM2_ObjectChangeAuth(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x150)

# --- Policy: Requires StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicySecret(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x151)

# --- Key Migration: Requires Duplicate output ---
@ta_init_function(next_funcs=["TPM2_Import"])
def init_TPM2_Rewrap(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x152)

# --- Key Lifecycle: TPM2_Create creates key, needs Load to use ---
@ta_init_function(next_funcs=["TPM2_Load"])
def init_TPM2_Create(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x153)

# --- Crypto Operations: Requires loaded ECC key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_ECDH_ZGen(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x154)

# --- Crypto Operations: Requires loaded HMAC key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_HMAC(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x155)

# --- Key Migration: Import -> Load ---
@ta_init_function(next_funcs=["TPM2_Load"])
def init_TPM2_Import(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x156)

# --- Key Lifecycle: TPM2_Load loads a key, enabling crypto operations ---
@ta_init_function(next_funcs=[
    "TPM2_Sign", "TPM2_RSA_Encrypt", "TPM2_RSA_Decrypt",
    "TPM2_ECDH_KeyGen", "TPM2_ECDH_ZGen", "TPM2_EncryptDecrypt", "TPM2_EncryptDecrypt2",
    "TPM2_Unseal", "TPM2_Certify", "TPM2_CertifyCreation", "TPM2_CertifyX509",
    "TPM2_Quote", "TPM2_Duplicate", "TPM2_ContextSave", "TPM2_FlushContext",
    "TPM2_ReadPublic", "TPM2_ObjectChangeAuth", "TPM2_Commit", "TPM2_ZGen_2Phase",
    "TPM2_ECC_Encrypt", "TPM2_ECC_Decrypt", "TPM2_HMAC", "TPM2_HMAC_Start",
    "TPM2_NV_Certify", "TPM2_EvictControl", "TPM2_MakeCredential", "TPM2_Rewrap"
])
def init_TPM2_Load(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x157)

# --- Attestation: Requires loaded signing key ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_Quote(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x158)

# --- Crypto Operations: Requires loaded RSA key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_RSA_Decrypt(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x159)

# --- Sequence Operations: HMAC_Start -> SequenceUpdate -> SequenceComplete ---
@ta_init_function(next_funcs=["TPM2_SequenceUpdate", "TPM2_SequenceComplete"])
def init_TPM2_HMAC_Start(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x15B)

# --- Sequence Operations: Continues sequence, can update more or complete ---
@ta_init_function(next_funcs=["TPM2_SequenceUpdate", "TPM2_SequenceComplete", "TPM2_EventSequenceComplete"])
def init_TPM2_SequenceUpdate(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x15C)

# --- Crypto Operations: Requires loaded signing key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_Sign(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x15D)

# --- Sealing: Requires loaded sealed data object ---
@ta_init_function  # No successors - terminal operation
def init_TPM2_Unseal(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x15E)

# --- Policy: Requires StartAuthSession and loaded signing key ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicySigned(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x160)

# --- Context Management: Restores saved context ---
@ta_init_function  # No successors - context restored, can use object/session
def init_TPM2_ContextLoad(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x161)

# --- Context Management: ContextSave -> ContextLoad ---
@ta_init_function(next_funcs=["TPM2_ContextLoad"])
def init_TPM2_ContextSave(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x162)

# --- Crypto Operations: Requires loaded ECC key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_ECDH_KeyGen(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x163)

# --- Crypto Operations: Requires loaded symmetric key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_EncryptDecrypt(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x164)

# --- Resource Management: Flushes loaded objects/sessions ---
@ta_init_function  # No successors - terminal operation
def init_TPM2_FlushContext(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x165)

# --- Key Lifecycle: LoadExternal loads external key ---
@ta_init_function(next_funcs=[
    "TPM2_Sign", "TPM2_RSA_Encrypt", "TPM2_VerifySignature",
    "TPM2_ECDH_KeyGen", "TPM2_ECC_Encrypt", "TPM2_FlushContext",
    "TPM2_ContextSave", "TPM2_ReadPublic"
])
def init_TPM2_LoadExternal(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x167)

# --- Credential: MakeCredential -> ActivateCredential ---
@ta_init_function(next_funcs=["TPM2_ActivateCredential"])
def init_TPM2_MakeCredential(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x168)

# --- NV Operations: Requires TPM2_NV_DefineSpace first ---
@ta_init_function  # No successors - operates on defined NV space
def init_TPM2_NV_ReadPublic(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x169)

# --- Policy: All policy commands require StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyAuthorize(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x16A)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyAuthValue(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x16B)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyCommandCode(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x16C)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyCounterTimer(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x16D)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyCpHash(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x16E)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyLocality(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x16F)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyNameHash(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x170)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyOR(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x171)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyTicket(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x172)

# --- Key Info: Requires loaded or persistent object ---
@ta_init_function  # No successors - terminal info operation
def init_TPM2_ReadPublic(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x173)

# --- Crypto Operations: Requires loaded RSA key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_RSA_Encrypt(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x174)

# --- Session Management: StartAuthSession -> Policy* commands or FlushContext ---
@ta_init_function(next_funcs=[
    "TPM2_PolicyPCR", "TPM2_PolicySecret", "TPM2_PolicySigned", "TPM2_PolicyAuthorize",
    "TPM2_PolicyAuthValue", "TPM2_PolicyPassword", "TPM2_PolicyOR", "TPM2_PolicyNV",
    "TPM2_PolicyCommandCode", "TPM2_PolicyCpHash", "TPM2_PolicyLocality",
    "TPM2_PolicyNameHash", "TPM2_PolicyCounterTimer", "TPM2_PolicyNvWritten",
    "TPM2_PolicyTemplate", "TPM2_PolicyAuthorizeNV", "TPM2_PolicyPhysicalPresence",
    "TPM2_PolicyDuplicationSelect", "TPM2_PolicyTicket", "TPM2_Policy_AC_SendSelect",
    "TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest",
    "TPM2_GetSessionAuditDigest", "TPM2_ContextSave"
])
def init_TPM2_StartAuthSession(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x176)

# --- Crypto Operations: Requires loaded key (public portion) ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_VerifySignature(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x177)

# --- Info: No chain dependencies ---
@ta_init_function  # No successors - standalone info
def init_TPM2_ECC_Parameters(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x178)

@ta_init_function  # No successors - standalone
def init_TPM2_FirmwareRead(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x179)

@ta_init_function  # No successors - standalone info
def init_TPM2_GetCapability(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x17A)

@ta_init_function  # No successors - standalone
def init_TPM2_GetRandom(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x17B)

# --- Self Test: Follows SelfTest or IncrementalSelfTest ---
@ta_init_function  # No successors - terminal in self-test chain
def init_TPM2_GetTestResult(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x17C)

# --- Crypto: Standalone hash operation (not part of sequence) ---
@ta_init_function  # No successors - standalone
def init_TPM2_Hash(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x17D)

# --- PCR: Standalone read ---
@ta_init_function  # No successors - terminal
def init_TPM2_PCR_Read(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x17E)

# --- Policy: Requires StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyPCR(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x17F)

# --- Policy: Requires StartAuthSession, resets policy session ---
@ta_init_function(next_funcs=[
    "TPM2_PolicyPCR", "TPM2_PolicySecret", "TPM2_PolicySigned", "TPM2_PolicyAuthorize",
    "TPM2_PolicyAuthValue", "TPM2_PolicyPassword", "TPM2_PolicyOR", "TPM2_PolicyNV",
    "TPM2_PolicyCommandCode", "TPM2_PolicyCpHash", "TPM2_PolicyLocality",
    "TPM2_PolicyNameHash", "TPM2_PolicyCounterTimer", "TPM2_PolicyNvWritten",
    "TPM2_PolicyTemplate", "TPM2_PolicyAuthorizeNV", "TPM2_PolicyPhysicalPresence",
    "TPM2_PolicyDuplicationSelect", "TPM2_PolicyTicket", "TPM2_FlushContext"
])
def init_TPM2_PolicyRestart(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x180)

@ta_init_function  # No successors - standalone info
def init_TPM2_ReadClock(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x181)

# --- PCR Operations: Can be followed by PCR_Read or Quote ---
@ta_init_function(next_funcs=["TPM2_PCR_Read", "TPM2_Quote"])
def init_TPM2_PCR_Extend(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x182)

@ta_init_function  # No successors - standalone
def init_TPM2_PCR_SetAuthValue(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x183)

# --- NV Attestation: Requires NV_DefineSpace and loaded signing key ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_NV_Certify(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x184)

# --- Sequence Operations: Terminal - requires HashSequenceStart ---
@ta_init_function  # No successors - terminal in sequence chain
def init_TPM2_EventSequenceComplete(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x185)

# --- Sequence Operations: HashSequenceStart -> SequenceUpdate -> SequenceComplete/EventSequenceComplete ---
@ta_init_function(next_funcs=["TPM2_SequenceUpdate", "TPM2_SequenceComplete", "TPM2_EventSequenceComplete"])
def init_TPM2_HashSequenceStart(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x186)

# --- Policy: Requires StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyPhysicalPresence(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x187)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyDuplicationSelect(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x188)

# --- Policy: Requires StartAuthSession, returns current digest ---
@ta_init_function  # No successors - info operation
def init_TPM2_PolicyGetDigest(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x189)

@ta_init_function  # No successors - standalone test
def init_TPM2_TestParms(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x18A)

# --- Crypto Operations: Requires loaded ECC key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_Commit(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x18B)

# --- Policy: Requires StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyPassword(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x18C)

# --- Crypto Operations: Requires loaded ECC key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_ZGen_2Phase(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x18D)

@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_EC_Ephemeral(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x18E)

# --- Policy: Requires StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyNvWritten(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x18F)

@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyTemplate(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x190)

# --- Key Lifecycle: CreateLoaded creates and loads key in one command ---
@ta_init_function(next_funcs=[
    "TPM2_Sign", "TPM2_RSA_Encrypt", "TPM2_RSA_Decrypt",
    "TPM2_ECDH_KeyGen", "TPM2_ECDH_ZGen", "TPM2_EncryptDecrypt", "TPM2_EncryptDecrypt2",
    "TPM2_Unseal", "TPM2_Certify", "TPM2_CertifyCreation", "TPM2_CertifyX509",
    "TPM2_Quote", "TPM2_Duplicate", "TPM2_ContextSave", "TPM2_FlushContext",
    "TPM2_ReadPublic", "TPM2_ObjectChangeAuth", "TPM2_Commit", "TPM2_ZGen_2Phase",
    "TPM2_ECC_Encrypt", "TPM2_ECC_Decrypt", "TPM2_HMAC", "TPM2_HMAC_Start",
    "TPM2_NV_Certify", "TPM2_EvictControl", "TPM2_MakeCredential"
])
def init_TPM2_CreateLoaded(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x191)

# --- Policy: Requires StartAuthSession and NV_DefineSpace ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_PolicyAuthorizeNV(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x192)

# --- Crypto Operations: Requires loaded symmetric key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_EncryptDecrypt2(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x193)

# --- Attached Component: No chain dependencies ---
@ta_init_function  # No successors - standalone
def init_TPM2_AC_GetCapability(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x194)

@ta_init_function  # No successors - standalone
def init_TPM2_AC_Send(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x195)

# --- Policy: Requires StartAuthSession ---
@ta_init_function(next_funcs=["TPM2_FlushContext", "TPM2_PolicyRestart", "TPM2_PolicyGetDigest"])
def init_TPM2_Policy_AC_SendSelect(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x196)

# --- Attestation: Requires loaded object and signing key ---
@ta_init_function  # No successors - terminal attestation
def init_TPM2_CertifyX509(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x197)

@ta_init_function  # No successors - standalone
def init_TPM2_ACT_SetTimeout(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x198)

# --- Crypto Operations: Requires loaded ECC key ---
@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_ECC_Encrypt(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x199)

@ta_init_function  # No successors - terminal crypto operation
def init_TPM2_ECC_Decrypt(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x19A)

# --- Vendor: No chain dependencies ---
@ta_init_function  # No successors - standalone vendor command
def init_TPM2_Vendor_TCG_Test(state: angr.SimState):
    return _generic_tpm_command_inputs(state, 0x20000000)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_bc50d971_d4c9_42c4_82cb_343fb7f37896_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


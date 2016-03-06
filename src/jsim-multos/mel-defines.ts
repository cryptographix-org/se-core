export enum MELINST {
  melSYSTEM =  0x00,
  melBRANCH =  0x01,
  melJUMP =    0x02,
  melCALL =    0x03,
  melSTACK =   0x04,
  melPRIMRET = 0x05,
  melINVALID = 0x06,
  melLOAD =    0x07,
  melSTORE =   0x08,
  melLOADI =   0x09,
  melSTOREI =  0x0A,
  melLOADA =   0x0B,
  melINDEX =   0x0C,
  melSETB =    0x0D,
  melCMPB =    0x0E,
  melADDB =    0x0F,
  melSUBB =    0x10,
  melSETW =    0x11,
  melCMPW =    0x12,
  melADDW =    0x13,
  melSUBW =    0x14,
  melCLEARN =  0x15,
  melTESTN =   0x16,
  melINCN =    0x17,
  melDECN =    0x18,
  melNOTN =    0x19,
  melCMPN =    0x1A,
  melADDN =    0x1B,
  melSUBN =    0x1C,
  melANDN =    0x1D,
  melORN =     0x1E,
  melXORN =    0x1F
};

export enum MELTAGADDR {
  melAddrTOS = 0x00,
  melAddrSB =  0x01,
  melAddrST =  0x02,
  melAddrDB =  0x03,
  melAddrLB =  0x04,
  melAddrDT =  0x05,
  melAddrPB =  0x06,
  melAddrPT =  0x07
};

export enum MELTAGCOND {
  melCondSPEC =  0x00, // Special
  melCondEQ =    0x01, // Equal
  melCondLT =    0x02, // Less than
  melCondLE =    0x03, // Less than, equal to
  melCondGT =    0x04, // Greater than
  melCondGE =    0x05, // Greater than, equal to
  melCondNE =    0x06, // Not equal to
  melCondALL =   0x07  // Always
};

export enum MELTAGSYSTEM {
  melSystemNOP =       0x00, // NOP
  melSystemSetSW =     0x01, // SETSW
  melSystemSetLa =     0x02, // SETLA
  melSystemSetSWLa =   0x03, // SETSWLA
  melSystemExit =      0x04, // EXIT
  melSystemExitSW =    0x05, // EXITSW
  melSystemExitLa =    0x06, // EXITLA
  melSystemExitSWLa =  0x07  // EXITSWLA
};

export enum MELTAGSTACK {
  melStackPUSHZ =  0x00, // PUSHZ
  melStackPUSHB =  0x01, // PUSHB
  melStackPUSHW =  0x02, // PUSHW
  melStackXX4 =    0x03, // Illegal
  melStackPOPN =   0x04, // POPN
  melStackPOPB =   0x05, // POPB
  melStackPOPW =   0x06, // POPW
  melStackXX7 =    0x07  // Illegal
};

export enum MELTAGPRIMRET {
  melPrimRetPRIM0 =  0x00, // PRIM 0
  melPrimRetPRIM1 =  0x01, // PRIM 1
  melPrimRetPRIM2 =  0x02, // PRIM 2
  melPrimRetPRIM3 =  0x03, // PRIM 3
  melPrimRetRET =    0x04, // RET
  melPrimRetRETI =   0x05, // RET In
  melPrimRetRETO =   0x06, // RET Out
  melPrimRetRETIO =  0x07  // RET InOut
};

export enum MELPARAMDEF {
  melParamDefNone =              0x00,
  melParamDefTopOfStack =        0x01,
  melParamDefByteOperLen =       0x11,
  melParamDefByteImmediate =     0x12,
  melParamDefByteCodeRelative =  0x18,
  melParamDefWordImmediate =     0x20,
  melParamDefWordOffsetSB =      0x21,
  melParamDefWordOffsetST =      0x22,
  melParamDefWordOffsetDB =      0x23,
  melParamDefWordOffsetLB =      0x24,
  melParamDefWordOffsetDT =      0x25,
  melParamDefWordOffsetPB =      0x26,
  melParamDefWordOffsetPT =      0x27,
  melParamDefWordCodeAddress =   0x28
};

function MELPARAM4( a, b, c, d )        { return ( (d<<24) | (c<<16) | (b<<8) | (a<<0) ); }
function OPTAG2MELINST( opCode, tag )   { return ( ( ( opCode & 0x1f ) << 3 ) | tag ); }
export function MEL2OPCODE( byteCode )         { return ( ( byteCode >> 3 ) & 0x1f ); }
export function MEL2INST( byteCode )           { return MEL2OPCODE( byteCode ); }
export function MEL2TAG( byteCode )            { return ( (byteCode) & 7 ) };

function MELPARAMSIZE( paramType )
{
  return ( paramType == MELPARAMDEF.melParamDefNone )
         ? 0
         : ( paramType < MELPARAMDEF.melParamDefWordImmediate) ? 1 : 2;
}

export class MEL
{
  public static melDecode = [];

  public static MELINST: MELINST;
  public static MELTAGSTACK: MELTAGSTACK;
  public static MELPARAMDEF: MELPARAMDEF;
  public static MELTAGADDR: MELTAGADDR;

}

function setMelDecode( byteCode: number, instName: string, param1?, param2?, param3?, param4? )
{
  param1 = param1 || MELPARAMDEF.melParamDefNone;
  param2 = param2 || MELPARAMDEF.melParamDefNone;
  param3 = param3 || MELPARAMDEF.melParamDefNone;
  param4 = param4 || MELPARAMDEF.melParamDefNone;

  MEL.melDecode[ byteCode ] = {
    byteCode: byteCode,
    instLen: 1 + MELPARAMSIZE( param1 ) + MELPARAMSIZE( param2 ) + MELPARAMSIZE( param3 ) + MELPARAMSIZE( param4 ),
    instName: instName,
    paramDefs: MELPARAM4( param1, param2, param3, param4 )
  };
}

function setMelDecodeStdModes( melInst: MELINST, instName: string, param1Def: MELPARAMDEF )
{
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrSB ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetSB );
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrST ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetST );
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrDB ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetDB );
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrLB ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetLB );
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrDT ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetDT );
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrPB ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetPB );
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrPT ), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetPT );
}

function setMelDecodeStdModesAndTOS( melInst: MELINST, instName: string, param1Def: MELPARAMDEF )
{
  setMelDecode( OPTAG2MELINST( melInst, MELTAGADDR.melAddrTOS ), instName, param1Def, MELPARAMDEF.melParamDefTopOfStack );
  setMelDecodeStdModes( melInst, instName, param1Def );
}

function fillMelDecode()
{
  setMelDecodeStdModesAndTOS( MELINST.melLOAD,   "LOAD",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melSTORE,  "STORE",  MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melLOADI,  "LOADI",  MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melSTOREI, "STOREI", MELPARAMDEF.melParamDefByteOperLen );

  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrSB ), "LOADA", MELPARAMDEF.melParamDefWordOffsetSB );
  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrST ), "LOADA", MELPARAMDEF.melParamDefWordOffsetST );
  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrDB ), "LOADA", MELPARAMDEF.melParamDefWordOffsetDB );
  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrLB ), "LOADA", MELPARAMDEF.melParamDefWordOffsetLB );
  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrDT ), "LOADA", MELPARAMDEF.melParamDefWordOffsetDT );
  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrPB ), "LOADA", MELPARAMDEF.melParamDefWordOffsetPB );
  setMelDecode( OPTAG2MELINST( MELINST.melLOADA, MELTAGADDR.melAddrPT ), "LOADA", MELPARAMDEF.melParamDefWordOffsetPT );

  setMelDecodeStdModes( MELINST.melINDEX,  "INDEX", MELPARAMDEF.melParamDefByteImmediate );

  setMelDecodeStdModesAndTOS( MELINST.melSETB,   "SETB", MELPARAMDEF.melParamDefByteImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melCMPB,   "CMPB", MELPARAMDEF.melParamDefByteImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melADDB,   "ADDB", MELPARAMDEF.melParamDefByteImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melSUBB,   "SUBB", MELPARAMDEF.melParamDefByteImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melSETW,   "SETW", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melCMPW,   "CMPW", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melADDW,   "ADDW", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecodeStdModesAndTOS( MELINST.melSUBW,   "SUBW", MELPARAMDEF.melParamDefWordImmediate );

  setMelDecodeStdModesAndTOS( MELINST.melCLEARN, "CLEARN", MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melTESTN,  "TESTN",  MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melINCN,   "INCN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melDECN,   "DECN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melNOTN,   "NOTN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melCMPN,   "CMPN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melADDN,   "ADDN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melSUBN,   "SUBN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melANDN,   "ANDN",   MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melORN,    "ORN",    MELPARAMDEF.melParamDefByteOperLen );
  setMelDecodeStdModesAndTOS( MELINST.melXORN,   "XORN",   MELPARAMDEF.melParamDefByteOperLen );

  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemNOP ), "NOP" );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemSetSW ), "SETSW", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemSetLa ), "SETLA", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemSetSWLa ), "SETSWLA", MELPARAMDEF.melParamDefWordImmediate, MELPARAMDEF.melParamDefWordImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExit ), "EXIT" );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExitSW ), "EXITSW", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExitLa ), "EXITA", MELPARAMDEF.melParamDefWordImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExitSWLa ), "EXITSWLA", MELPARAMDEF.melParamDefWordImmediate, MELPARAMDEF.melParamDefWordImmediate );

  // setMelDecode( OPTAG2MELINST( melBRANCH, melCondSPEC ), "---", 0, melAddrTOS );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondEQ ), "BEQ", MELPARAMDEF.melParamDefByteCodeRelative );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondLT ), "BLT", MELPARAMDEF.melParamDefByteCodeRelative );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondLE ), "BLE", MELPARAMDEF.melParamDefByteCodeRelative );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondGT ), "BGT", MELPARAMDEF.melParamDefByteCodeRelative );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondGE ), "BGE", MELPARAMDEF.melParamDefByteCodeRelative );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondNE ), "BNE", MELPARAMDEF.melParamDefByteCodeRelative );
  setMelDecode( OPTAG2MELINST( MELINST.melBRANCH, MELTAGCOND.melCondALL ), "BA", MELPARAMDEF.melParamDefByteCodeRelative );

  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondSPEC ), "JA", MELPARAMDEF.melParamDefNone );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondEQ ), "JEQ", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondLT ), "JLT", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondLE ), "JLE", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondGT ), "JGT", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondGE ), "JGE", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondNE ), "JNE", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melJUMP, MELTAGCOND.melCondALL ), "JA", MELPARAMDEF.melParamDefWordCodeAddress );

  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondSPEC ), "CA", MELPARAMDEF.melParamDefNone );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondEQ ), "CEQ", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondLT ), "CLT", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondLE ), "CLE", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondGT ), "CGT", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondGE ), "CGE", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondNE ), "CNE", MELPARAMDEF.melParamDefWordCodeAddress );
  setMelDecode( OPTAG2MELINST( MELINST.melCALL, MELTAGCOND.melCondALL ), "CA", MELPARAMDEF.melParamDefWordCodeAddress );

  setMelDecode( OPTAG2MELINST( MELINST.melSTACK, MELTAGSTACK.melStackPUSHZ ), "PUSHZ", MELPARAMDEF.melParamDefByteOperLen );
  setMelDecode( OPTAG2MELINST( MELINST.melSTACK, MELTAGSTACK.melStackPUSHB ), "PUSHB", MELPARAMDEF.melParamDefByteImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melSTACK, MELTAGSTACK.melStackPUSHW ), "PUSHW", MELPARAMDEF.melParamDefWordImmediate );
  // setMelDecode( OPTAG2MELINST( melSTACK, melStackXX4 ), "--" );
  setMelDecode( OPTAG2MELINST( MELINST.melSTACK, MELTAGSTACK.melStackPOPN ), "POPN", MELPARAMDEF.melParamDefByteOperLen );
  setMelDecode( OPTAG2MELINST( MELINST.melSTACK, MELTAGSTACK.melStackPOPB ), "POPB" );
  setMelDecode( OPTAG2MELINST( MELINST.melSTACK, MELTAGSTACK.melStackPOPW ), "POPW" );
  // setMelDecode( OPTAG2MELINST( melSTACK, melStackXX7 ), "--" );

  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM0 ), "PRIM", MELPARAMDEF.melParamDefByteImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM1 ), "PRIM", MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM2 ), "PRIM", MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM3 ), "PRIM", MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRET ), "RET" );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRETI ), "RET", MELPARAMDEF.melParamDefByteOperLen );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRETO ), "RET", MELPARAMDEF.melParamDefByteOperLen );
  setMelDecode( OPTAG2MELINST( MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRETIO ), "RET", MELPARAMDEF.melParamDefByteOperLen, MELPARAMDEF.melParamDefByteOperLen );
}


fillMelDecode();

export var MELDecode = MEL.melDecode;
export const MEL_CCR_Z = 0x01;
export const MEL_CCR_C = 0x02;

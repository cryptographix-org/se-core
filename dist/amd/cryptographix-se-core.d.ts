declare module 'cryptographix-se-core'
{
  import { ByteArray, ByteEncoding, Kind, EndPoint, Message, Protocol, KindInfo } from 'cryptographix-sim-core';


  export class Key {
      _type: number;
      _size: number;
      _componentArray: ByteString[];
      constructor();
      setType(keyType: number): void;
      getType(): number;
      setSize(size: number): void;
      getSize(): number;
      setComponent(comp: number, value: ByteString): void;
      getComponent(comp: number): ByteString;
      static SECRET: number;
      static PRIVATE: number;
      static PUBLIC: number;
      static DES: number;
      static AES: number;
      static MODULUS: number;
      static EXPONENT: number;
      static CRT_P: number;
      static CRT_Q: number;
      static CRT_DP1: number;
      static CRT_DQ1: number;
      static CRT_PQ: number;
  }



  export class Crypto {
      constructor();
      encrypt(key: Key, mech: any, data: ByteString): ByteString;
      decrypt(key: any, mech: any, data: any): any;
      sign(key: Key, mech: any, data: ByteString, iv?: any): ByteString;
      static desPC: any;
      static desSP: any;
      private des(key, message, encrypt, mode, iv?, padding?);
      verify(key: any, mech: any, data: any, signature: any, iv: any): any;
      digest(mech: any, data: any): any;
      static DES_CBC: Number;
      static DES_ECB: number;
      static DES_MAC: number;
      static DES_MAC_EMV: number;
      static ISO9797_METHOD_1: number;
      static ISO9797_METHOD_2: number;
      static MD5: number;
      static RSA: number;
      static SHA_1: number;
      static SHA_512: number;
  }

  export class ByteString {
      byteArray: ByteArray;
      static HEX: ByteEncoding;
      static BASE64: ByteEncoding;
      constructor(value: string | ByteString | ByteArray, encoding?: number);
      length: number;
      bytes(offset: number, count?: number): ByteString;
      byteAt(offset: number): number;
      equals(otherByteString: ByteString): void;
      concat(value: ByteString): ByteString;
      left(count: number): ByteString;
      right(count: number): ByteString;
      not(): ByteString;
      and(value: ByteString): ByteString;
      or(value: ByteString): ByteString;
      pad(method: number, optional?: boolean): ByteString;
      toString(encoding?: number): string;
  }
  export const HEX: ByteEncoding;
  export const BASE64: ByteEncoding;


  export class ByteBuffer {
      byteArray: ByteArray;
      constructor(value?: ByteArray | ByteString | string, encoding?: any);
      length: number;
      toByteString(): ByteString;
      clear(): void;
      append(value: ByteString | ByteBuffer | number): ByteBuffer;
  }

  export class BaseTLV {
      static Encodings: {
          EMV: number;
          DGI: number;
      };
      static parseTLV(buffer: ByteArray, encoding: number): {
          tag: number;
          len: number;
          value: ByteArray;
          lenOffset: number;
          valueOffset: number;
      };
      byteArray: ByteArray;
      encoding: number;
      constructor(tag: number, value: ByteArray, encoding?: number);
      tag: number;
      value: ByteArray;
      len: number;
  }



  export class TLV {
      tlv: BaseTLV;
      encoding: number;
      constructor(tag: number, value: ByteString, encoding: number);
      getTLV(): ByteString;
      getTag(): number;
      getValue(): ByteString;
      getL(): ByteString;
      getLV(): ByteString;
      static parseTLV(buffer: ByteString, encoding: number): {
          tag: number;
          len: number;
          value: ByteString;
          lenOffset: number;
          valueOffset: number;
      };
      static EMV: number;
      static DGI: number;
  }



  export class TLVList {
      _tlvs: TLV[];
      constructor(tlvStream: ByteString, encoding?: number);
      index(index: number): TLV;
  }






  export class CommandAPDU implements Kind {
      CLA: number;
      INS: number;
      P1: number;
      P2: number;
      data: ByteArray;
      Le: number;
      constructor(attributes?: {});
      Lc: number;
      header: ByteArray;
      static init(CLA?: number, INS?: number, P1?: number, P2?: number, data?: ByteArray, expectedLen?: number): CommandAPDU;
      set(CLA: number, INS: number, P1: number, P2: number, data?: ByteArray, expectedLen?: number): CommandAPDU;
      setCLA(CLA: number): CommandAPDU;
      setINS(INS: number): CommandAPDU;
      setP1(P1: number): CommandAPDU;
      setP2(P2: number): CommandAPDU;
      setData(data: ByteArray): CommandAPDU;
      setLe(Le: number): CommandAPDU;
      toJSON(): {};
      encodeBytes(options?: {}): ByteArray;
      decodeBytes(byteArray: ByteArray, options?: {}): this;
  }

  export enum ISO7816 {
      CLA_ISO = 0,
      INS_EXTERNAL_AUTHENTICATE = 130,
      INS_GET_CHALLENGE = 132,
      INS_INTERNAL_AUTHENTICATE = 136,
      INS_SELECT_FILE = 164,
      INS_READ_RECORD = 178,
      INS_UPDATE_RECORD = 220,
      INS_VERIFY = 32,
      INS_BLOCK_APPLICATION = 30,
      INS_UNBLOCK_APPLICATION = 24,
      INS_UNBLOCK_CHANGE_PIN = 36,
      INS_GET_DATA = 202,
      TAG_APPLICATION_TEMPLATE = 97,
      TAG_FCI_PROPRIETARY_TEMPLATE = 165,
      TAG_FCI_TEMPLATE = 111,
      TAG_AID = 79,
      TAG_APPLICATION_LABEL = 80,
      TAG_LANGUAGE_PREFERENCES = 24365,
      TAG_APPLICATION_EFFECTIVE_DATE = 24357,
      TAG_APPLICATION_EXPIRY_DATE = 24356,
      TAG_CARDHOLDER_NAME = 24352,
      TAG_ISSUER_COUNTRY_CODE = 24360,
      TAG_ISSUER_URL = 24400,
      TAG_PAN = 90,
      TAG_PAN_SEQUENCE_NUMBER = 24372,
      TAG_SERVICE_CODE = 24368,
      ISO_PINBLOCK_SIZE = 8,
      APDU_LEN_LE_MAX = 256,
      SW_SUCCESS = 36864,
      SW_WARNING_NV_MEMORY_UNCHANGED = 25088,
      SW_PART_OF_RETURN_DATA_CORRUPTED = 25217,
      SW_END_FILE_REACHED_BEFORE_LE_BYTE = 25218,
      SW_SELECTED_FILE_INVALID = 25219,
      SW_FCI_NOT_FORMATTED_TO_ISO = 25220,
      SW_WARNING_NV_MEMORY_CHANGED = 25344,
      SW_FILE_FILLED_BY_LAST_WRITE = 25473,
      SW_WRONG_LENGTH = 26368,
      SW_FUNCTIONS_IN_CLA_NOT_SUPPORTED = 26624,
      SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 26753,
      SW_SECURE_MESSAGING_NOT_SUPPORTED = 26754,
      SW_COMMAND_NOT_ALLOWED = 26880,
      SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE = 27009,
      SW_SECURITY_STATUS_NOT_SATISFIED = 27010,
      SW_FILE_INVALID = 27011,
      SW_DATA_INVALID = 27012,
      SW_CONDITIONS_NOT_SATISFIED = 27013,
      SW_COMMAND_NOT_ALLOWED_AGAIN = 27014,
      SW_EXPECTED_SM_DATA_OBJECTS_MISSING = 27015,
      SW_SM_DATA_OBJECTS_INCORRECT = 27016,
      SW_WRONG_PARAMS = 27136,
      SW_WRONG_DATA = 27264,
      SW_FUNC_NOT_SUPPORTED = 27265,
      SW_FILE_NOT_FOUND = 27266,
      SW_RECORD_NOT_FOUND = 27267,
      SW_NOT_ENOUGH_SPACE_IN_FILE = 27268,
      SW_LC_INCONSISTENT_WITH_TLV = 27269,
      SW_INCORRECT_P1P2 = 27270,
      SW_LC_INCONSISTENT_WITH_P1P2 = 27271,
      SW_REFERENCED_DATA_NOT_FOUND = 27272,
      SW_WRONG_P1P2 = 27392,
      SW_INS_NOT_SUPPORTED = 27904,
      SW_CLA_NOT_SUPPORTED = 28160,
      SW_UNKNOWN = 28416,
  }

  export class ResponseAPDU implements Kind {
      SW: number;
      data: ByteArray;
      constructor(attributes?: {});
      La: number;
      static init(sw: number, data?: ByteArray): ResponseAPDU;
      set(sw: number, data?: ByteArray): ResponseAPDU;
      setSW(SW: number): ResponseAPDU;
      setSW1(SW1: number): ResponseAPDU;
      setSW2(SW2: number): ResponseAPDU;
      setData(data: ByteArray): ResponseAPDU;
      encodeBytes(options?: {}): ByteArray;
      decodeBytes(byteArray: ByteArray, options?: {}): this;
  }



  export interface Slot {
      isPresent: boolean;
      isPowered: boolean;
      powerOn(): Promise<ByteArray>;
      powerOff(): Promise<ByteArray>;
      reset(): Promise<ByteArray>;
      executeAPDU(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
  }




  export class SlotProtocol implements Protocol<Slot> {
      static getHandler(): SlotProtocolHandler;
      static getProxy(endPoint: EndPoint): SlotProtocolProxy;
  }
  export class SlotProtocolProxy implements Slot {
      endPoint: EndPoint;
      pending: any;
      private powerCommand(method);
      constructor(endPoint: EndPoint);
      powerOn(): Promise<ByteArray>;
      reset(): Promise<ByteArray>;
      powerOff(): Promise<ByteArray>;
      isPresent: boolean;
      isPowered: boolean;
      executeAPDU(cmd: CommandAPDU): Promise<ResponseAPDU>;
  }
  export class SlotProtocolHandler {
      endPoint: EndPoint;
      slot: Slot;
      constructor();
      linkSlot(slot: Slot, endPoint: EndPoint): void;
      unlinkSlot(): void;
      onMessage(packet: Message<any>, receivingEndPoint: EndPoint): void;
  }




  export interface JSIMCard {
      isPowered: boolean;
      powerOn(): Promise<ByteArray>;
      powerOff(): Promise<ByteArray>;
      reset(): Promise<ByteArray>;
      exchangeAPDU(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
  }



  export class JSIMScriptApplet {
      selectApplication(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
      deselectApplication(): void;
      executeAPDU(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
  }





  export class JSIMScriptCard implements JSIMCard {
      private _powerIsOn;
      private _atr;
      applets: {
          aid: ByteArray;
          applet: JSIMScriptApplet;
      }[];
      selectedApplet: JSIMScriptApplet;
      constructor();
      loadApplication(aid: ByteArray, applet: JSIMScriptApplet): void;
      isPowered: boolean;
      powerOn(): Promise<ByteArray>;
      powerOff(): Promise<any>;
      reset(): Promise<ByteArray>;
      exchangeAPDU(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
  }





  export class JSIMSlot implements Slot {
      card: JSIMCard;
      constructor(card?: JSIMCard);
      isPresent: boolean;
      isPowered: boolean;
      powerOn(): Promise<ByteArray>;
      powerOff(): Promise<ByteArray>;
      reset(): Promise<ByteArray>;
      executeAPDU(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
      insertCard(card: JSIMCard): void;
      ejectCard(): void;
  }

  export function hex2(val: any): string;
  export function hex4(val: any): string;
  export enum MEMFLAGS {
      READ_ONLY = 1,
      TRANSACTIONABLE = 2,
      TRACE = 4,
  }
  export class Segment {
      private memData;
      private memType;
      private readOnly;
      private flags;
      private inTransaction;
      private transBlocks;
      memTraces: any;
      constructor(segType: any, size: any, flags?: any, base?: ByteArray);
      getType(): any;
      getLength(): number;
      getFlags(): any;
      getDebug(): {
          memData: ByteArray;
          memType: any;
          readOnly: any;
          inTransaction: boolean;
          transBlocks: any[];
      };
      beginTransaction(): void;
      endTransaction(commit: any): void;
      readByte(addr: any): any;
      zeroBytes(addr: any, len: any): void;
      readBytes(addr: any, len: any): ByteArray;
      copyBytes(fromAddr: any, toAddr: any, len: any): void;
      writeBytes(addr: number, val: ByteArray): void;
      newAccessor(addr: any, len: any, name: any): Accessor;
  }
  export class Accessor {
      offset: number;
      length: number;
      id: string;
      seg: Segment;
      constructor(seg: any, addr: any, len: any, name: any);
      traceMemoryOp(op: any, addr: any, len: any, addr2?: any): void;
      traceMemoryValue(val: any): void;
      zeroBytes(addr: number, len: number): void;
      readByte(addr: number): number;
      readBytes(addr: any, len: any): ByteArray;
      copyBytes(fromAddr: number, toAddr: number, len: number): ByteArray;
      writeByte(addr: number, val: number): void;
      writeBytes(addr: number, val: ByteArray): void;
      getType(): any;
      getLength(): number;
      getID(): string;
      getDebug(): {
          offset: number;
          length: number;
          seg: Segment;
      };
  }
  export class MemoryManager {
      private memorySegments;
      private memTraces;
      newSegment(memType: any, size: any, flags?: any): Segment;
      getMemTrace(): any[];
      initMemTrace(): void;
      getSegment(type: any): any;
  }

  export enum MELINST {
      melSYSTEM = 0,
      melBRANCH = 1,
      melJUMP = 2,
      melCALL = 3,
      melSTACK = 4,
      melPRIMRET = 5,
      melINVALID = 6,
      melLOAD = 7,
      melSTORE = 8,
      melLOADI = 9,
      melSTOREI = 10,
      melLOADA = 11,
      melINDEX = 12,
      melSETB = 13,
      melCMPB = 14,
      melADDB = 15,
      melSUBB = 16,
      melSETW = 17,
      melCMPW = 18,
      melADDW = 19,
      melSUBW = 20,
      melCLEARN = 21,
      melTESTN = 22,
      melINCN = 23,
      melDECN = 24,
      melNOTN = 25,
      melCMPN = 26,
      melADDN = 27,
      melSUBN = 28,
      melANDN = 29,
      melORN = 30,
      melXORN = 31,
  }
  export enum MELTAGADDR {
      melAddrTOS = 0,
      melAddrSB = 1,
      melAddrST = 2,
      melAddrDB = 3,
      melAddrLB = 4,
      melAddrDT = 5,
      melAddrPB = 6,
      melAddrPT = 7,
  }
  export enum MELTAGCOND {
      melCondSPEC = 0,
      melCondEQ = 1,
      melCondLT = 2,
      melCondLE = 3,
      melCondGT = 4,
      melCondGE = 5,
      melCondNE = 6,
      melCondALL = 7,
  }
  export enum MELTAGSYSTEM {
      melSystemNOP = 0,
      melSystemSetSW = 1,
      melSystemSetLa = 2,
      melSystemSetSWLa = 3,
      melSystemExit = 4,
      melSystemExitSW = 5,
      melSystemExitLa = 6,
      melSystemExitSWLa = 7,
  }
  export enum MELTAGSTACK {
      melStackPUSHZ = 0,
      melStackPUSHB = 1,
      melStackPUSHW = 2,
      melStackXX4 = 3,
      melStackPOPN = 4,
      melStackPOPB = 5,
      melStackPOPW = 6,
      melStackXX7 = 7,
  }
  export enum MELTAGPRIMRET {
      melPrimRetPRIM0 = 0,
      melPrimRetPRIM1 = 1,
      melPrimRetPRIM2 = 2,
      melPrimRetPRIM3 = 3,
      melPrimRetRET = 4,
      melPrimRetRETI = 5,
      melPrimRetRETO = 6,
      melPrimRetRETIO = 7,
  }
  export enum MELPARAMDEF {
      melParamDefNone = 0,
      melParamDefTopOfStack = 1,
      melParamDefByteOperLen = 17,
      melParamDefByteImmediate = 18,
      melParamDefByteCodeRelative = 24,
      melParamDefWordImmediate = 32,
      melParamDefWordOffsetSB = 33,
      melParamDefWordOffsetST = 34,
      melParamDefWordOffsetDB = 35,
      melParamDefWordOffsetLB = 36,
      melParamDefWordOffsetDT = 37,
      melParamDefWordOffsetPB = 38,
      melParamDefWordOffsetPT = 39,
      melParamDefWordCodeAddress = 40,
  }
  export function MEL2OPCODE(byteCode: any): number;
  export function MEL2INST(byteCode: any): number;
  export function MEL2TAG(byteCode: any): number;
  export class MEL {
      static melDecode: any[];
      static MELINST: MELINST;
      static MELTAGSTACK: MELTAGSTACK;
      static MELPARAMDEF: MELPARAMDEF;
      static MELTAGADDR: MELTAGADDR;
  }
  export var MELDecode: any[];
  export const MEL_CCR_Z: number;
  export const MEL_CCR_C: number;



  export class MELVirtualMachine {
      ramSegment: any;
      romSegment: any;
      codeArea: any;
      staticArea: any;
      publicArea: any;
      dynamicArea: any;
      sessionSize: any;
      isExecuting: any;
      currentIP: any;
      localBase: any;
      dynamicTop: any;
      conditionCodeReg: any;
      initMVM(params: any): void;
      disassembleCode(resetIP: any, stepToNextIP: any): string;
      private mapToSegmentAddr(addrTag, addrOffset);
      private mapFromSegmentAddr(segmentAddr);
      private checkDataAccess(addrTag, offset, length);
      private readSegmentData(addrTag, offset, length);
      private writeSegmentData(addrTag, offset, val);
      private pushZerosToStack(cnt);
      private pushConstToStack(cnt, val);
      private copyOnStack(fromOffset, toOffset, cnt);
      private pushToStack(addrTag, offset, cnt);
      private popFromStackAndStore(addrTag, offset, cnt);
      private popFromStack(cnt);
      setupApplication(execParams: any): void;
      private initExecution();
      segs: string[];
      private constByteBinaryOperation(opCode, constVal, addrTag, addrOffset);
      private constWordBinaryOperation(opCode, constVal, addrTag, addrOffset);
      private binaryOperation(opCode, opSize, addrTag, addrOffset);
      private unaryOperation(opCode, opSize, addrTag, addrOffset);
      private handleReturn(inBytes, outBytes);
      private isCondition(tag);
      executeStep(): any;
      setCommandAPDU(commandAPDU: CommandAPDU): void;
      getResponseAPDU(): ResponseAPDU;
      getDebug: {};
  }





  export class JSIMMultosApplet {
      sessionSize: any;
      codeArea: any;
      staticArea: any;
      constructor(codeArea: any, staticArea: any, sessionSize: any);
  }
  export class JSIMMultosCard implements JSIMCard {
      private cardConfig;
      static defaultConfig: {
          romSize: number;
          ramSize: number;
          publicSize: number;
          nvramSize: number;
      };
      private powerIsOn;
      private atr;
      applets: {
          aid: ByteArray;
          applet: JSIMMultosApplet;
      }[];
      selectedApplet: JSIMMultosApplet;
      constructor(config?: any);
      loadApplication(aid: ByteArray, alu: ByteArray): void;
      isPowered: boolean;
      powerOn(): Promise<ByteArray>;
      powerOff(): Promise<any>;
      reset(): Promise<ByteArray>;
      exchangeAPDU(commandAPDU: CommandAPDU): Promise<ResponseAPDU>;
      memoryManager: MemoryManager;
      romSegment: any;
      nvramSegment: any;
      ramSegment: any;
      mvm: any;
      initializeVM(config: any): void;
      resetVM(): void;
      shutdownVM(): void;
      selectApplication(applet: JSIMMultosApplet, sessionSize: any): void;
      executeStep(): any;
  }

  export function callPrimitive(ctx: any, prim: any, set: any, arg1: any, arg2: any, arg3: any): void;

  export class SecurityManager {
      initSecurity(): void;
      processAPDU(apdu: any): boolean;
  }

  export class ADC {
  }

  export class ALC {
  }

  export class ALU implements Kind {
      static kindInfo: KindInfo;
      code: ByteArray;
      data: ByteArray;
      fci: ByteArray;
      dir: ByteArray;
      constructor(attributes?: {});
      toJSON(): {};
      private getALUSegment(bytes, segmentID);
      decodeBytes(bytes: ByteArray, options?: Object): this;
      encodeBytes(options?: {}): ByteArray;
  }
}

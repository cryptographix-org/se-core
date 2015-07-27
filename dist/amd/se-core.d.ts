declare module 'se-core'
{
import {ByteArray,KindInfo} from 'sim-core';

  
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
      encrypt(key: any, mech: any, data: ByteString): ByteString;
      decrypt(key: any, mech: any, data: any): any;
      sign(key: any, mech: any, data: any, iv: any): ByteString;
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
  
  export class Hex {
      private static decoder;
      static decode(a: any): any[];
  }
  
  export class ByteString {
      static UTF8: number;
      static BASE64: number;
      static ASCII: number;
      static HEX: number;
      constructor(value: any, encoding?: any);
      length: number;
      _bytes: Uint8Array;
      bytes(offset: number, count?: number): ByteString;
      byteAt(offset: number): number;
      equals(otherByteString: ByteString): boolean;
      concat(value: ByteString): ByteString;
      left(value: any): ByteString;
      right(value: any): ByteString;
      not(): ByteString;
      and(value: ByteString): ByteString;
      or(value: ByteString): ByteString;
      pad(method: number, optional?: boolean): ByteString;
      toString(encoding: any): string;
  }
  export const HEX: number;
  export const ASCII: number;
  export const BASE64: number;
  export const UTF8: number;
  
  
  export class ByteBuffer {
      _bytes: Uint8Array;
      constructor(value?: any, encoding?: any);
      length: number;
      toByteString(): ByteString;
      clear(): void;
      append(value: any): ByteBuffer;
  }
  
  
  export class TLV {
      _bytes: Uint8Array;
      _encoding: number;
      _tag: number;
      _taglen: number;
      _lenlen: number;
      constructor(tag: number, value: ByteString, encoding: number);
      getTLV(): ByteString;
      getTag(): number;
      getValue(): ByteString;
      getL(): ByteString;
      getLV(): ByteString;
      static parseTLV(buffer: ByteString, encoding: number): {
          tag: number;
          len: number;
          value: any;
          lenOffset: number;
          valueOffset: number;
      };
      static EMV: number;
      static DGI: number;
      static L16: number;
  }
  
  
  
  export class TLVList {
      _tlvs: TLV[];
      constructor(tlvStream: ByteString, encoding?: number);
      index(index: any): TLV;
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
  
  export class ALU implements Kind {
      private static $kindInfo;
      kindInfo: KindInfo;
      private aluBytes;
      properties: {};
      constructor(byteArray?: ByteArray);
      private getALUSegment(segmentID);
      static decodeBlob(blob: ByteArray, opts?: Object): ALU;
      encodeBlob(opts?: {}): ByteArray;
  }
  
  export class MULTOSTester {
      execTests(): void;
  }
  
  export class CardApplication {
      onAPDUResponse: any;
      constructor(onAPDUResponse: any);
      selectApplication(bP1: any, bP2: any, sAID: any): {
          sw: number;
          data: any;
      };
      deselectApplication(): void;
      executeAPDUCommand(bCLA: any, bINS: any, bP1: any, bP2: any, commandData: any, wLe: any): {
          sw: number;
          data: any;
      };
  }
  }

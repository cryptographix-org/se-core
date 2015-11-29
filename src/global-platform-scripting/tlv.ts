import { BaseTLV as BaseTLV } from '../base/base-tlv';
import { ByteString } from './byte-string';
import { ByteBuffer } from './byte-buffer';

export class TLV
{
  tlv: BaseTLV;
  encoding: number;

  constructor ( tag: number, value: ByteString, encoding: number )
  {
    this.tlv = new BaseTLV( tag, value.byteArray, encoding );

    this.encoding = encoding;
  }

  getTLV(): ByteString
  {
    return new ByteString( this.tlv.byteArray );
  }

  getTag(): number
  {
    return this.tlv.tag;
  }

  getValue(): ByteString
  {
    return new ByteString( this.tlv.value );
  }

  getL(): ByteString
  {
    var info = BaseTLV.parseTLV( this.tlv.byteArray, this.encoding );

    return new ByteString( this.tlv.byteArray.slice( info.lenOffset, info.valueOffset ) );
  }

  getLV()
  {
    var info = BaseTLV.parseTLV( this.tlv.byteArray, this.encoding );

    return new ByteString( this.tlv.byteArray.slice( info.lenOffset, info.valueOffset + info.len ) );
  }

  static parseTLV( buffer: ByteString, encoding: number ): { tag: number, len: number, value: ByteString, lenOffset: number, valueOffset: number }
  {
    let info = BaseTLV.parseTLV( buffer.byteArray, encoding );

    return {
      tag: info.tag,
      len: info.len,
      value: new ByteString( info.value ),
      lenOffset: info.lenOffset,
      valueOffset: info.valueOffset
    };
  }

  static EMV = BaseTLV.Encodings.EMV;
  static DGI = BaseTLV.Encodings.DGI;
//  static L16 = BaseTLV.L16;
}

import { ByteArray } from 'sim-core';

export class BaseTLV
{
  public static Encodings = {
    EMV: 1,
    DGI: 2
  };

  static parseTLV( buffer: ByteArray, encoding: number ): { tag: number, len: number, value: ByteArray, lenOffset: number, valueOffset: number }
  {
    var res = { tag: 0, len: 0, value: undefined, lenOffset: 0, valueOffset: 0 };
    var off = 0;
    var bytes = buffer.backingArray;  // TODO: Use byteAt( .. )

    switch( encoding )
    {
      case BaseTLV.Encodings.EMV:
      {
        while( ( off < bytes.length ) && ( ( bytes[ off ] == 0x00 ) || ( bytes[ off ] == 0xFF ) ) )
          ++off;

        if ( off >= bytes.length )
          return res;

        if ( ( bytes[ off ] & 0x1F ) == 0x1F )
        {
          res.tag = bytes[ off++ ] << 8;
          if ( off >= bytes.length )
          { /*log("1");*/  return null; }
        }

        res.tag |= bytes[ off++ ];

        res.lenOffset = off;

        if ( off >= bytes.length )
        { /*log("2");*/  return null; }

        var ll = ( bytes[ off ] & 0x80 ) ? ( bytes[ off++ ] & 0x7F ) : 1;
        while( ll-- > 0 )
        {
          if ( off >= bytes.length )
          { /*log("3:" + off + ":" + bytes.length);  */return null; }

          res.len = ( res.len << 8 ) | bytes[ off++ ];
        }

        res.valueOffset = off;
        if ( off + res.len > bytes.length )
      { /*log("4");*/  return null; }
        res.value = bytes.slice( res.valueOffset, res.valueOffset + res.len );

  //      log( res.valueOffset + "+" + res.len + "=" + bytes );
        break;
      }
    }

    return res;
  }

  public byteArray: ByteArray;
  encoding: number;

  constructor ( tag: number, value: ByteArray, encoding?: number )
  {
    this.encoding = encoding || BaseTLV.Encodings.EMV;

    switch( this.encoding )
    {
      case BaseTLV.Encodings.EMV:
      {
        var tlvBuffer = new ByteArray([]);

        if ( tag >=  0x100 )
          tlvBuffer.addByte( ( tag >> 8 ) & 0xFF );
        tlvBuffer.addByte( tag & 0xFF );

        var len = value.length;
        if ( len > 0xFF )
        {
          tlvBuffer.addByte( 0x82 );
          tlvBuffer.addByte( ( len >> 8 ) & 0xFF );
        }
        else if ( len > 0x7F )
          tlvBuffer.addByte( 0x81 );

        tlvBuffer.addByte( len & 0xFF );

        tlvBuffer.concat( value );

        this.byteArray = tlvBuffer;

        break;
      }
    }
  }

  get tag(): number
  {
    return BaseTLV.parseTLV( this.byteArray, this.encoding ).tag;
  }

  get value(): ByteArray
  {
    return BaseTLV.parseTLV( this.byteArray, this.encoding ).value;
  }

  get len(): number
  {
    return BaseTLV.parseTLV( this.byteArray, this.encoding ).len;
  }
}

BaseTLV.Encodings[ "CTV" ] = 4;// { parse: 0, build: 1 };

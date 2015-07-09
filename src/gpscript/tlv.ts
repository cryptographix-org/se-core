import { ByteString } from './byte-string';
import { ByteBuffer } from './byte-buffer';

export class TLV
{
  _bytes: Uint8Array;
  _encoding: number;
  _tag: number;
  _taglen: number;
  _lenlen: number

  constructor ( tag: number, value: ByteString, encoding: number )
  {
    this._encoding = encoding;
    this._bytes = undefined;
    this._tag = tag;

    if ( tag == undefined )
    {
      this._bytes = value._bytes;
    }
    else
    {
      switch( encoding )
      {
        case TLV.EMV:
        {
          var tlvBuffer = new ByteBuffer();

          if ( tag >=  0x100 )
            tlvBuffer.append( ( tag >> 8 ) & 0xFF );
          tlvBuffer.append( tag & 0xFF );

          this._taglen = tlvBuffer.length;

          var len = value.length;
          if ( len > 0xFF )
          {
            tlvBuffer.append( 0x82 );
            tlvBuffer.append( ( len >> 8 ) & 0xFF );
          }
          else if ( len > 0x7F )
            tlvBuffer.append( 0x81 );

          tlvBuffer.append( len & 0xFF );

          this._lenlen = tlvBuffer.length - this._taglen;

          tlvBuffer.append( value._bytes );

          this._bytes = tlvBuffer._bytes;
  //        log( value._bytes );
          break;
        }
      }
    }
  }

  getTLV()
  {
    return new ByteString( this._bytes );
  }

  getTag()
  {
    return this._tag;
  }

  getValue()
  {
    return new ByteString( this._bytes.subarray( this._taglen + this._lenlen ) );
  }

  getL()
  {
    return new ByteString( this._bytes.subarray( this._taglen, this._taglen + this._lenlen ) );
  }

  getLV()
  {
    return new ByteString( this._bytes.subarray( this._taglen ) );
  }

  static parseTLV( buffer: ByteString, encoding: number )
  {
    var res = { tag: 0, len: 0, value: undefined, lenOffset: 0, valueOffset: 0 };
    var off = 0;
    var bytes = buffer._bytes;

    switch( encoding )
    {
      case TLV.EMV:
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
        res.value = new ByteString( bytes.subarray( res.valueOffset, res.valueOffset + res.len ) );

  //      log( res.valueOffset + "+" + res.len + "=" + bytes );
        break;
      }
    }

    return res;
  }


  static EMV = 1;
  static DGI = 2;
  static L16 = 3;
}

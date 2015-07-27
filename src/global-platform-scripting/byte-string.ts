import { ByteBuffer } from './byte-buffer';
import { Crypto } from './crypto';
import { Hex } from './utils';

export class ByteString
{
  static UTF8 = 2;
  static BASE64 = 4;
  static ASCII = 3;
  static HEX = 16;

  constructor( value, encoding? )
  {
    if ( encoding == undefined )
    {
      if ( value instanceof ByteString )
        this._bytes = value._bytes;
      else if ( value instanceof Uint8Array )
        this._bytes = value;
      else
        this._bytes = new Uint8Array( value );
    }
    else
    {
      switch( encoding )
      {
        case ByteString.HEX:
          this._bytes = new Uint8Array( Hex.decode( value ) );
          break;

        default:
          throw "ByteString unsupported encoding";
      }
    }
    this.length = this._bytes.length;
  }

  length: number;
  _bytes: Uint8Array;

  bytes( offset: number, count?: number ): ByteString
  {
    var end = ( count != undefined ) ? ( offset + count ) : this._bytes.length;

    return new ByteString( this._bytes.subarray( offset, end ) );
  }

  byteAt( offset: number ): number
  {
    return this._bytes[ offset ];
  }

  equals( otherByteString: ByteString )
  {
    return !( this._bytes < otherByteString._bytes ) && !( this._bytes > otherByteString._bytes );
  }

  concat( value: ByteString ): ByteString
  {
    var x = new Uint8Array( this._bytes.length + value.length );
    x.set( this._bytes );
    x.set( value._bytes, this._bytes.length );

    this._bytes = x; this.length = this._bytes.length;

    return new ByteString( x );
  }

  left( /*Number*/value )
  {
    return new ByteString( this._bytes.subarray( 0, value ) );
  }

  right( /*Number*/ value )
  {
    return new ByteString( this._bytes.subarray( -value ) );
  }

  not( ): ByteString
  {
    var bs = new Uint8Array( this._bytes ); // clone
    for( var i = 0; i < bs.length; ++i )
      bs[i] = bs[i] ^0xFF;

    return new ByteString( bs );
  }

  and( value: ByteString ): ByteString
  {
    var bs = new Uint8Array( this._bytes ); // clone

    for( var i = 0; i < bs.length; ++i )
      bs[i] = bs[i] & value._bytes[ i ];

    return new ByteString( bs );
  }

  or( value: ByteString ): ByteString
  {
    var bs = new Uint8Array( this._bytes ); // clone

    for( var i = 0; i < bs.length; ++i )
      bs[i] = bs[i] | value._bytes[ i ];

    return new ByteString( bs );
  }

  pad( method: number, optional?: boolean )
  {
    var bs = new ByteBuffer( this._bytes ); // clone

    if ( optional == undefined )
      optional = false;

    if ( ( ( bs.length & 7 ) != 0 ) || ( !optional ) )
    {
      var newlen = ( ( bs.length + 8 ) & ~7 );
      if ( method == Crypto.ISO9797_METHOD_1 )
        bs.append( 0x80 );

      while( bs.length < newlen )
        bs.append( 0x00 );
    }

    return bs.toByteString();
  }

  toString( encoding )
  {
    var res = "";
//    if ( encoding == undefined )
//    {
//      for( var i = 0; i < this._bytes.length; ++i )
//        res += String.fromCharCode( this._bytes[ i ] );
//  }
//    else
    {
      for( var i = 0; i < this._bytes.length; ++i )
        res += ( "0" + (this._bytes[ i ]).toString( 16 ).toUpperCase() ).slice( -2 );
    }

    return res;
  }
}

export const HEX = ByteString.HEX;
export const ASCII = ByteString.ASCII;
export const BASE64 = ByteString.BASE64;
export const UTF8 = ByteString.UTF8;

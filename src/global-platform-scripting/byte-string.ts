import { ByteArray } from 'sim-core';

import { ByteBuffer } from './byte-buffer';
import { Crypto } from './crypto';

export class ByteString
{
  public byteArray: ByteArray;

  public static HEX = ByteArray.HEX;
  public static BASE64 = ByteArray.HEX;

  constructor( value: string | ByteString | ByteArray, encoding?: number )
  {
    if ( !encoding )
    {
      if ( value instanceof ByteString )
        this.byteArray = value.byteArray;
      else if ( value instanceof ByteArray )
        this.byteArray = value.slice(0,value.length);
//      else
//        super( Uint8Array( value ) );
    }
    else
    {
      switch( encoding )
      {
        case ByteString.HEX:
          this.byteArray = new ByteArray( <string>value, ByteArray.HEX );
          break;

        default:
          throw "ByteString unsupported encoding";
      }
    }
  }

  get length(): number
  {
    return this.byteArray.length;
  }

  bytes( offset: number, count?: number ): ByteString
  {
    var end = ( count != undefined ) ? ( offset + count ) : this.byteArray.length;

    return new ByteString( this.byteArray.slice( offset, end ) );
  }

  byteAt( offset: number ): number
  {
    return this.byteArray.byteAt( offset );
  }

  equals( otherByteString: ByteString )
  {
//    return !( this._bytes < otherByteString._bytes ) && !( this._bytes > otherByteString._bytes );
  }

  concat( value: ByteString ): ByteString
  {
    this.byteArray.concat( value.byteArray );

    return this;
  }

  left( count: number )
  {
    return new ByteString( this.byteArray.slice( 0, count ) );
  }

  right( count: number ): ByteString
  {
    return new ByteString( this.byteArray.slice( -count, 0 ) );
  }

  not( ): ByteString
  {
    return new ByteString( this.byteArray.not() );
  }

  and( value: ByteString ): ByteString
  {
    return new ByteString( this.byteArray.and( value.byteArray) );
  }

  or( value: ByteString ): ByteString
  {
    return new ByteString( this.byteArray.or( value.byteArray) );
  }

  pad( method: number, optional?: boolean )
  {
    var bs = new ByteBuffer( this.byteArray ); // clone

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

  toString( encoding?: number ): string
  {
    //TODO: encoding ...
    return this.byteArray.toString( ByteArray.HEX );
  }
}

export const HEX = ByteString.HEX;
//export const ASCII = ByteString.ASCII;
export const BASE64 = ByteString.BASE64;
//export const UTF8 = ByteString.UTF8;

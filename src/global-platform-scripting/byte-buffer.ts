import { ByteArray } from 'sim-core';
import { ByteString } from './byte-string';

export class ByteBuffer
{
  byteArray: ByteArray;

  constructor ( value?, encoding? )
  {
    if ( value instanceof ByteArray )
    {
      this.byteArray = value;
    }
    else if ( value instanceof ByteString )
    {
      this.byteArray = value.bytes;
    }
    else if ( encoding != undefined )
    {
      this.byteArray = new ByteString( value, encoding ).byteArray;
    }
    else
      this.byteArray = new ByteArray( [] );
  }

  get length()
  {
    return this.byteArray.length;
  }

  toByteString(): ByteString
  {
    return new ByteString( this.byteArray );
  }

  clear()
  {
    this.byteArray = new ByteArray( [] );
  }

  append( value: ByteString | ByteBuffer | number ): ByteBuffer
  {
    let valueArray: ByteArray;

    if ( ( value instanceof ByteString ) || ( value instanceof ByteBuffer ) )
    {
      valueArray = value.byteArray;
    }
    else if ( typeof value == "number" )
    {
      valueArray = new ByteArray( [ ( <number>value & 0xff ) ] );
    }
/*    else if ( typeof value == "string" )
    {
      valueArray = new Uint8Array( value.length );
      for( var i = 0; i < value.length; ++i )
        valueArray[i] = value.charAt( i );
    }*/
//    else
//      valueArray = new ByteArray( value );

    this.byteArray.concat( valueArray );

    return this;
  }
}

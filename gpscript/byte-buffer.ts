import ByteString from "./byte-string";

export default class ByteBuffer
{
  _bytes: Uint8Array;

  constructor ( value?, encoding? )
  {
    if ( value instanceof Uint8Array )
    {
      this._bytes = value;
    }
    else if ( value instanceof ByteString )
    {
      this._bytes = value._bytes;
    }
    else if ( encoding != undefined )
    {
      this._bytes = new ByteString( value, encoding )._bytes;
    }
    else
      this._bytes = new Uint8Array( 0 );

    this.length = this._bytes.length;
  }

  length: number;

  toByteString(): ByteString
  {
    return new ByteString( this._bytes );
  }

  clear()
  {
    this._bytes = new Uint8Array( 0 );

    this.length = this._bytes.length;
  }

  append( value ): ByteBuffer
  {
    var valueArray = undefined;

    if ( ( value instanceof ByteString ) || ( value instanceof ByteBuffer ) )
    {
      valueArray = value._bytes;
    }
    else if ( typeof value == "number" )
    {
      valueArray = new Uint8Array( 1 );
      valueArray[0] = ( value & 0xff );
    }
    else if ( typeof value == "string" )
    {
      valueArray = new Uint8Array( value.length );
      for( var i = 0; i < value.length; ++i )
        valueArray[i] = value.charAt( i );
    }
    else
      valueArray = new Uint8Array( value );

    var old = this._bytes;

    this.length += valueArray.length;

    this._bytes = new Uint8Array( this.length );

    this._bytes.set( old );
    this._bytes.set( valueArray, old.length );

    return this;
  }
}

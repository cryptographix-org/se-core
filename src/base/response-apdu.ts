import { ByteArray, Kind, KindInfo } from 'sim-core';

/**
 * Encoder/Decodor for a APDU Response
 */
export class ResponseAPDU implements Kind
{
  /**
   * @$kindInfo
   */
  private static $kindInfo: KindInfo = KindInfo.$kindHelper
    .init( 'APDUResponse', 'ISO7816 Response APDU' )
    .field( 'SW', 'Status Word', 'integer' )
    .field( 'data', 'Response Data', 'bytearray' )
    .seal();

  get kindInfo()
  {
    return ResponseAPDU.$kindInfo;
  }

  properties = {
    SW: 0,
    data: undefined,
  };

  /**
   * @constructor
   *
   * Deserialize from a JSON object
   */
  constructor( attributes?: {} )
  {
    if ( attributes )
    {
      for( let prop in this.properties )
        if ( attributes[ prop ])
          this.properties[ prop ] = attributes[prop];
    }
  }

  public static init( sw: number, data?: ByteArray ): ResponseAPDU
  {
    return ( new ResponseAPDU() ).set( sw, data );
  }

  public set( sw: number, data?: ByteArray ): ResponseAPDU
  {
    this.properties = {
      SW: sw,
      data: data
    };

    return this;
  }

  public setSW( SW: number ): ResponseAPDU        { this.properties.SW = SW; return this; }
  public setSW1( SW1: number ): ResponseAPDU      { this.properties.SW = ( this.properties.SW & 0xFF ) | ( SW1 << 8 ); return this; }
  public setSW2( SW2: number ): ResponseAPDU      { this.properties.SW = ( this.properties.SW & 0xFF00 ) | SW2; return this; }
  public setData( Data: ByteArray ): ResponseAPDU { this.properties.data = Data; return this; }

  /**
   * Encoder function, returns a blob from an APDUResponse object
   */
  public encodeBytes( options?: {} ): ByteArray
  {
    var apduResp = [], len = 0;
    let props = this.properties;

    if ( props.data )
    {
      while( len < props.data.length )
      {
        apduResp[ len ] = props.data.byteAt( len );
        ++len;
      }
    }

    apduResp[ len++ ] = ( props.SW >> 8 ) & 0xff;
    apduResp[ len++ ] = ( props.SW >> 0 ) & 0xff;

    return new ByteArray( apduResp );
  }

  public decodeBytes( byteArray: ByteArray, options?: {} ): ResponseAPDU
  {
    if ( byteArray.length < 2 )
      throw new Error( 'ResponseAPDU Buffer invalid' );

    let la = byteArray.length - 2;

    this.properties.SW = byteArray.wordAt( la );
    if ( la )
      this.properties.data = byteArray.slice( 0, la );

    return this;
  }
}

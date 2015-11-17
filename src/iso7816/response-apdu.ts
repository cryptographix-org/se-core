import {  ByteArray, Kind, KindInfo } from 'sim-core';

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
    .field( 'sw', 'Status Word', 'integer' )
    .field( 'data', 'Response Data', 'bytearray' )
    .seal();

  get kindInfo()
  {
    return ResponseAPDU.$kindInfo;
  }

  properties = {
    SW12: 0,
    Data: undefined,
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

  buildResponse( sw: number, data?: ByteArray ): ResponseAPDU
  {
    this.properties.SW12 = sw;
    this.properties.Data = data;

    return this;
  }

  /**
   * Encoder function, returns a blob from an APDUResponse object
   */
  public encodeBytes( options?: {} ): ByteArray
  {
    //@ TODO: rebuild binary APDUResponse
    return new ByteArray( [ this.properties.SW12 ] );
  }

  public decodeBytes( byteArray: ByteArray, options?: {} ): ResponseAPDU
  {
    if ( byteArray.length < 2 )
      throw new Error( 'ResponseAPDU Buffer invalid' );

    let la = byteArray.length - 2;

    this.properties.SW12 = byteArray.wordAt( la );
    if ( la )
      this.properties.Data = byteArray.bytes( 0, la );

    return this;
  }
}

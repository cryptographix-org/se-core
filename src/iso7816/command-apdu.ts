import {  ByteArray, Kind, KindInfo } from 'sim-core';

/**
 * Encoder/Decodor Kind for a APDU Command
 */
export class CommandAPDU implements Kind
{
  /**
   * @$kindInfo
   */
  private static $kindInfo: KindInfo = KindInfo.$kindHelper
    .init( 'APDUCommand', 'ISO7816 Command APDU' )
    .field( 'CLI', 'Class', 'string' )
    .field( 'INS', 'Instruction', 'string' )
    .field( 'P1', 'P1 Param', 'byte' )
    .field( 'P2', 'P2 Param', 'byte' )
    .field( 'Lc', 'Command Length', 'integer' )
    .field( 'Data', 'Command Data', 'bytearray' )
    .field( 'Le', 'Expected Length', 'integer' )
    .seal();

  get kindInfo()
  {
    return CommandAPDU.$kindInfo;
  }

  properties = {
    CLA: 0,
    INS: 0,
    P1: 0,
    P2: 0,
    Data: undefined,
    Le: 0
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

  /**
   * Builder
   */
  buildCommand( CLA: number, INS: number, P1: number, P2: number, data?: ByteArray, expectedLen? ): CommandAPDU
  {
    this.properties.CLA = CLA;
    this.properties.INS = INS;
    this.properties.P1 = P1;
    this.properties.P2 = P2;
    this.properties.Data = data;
    this.properties.Le = expectedLen;

    return this;
  }

  /**
   * Serialization, returns a JSON object
   */
  public toJSON(): {}
  {
    return this.properties;
  }

  /**
   * Encoder
   */
  public encodeBytes( options?: {} ): ByteArray
  {
    //@ TODO: rebuild binary APDUCommand
    return new ByteArray( [ this.properties.CLA, this.properties.INS, this.properties.P1, this.properties.P2 ] );
  }

  /**
  * Decoder
  */
  public decodeBytes( byteArray: ByteArray, options?: {} ): CommandAPDU
  {
    if ( byteArray.length < 4 )
      throw new Error( 'CommandAPDU: Invalid buffer' );

    let offset = 0;

    this.properties.CLA = byteArray.byteAt( offset++ );
    this.properties.INS = byteArray.byteAt( offset++ );
    this.properties.P1 = byteArray.byteAt( offset++ );
    this.properties.P2 = byteArray.byteAt( offset++ );

    if ( byteArray.length > offset + 1 )
    {
      var Lc = byteArray.byteAt( offset++ );
      this.properties.Data = byteArray.bytes( offset, Lc );
      offset += Lc;
    }

    if ( byteArray.length > offset )
      this.properties.Le = byteArray.byteAt( offset++ );

    if ( byteArray.length != offset )
      throw new Error( 'CommandAPDU: Invalid buffer' );

    return this;
  }
}

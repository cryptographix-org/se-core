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
    .field( 'data', 'Command Data', 'bytearray' )
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
    data: undefined,
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
   * Fluent Builder
   */
  public static init( CLA?: number, INS?: number, P1?: number, P2?: number, data?: ByteArray, expectedLen?: number ): CommandAPDU
  {
    return ( new CommandAPDU() ).set( CLA, INS, P1, P2, data, expectedLen );
  }

  public set( CLA: number, INS: number, P1: number, P2: number, data?: ByteArray, expectedLen?: number ): CommandAPDU
  {
    this.properties.CLA = CLA;
    this.properties.INS = INS;
    this.properties.P1 = P1;
    this.properties.P2 = P2;
    this.properties.data = data;
    this.properties.Le = expectedLen;

    return this;
  }

  public setCLA( CLA: number ): CommandAPDU      { this.properties.CLA = CLA; return this; }
  public setINS( INS: number ): CommandAPDU      { this.properties.INS = INS; return this; }
  public setP1( P1: number ): CommandAPDU        { this.properties.P1 = P1; return this; }
  public setP2( P2: number ): CommandAPDU        { this.properties.P2 = P2; return this; }
  public setData( data: ByteArray ): CommandAPDU { this.properties.data = data; return this; }
  public setLe( Le: number ): CommandAPDU        { this.properties.Le = Le; return this; }

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
      this.properties.data = byteArray.slice( offset, Lc );
      offset += Lc;
    }

    if ( byteArray.length > offset )
      this.properties.Le = byteArray.byteAt( offset++ );

    if ( byteArray.length != offset )
      throw new Error( 'CommandAPDU: Invalid buffer' );

    return this;
  }
}

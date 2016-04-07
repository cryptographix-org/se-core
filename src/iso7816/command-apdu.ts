import {  ByteArray, Kind, KindBuilder, KindInfo } from 'cryptographix-sim-core';

/**
 * Encoder/Decodor Kind for a APDU Command
 */
export class CommandAPDU implements Kind
{
  CLA: number; // = 0;
  INS: number;
  P1: number;
  P2: number;
  data: ByteArray;
  Le: number;

  /**
   * @constructor
   *
   * Deserialize from a JSON object
   */
  constructor( attributes?: {} )
  {
    Kind.initFields( this, attributes );
  }

  public get Lc():number          { return this.data.length; }
  public get header(): ByteArray  { return new ByteArray( [ this.CLA, this.INS, this.P1, this.P2 ] ); }

  /**
   * Fluent Builder
   */
  public static init( CLA?: number, INS?: number, P1?: number, P2?: number, data?: ByteArray, expectedLen?: number ): CommandAPDU
  {
    return ( new CommandAPDU() ).set( CLA, INS, P1, P2, data, expectedLen );
  }

  public set( CLA: number, INS: number, P1: number, P2: number, data?: ByteArray, expectedLen?: number ): CommandAPDU
  {
    this.CLA = CLA;
    this.INS = INS;
    this.P1 = P1;
    this.P2 = P2;
    this.data = data || new ByteArray();
    this.Le = expectedLen || 0;

    return this;
  }

  public setCLA( CLA: number ): CommandAPDU      { this.CLA = CLA; return this; }
  public setINS( INS: number ): CommandAPDU      { this.INS = INS; return this; }
  public setP1( P1: number ): CommandAPDU        { this.P1 = P1; return this; }
  public setP2( P2: number ): CommandAPDU        { this.P2 = P2; return this; }
  public setData( data: ByteArray ): CommandAPDU { this.data = data; return this; }
  public setLe( Le: number ): CommandAPDU        { this.Le = Le; return this; }

  /**
   * Serialization, returns a JSON object
   */
  public toJSON(): {}
  {
    return {
      CLA: this.CLA,
      INS: this.INS,
      P1: this.P1,
      P2: this.P2,
      data: this.data,
      Le: this.Le
    };
  }

  /**
   * Encoder
   */
  public encodeBytes( options?: {} ): ByteArray
  {
    let dlen = ( ( this.Lc > 0 ) ? 1 + this.Lc : 0 );
    let len = 4 + dlen + ( ( this.Le > 0 ) ? 1 : 0 );
    let ba = new ByteArray().setLength( len );

    // rebuild binary APDUCommand
    ba.setBytesAt( 0, this.header );
    if ( this.Lc ) {
      ba.setByteAt( 4, this.Lc );
      ba.setBytesAt( 5, this.data );
    }

    if ( this.Le > 0 ) {
      ba.setByteAt( 4 + dlen, this.Le );
    }

    return ba;
  }

  /**
  * Decoder
  */
  public decodeBytes( byteArray: ByteArray, options?: {} ): this
  {
    if ( byteArray.length < 4 )
      throw new Error( 'CommandAPDU: Invalid buffer' );

    let offset = 0;

    this.CLA = byteArray.byteAt( offset++ );
    this.INS = byteArray.byteAt( offset++ );
    this.P1 = byteArray.byteAt( offset++ );
    this.P2 = byteArray.byteAt( offset++ );

    if ( byteArray.length > offset + 1 )
    {
      var Lc = byteArray.byteAt( offset++ );
      this.data = byteArray.bytesAt( offset, Lc );
      offset += Lc;
    }

    if ( byteArray.length > offset )
      this.Le = byteArray.byteAt( offset++ );

    if ( byteArray.length != offset )
      throw new Error( 'CommandAPDU: Invalid buffer' );

    return this;
  }
}

KindBuilder.init( CommandAPDU, 'ISO7816 Command APDU' )
  .byteField( 'CLA', 'Class' )
  .byteField( 'INS', 'Instruction' )
  .byteField( 'P1', 'P1 Param' )
  .byteField( 'P2', 'P2 Param' )
  .uint32Field( 'Lc', 'Command Length', { calculated: true } )
  .field( 'data', 'Command Data', ByteArray )
  .uint32Field( 'Le', 'Expected Length' )
  ;

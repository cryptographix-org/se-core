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
  description: string;
  details: string;

  /**
   * @constructor
   *
   * Deserialize from a JSON object
   */
  constructor( attributes?: {} )
  {
    Kind.initFields( this, attributes );
  }

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
      data: this.data && this.data.backingArray,
      Le: this.Le,
      description: this.description,
      details: this.details
    };
  }

  public toString(): string {
    function hex2( val ) { return ( "00" + val.toString( 16 ).toUpperCase() ).substr( -2 ); }

    let s = 'CommandAPDU ';
    s +=     'CLA=0x' + hex2(this.CLA);
    s += ','+'INS=0x' + hex2(this.INS);
    s += ','+'P1=0x' + hex2(this.P1);
    s += ','+'P2=0x' + hex2(this.P2);
    if ( this.data && this.data.length ) {
      s += ','+'Lc=' + this.Lc;
      s += ','+'Data=' + this.data.toString(ByteArray.HEX);
    }
    if ( this.Le )
      s += ','+'Le=' + this.Le;

    if ( this.description )
      s += ' ('+this.description+')';

    return s;
  }

  public get Lc():number          { return this.data.length; }
  public get header(): ByteArray  { return new ByteArray( [ this.CLA, this.INS, this.P1, this.P2 ] ); }

  /**
   * Fluent Builder
   */
  public static init( CLA?: number, INS?: number, P1?: number, P2?: number, data?: ByteArray ): CommandAPDU
  {
    return ( new CommandAPDU() ).set( CLA, INS, P1, P2, data );
  }

  public set( CLA: number, INS: number, P1: number, P2: number, data?: ByteArray ): this
  {
    this.CLA = CLA;
    this.INS = INS;
    this.P1 = P1;
    this.P2 = P2;
    this.data = data || new ByteArray();
    this.Le = undefined;

    return this;
  }

  public setCLA( CLA: number ): this      { this.CLA = CLA; return this; }
  public setINS( INS: number ): this      { this.INS = INS; return this; }
  public setP1( P1: number ): this        { this.P1 = P1; return this; }
  public setP2( P2: number ): this        { this.P2 = P2; return this; }
  public setData( data: ByteArray ): this { this.data = data; return this; }
  public setLe( Le: number ): this        { this.Le = Le; return this; }
  public setDescription( description: string ): this {
    this.description = description; return this;
  }
  public setDetails( details: string ): this {
    this.details = details; return this;
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
  .stringField( 'description', 'Description', { /*optional: true*/ } )
  .stringField( 'details', 'Details', { /*optional: true*/ } )
  ;

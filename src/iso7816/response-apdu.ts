import { ByteArray, Kind, KindInfo, KindBuilder } from 'cryptographix-sim-core';
import { ISO7816 } from './iso7816';

/**
 * Encoder/Decodor for a APDU Response
 */
export class ResponseAPDU implements Kind
{
  SW: number;
  data: ByteArray;
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
      data: this.data && this.data.backingArray,
      SW: this.SW,
      description: this.description,
      details: this.details
    };
  }

  public toString(): string {
    function hex4( val ) { return ( "0000" + val.toString( 16 ).toUpperCase() ).substr( -4 ); }

    let s = 'ResponseAPDU ';
    s +=     'SW=0x' + hex4(this.SW);
    if ( this.data && this.data.length ) {
      s += ','+'La=' + this.La;
      s += ','+'Data=' + this.data.toString(ByteArray.HEX);
    }
    if ( this.description )
      s += ' ('+this.description+')';

    return s;
  }


  public get La() { return this.data.length; }

  public static init( sw: number, data?: ByteArray ): ResponseAPDU
  {
    return ( new ResponseAPDU() ).set( sw, data );
  }

  public set( sw: number, data?: ByteArray ): this
  {
    this.SW = sw;
    this.data = data || new ByteArray();

    return this;
  }

  public setSW( SW: number ): this        { this.SW = SW; return this; }
  public setSW1( SW1: number ): this      { this.SW = ( this.SW & 0xFF ) | ( SW1 << 8 ); return this; }
  public setSW2( SW2: number ): this      { this.SW = ( this.SW & 0xFF00 ) | SW2; return this; }
  public setData( data: ByteArray ): this { this.data = data; return this; }
  public setDescription( description: string ): this {
    this.description = description; return this;
  }
  public setDetails( details: string ): this {
    this.details = details; return this;
  }


  /**
   * Encoder function, returns a blob from an APDUResponse object
   */
  public encodeBytes( options?: {} ): ByteArray
  {
    let ba = new ByteArray().setLength( this.La + 2 );

    ba.setBytesAt( 0, this.data );
    ba.setByteAt( this.La    , ( this.SW >> 8 ) & 0xff );
    ba.setByteAt( this.La + 1, ( this.SW >> 0 ) & 0xff );

    return ba;
  }

  public decodeBytes( byteArray: ByteArray, options?: {} ): this
  {
    if ( byteArray.length < 2 )
      throw new Error( 'ResponseAPDU Buffer invalid' );

    let la = byteArray.length - 2;

    this.SW = byteArray.wordAt( la );
    this.data = ( la ) ? byteArray.bytesAt( 0, la ) : new ByteArray();

    return this;
  }
}

KindBuilder.init( ResponseAPDU, 'ISO7816 Response APDU' )
  .uint32Field( 'SW', 'Status Word' )
  .uint32Field( 'La', 'Actual Length',  { calculated: true } )
  .field( 'data', 'Response Data', ByteArray )
  .stringField( 'description', 'Description', { /*optional: true*/ } )
  .stringField( 'details', 'Details', { /*optional: true*/ } )
  ;

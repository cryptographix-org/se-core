import { ByteArray, Kind, KindInfo, KindBuilder } from 'cryptographix-sim-core';
import { ISO7816 } from './iso7816';

/**
 * Encoder/Decodor for a APDU Response
 */
export class ResponseAPDU implements Kind
{
  SW: number;
  data: ByteArray;

  /**
   * @constructor
   *
   * Deserialize from a JSON object
   */
  constructor( attributes?: {} )
  {
    Kind.initFields( this, attributes );
  }

  public get La() { return this.data.length; }

  public static init( sw: number, data?: ByteArray ): ResponseAPDU
  {
    return ( new ResponseAPDU() ).set( sw, data );
  }

  public set( sw: number, data?: ByteArray ): ResponseAPDU
  {
    this.SW = sw;
    this.data = data || new ByteArray();

    return this;
  }

  public setSW( SW: number ): ResponseAPDU        { this.SW = SW; return this; }
  public setSW1( SW1: number ): ResponseAPDU      { this.SW = ( this.SW & 0xFF ) | ( SW1 << 8 ); return this; }
  public setSW2( SW2: number ): ResponseAPDU      { this.SW = ( this.SW & 0xFF00 ) | SW2; return this; }
  public setData( data: ByteArray ): ResponseAPDU { this.data = data; return this; }

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
  ;

import { ByteArray, Kind, KindInfo } from 'sim-core';

export class ALU implements Kind
{
  /**
   * @$kindInfo
   */
  private static $kindInfo: KindInfo = KindInfo.$kindHelper
    .init( 'ALU', "MULTOS Application Load Unit" )
    .field( "code", "Code Segment", "string" )
    .field( "data", "Data Segment", "string" )
    .field( "fci", "FCI Segment", "string" )
    .field( "dir", "DIR Segment", "string" )
    .seal();

  get kindInfo()
  {
    return ALU.$kindInfo;
  }

  private aluBytes: ByteArray;

  public properties: {};

  /**
   * Encoder/Decodor for a MULTOS Application Load Unit
   *
   * @constructor
   */
  constructor( byteArray?: ByteArray )
  {
    this.properties = {
      "code": null,
      "data": null,
      "fci": null,
      "dir": null
    };

    if ( byteArray )
    {
      this.aluBytes = byteArray;

      this.properties[ "code" ] = this.getALUSegment( 1 );
      this.properties[ "data" ] = this.getALUSegment( 2 );
      this.properties[ "dir" ] = this.getALUSegment( 3 );
      this.properties[ "fci" ] = this.getALUSegment( 4 );
    }
  }

  private getALUSegment( segmentID: number )
  {
    var offset = 8;

    while( ( segmentID > 1 ) && ( offset < this.aluBytes.length ) )
    {
      offset += 2 + this.aluBytes.wordAt( offset );
      --segmentID;
    }

    return this.aluBytes.bytes( offset + 2, this.aluBytes.wordAt( offset ) );
  }

  /**
   * Decoder factory function, decodes a blob into a MultoALU object
   */
  static decodeBlob( blob: ByteArray, opts?: Object ): ALU
  {
    return new ALU( blob );
  }

  /**
   * Encoder function, returns a blob into a MultoALU object
   */
  public encodeBlob( opts?: {} ): ByteArray
  {
    //@ TODO: rebuild binary ALU
    return new ByteArray( [] );
  }
}

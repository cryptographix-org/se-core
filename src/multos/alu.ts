import { ByteArray,Kind,KindInfo } from 'sim-core';

/**
 * Encoder/Decodor for a MULTOS Application Load Unit
 */
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

  public properties = {
    code: new ByteArray([]),
    data: new ByteArray([]),
    fci: new ByteArray([]),
    dir: new ByteArray([])
  };

  /**
   * @constructor
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
   * Serialization, returns a JSON object
   */
  public toJSON(): {}
  {
    return this.properties;
  }

  private getALUSegment( bytes: ByteArray, segmentID: number )
  {
    var offset = 8;

    while( ( segmentID > 1 ) && ( offset < bytes.length ) )
    {
      offset += 2 + bytes.wordAt( offset );
      --segmentID;
    }

    return bytes.slice( offset + 2, bytes.wordAt( offset ) );
  }

  /**
   * Decoder factory function, decodes a blob into a MultosALU object
   */
  public decodeBytes( bytes: ByteArray, options?: Object ): ALU
  {
    this.properties.code = this.getALUSegment( bytes, 1 );
    this.properties.data = this.getALUSegment( bytes, 2 );
    this.properties.dir = this.getALUSegment( bytes, 3 );
    this.properties.fci = this.getALUSegment( bytes, 4 );

    return this;
  }

  /**
   * Encoder function, returns a blob from a MultosALU object
   */
  public encodeBytes( options?: {} ): ByteArray
  {
    //@ TODO: rebuild binary ALU
    return new ByteArray( [] );
  }
}

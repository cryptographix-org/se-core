import { ByteArray, Kind, KindInfo, KindBuilder } from 'cryptographix-sim-core';

/**
 * Encoder/Decodor for a MULTOS Application Load Unit
 */
export class ALU implements Kind
{
  static kindInfo: KindInfo;

  code: ByteArray = new ByteArray();
  data: ByteArray = new ByteArray();
  fci: ByteArray = new ByteArray();
  dir: ByteArray = new ByteArray();

  /**
   * @constructor
   */
  constructor( attributes?: {} )
  {
    if ( attributes )
    {
      for( let field in ALU.kindInfo.fields )
        if ( attributes[ field.id ] )
          this[ field.id ] = attributes[ field.id ];
    }
  }

  /**
   * Serialization, returns a JSON object
   */
  public toJSON(): {}
  {
    return {
      code: this.code,
      data: this.data,
      fci: this.fci,
      dir: this.dir
    };
  }

  private getALUSegment( bytes: ByteArray, segmentID: number )
  {
    var offset = 8;

    while( ( segmentID > 1 ) && ( offset < bytes.length ) )
    {
      offset += 2 + bytes.wordAt( offset );
      --segmentID;
    }

    return bytes.viewAt( offset + 2, bytes.wordAt( offset ) );
  }

  /**
   * Decoder factory function, decodes a blob into a MultosALU object
   */
  public decodeBytes( bytes: ByteArray, options?: Object ): ALU
  {
    this.code = this.getALUSegment( bytes, 1 );
    this.data = this.getALUSegment( bytes, 2 );
    this.dir = this.getALUSegment( bytes, 3 );
    this.fci = this.getALUSegment( bytes, 4 );

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

KindBuilder.init( ALU, "MULTOS Application Load Unit" )
  .field( "code", "Code Segment", ByteArray )
  .field( "data", "Data Segment", ByteArray )
  .field( "fci", "FCI Segment", ByteArray )
  .field( "dir", "DIR Segment", ByteArray )
  ;

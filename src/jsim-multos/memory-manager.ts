import { ByteArray } from 'cryptographix-sim-core';

export function hex2( val ) { return ( "00" + val.toString( 16 ).toUpperCase() ).substr( -2 ); }
export function hex4( val ) { return ( "0000" + val.toString( 16 ).toUpperCase() ).substr( -4 ); }

export enum MEMFLAGS {
  READ_ONLY = 1 << 0,
  TRANSACTIONABLE = 1 << 1,
  TRACE = 1 << 2
}

export class Segment
{
  private memData: ByteArray;
  private memType;
  private readOnly;
  private flags;
  private inTransaction = false;
  private transBlocks = [];
  memTraces;

  constructor( segType, size, flags?, base?: ByteArray )
  {
    this.memType = segType;
    this.readOnly = ( flags & MEMFLAGS.READ_ONLY ) ? true : false;

    if ( base )
    {
      this.memData = new ByteArray( base )
    }
    else
    {
      this.memData = new ByteArray( [] ).setLength( size );
    }
  }

  getType() { return this.memType; }
  getLength() { return this.memData.length; }
  getFlags() { return this.flags; }
  getDebug() { return { memData: this.memData, memType: this.memType, readOnly: this.readOnly, inTransaction: this.inTransaction, transBlocks: this.transBlocks }; }

  beginTransaction()
  {
    this.inTransaction = true;
    this.transBlocks = [];
  }

  endTransaction( commit )
  {
    if ( !commit && this.inTransaction )
    {
      this.inTransaction = false;

      // rollback transactions
      for( var i=0; i < this.transBlocks.length; i++ )
      {
        var block = this.transBlocks[ i ];

        this.writeBytes( block.addr, block.data );
      }
    }

    this.transBlocks = [];
  }

  readByte( addr )
  {
    return this.memData[ addr ];
  }

  zeroBytes( addr, len )
  {
    for( var i = 0; i < len; ++i )
      this.memData[ addr + i ] = 0;
  }

  readBytes( addr, len ): ByteArray
  {
    return this.memData.viewAt( addr, len );
  }

  copyBytes( fromAddr, toAddr, len )
  {
    this.writeBytes( toAddr, this.readBytes( fromAddr, len ) );
  }

  writeBytes( addr: number, val: ByteArray )
  {
    if ( this.inTransaction && ( this.flags & MEMFLAGS.TRANSACTIONABLE ) )
    {
      // save previous EEPROM contents
      this.transBlocks.push( { addr: addr, data: this.readBytes( addr, val.length ) } );
    }

    this.memData.setBytesAt( addr, val );
  }

  newAccessor( addr, len, name ): Accessor
  {
    return new Accessor( this, addr, len, name );
  }
}

export class Accessor
{
  offset: number;
  length: number;
  id: string;
  seg: Segment;

  constructor( seg, addr, len, name )
  {
    this.seg = seg;

    this.offset = addr;
    this.length = len;
    this.id = name;
  }

  traceMemoryOp( op, addr, len, addr2? )
  {
    if ( this.id != "code" )
      this.seg.memTraces.push( { op: op, name: this.id, addr: addr, len: len, addr2: addr2 } );
  }

  traceMemoryValue( val )
  {
    if ( this.id != "code" )
    {
      var memTrace = this.seg.memTraces[ this.seg.memTraces.length - 1 ];

      memTrace.val = val;
    }
  }

  zeroBytes( addr: number, len: number )
  {
    if ( addr + len > this.length )
    {
      this.traceMemoryOp( "ZR-error", addr, this.length );
      throw new Error( "MM: Invalid Zero" );
    }

    this.traceMemoryOp( "ZR", addr, len );
    this.seg.zeroBytes( this.offset + addr, len );
    this.traceMemoryValue( [ 0 ] );
  }

  readByte( addr: number ): number
  {
    if ( addr + 1 > this.length )
    {
      this.traceMemoryOp( "RD-error", addr, 1 );
      throw new Error( "MM: Invalid Read" );
    }

    this.traceMemoryOp( "RD", addr, 1 );

    var val = this.seg.readByte( this.offset + addr );

    this.traceMemoryValue( [ val ]);

    return val;
  }

  readBytes( addr, len ): ByteArray
  {
    if ( addr + len > this.length )
    {
      this.traceMemoryOp( "RD-error", addr, len );
      throw new Error( "MM: Invalid Read" );
    }

    this.traceMemoryOp( "RD", addr, len );
    var val = this.seg.readBytes( this.offset + addr, len );
    this.traceMemoryValue( val );

    return val;
  }

  copyBytes( fromAddr: number, toAddr: number, len: number ): ByteArray
  {
    if ( ( fromAddr + len > this.length ) || ( toAddr + len > this.length ) )
    {
      this.traceMemoryOp( "CP-error", fromAddr, len, toAddr );
      throw new Error( "MM: Invalid Read" );
    }

    //if ( memTracing )
    {
      this.traceMemoryOp( "CP", fromAddr, len, toAddr );
      var val = this.seg.readBytes( this.offset + fromAddr, len );
      this.traceMemoryValue( val );
    }

    this.seg.copyBytes( this.offset + fromAddr, this.offset + toAddr, len );
    return val;
  }

  writeByte( addr: number, val: number )
  {
    if ( addr + 1 > this.length )
    {
      this.traceMemoryOp( "WR-error", addr, 1 );
      throw new Error( "MM: Invalid Write" );
    }

    this.traceMemoryOp( "WR", addr, 1 );
    this.seg.writeBytes( this.offset + addr, new ByteArray( [ val ] ) );
    this.traceMemoryValue( [ val ] );
  }

  writeBytes( addr: number, val: ByteArray )
  {
    if ( addr + val.length > this.length )
    {
      this.traceMemoryOp( "WR-error", addr, val.length );
      throw new Error( "MM: Invalid Write" );
    }

    this.traceMemoryOp( "WR", addr, val.length );
    this.seg.writeBytes( this.offset + addr, val );
    this.traceMemoryValue( val );
  }

  getType() { return this.seg.getType(); }
  getLength() { return this.length; }
  getID() { return this.id; }
//        beginTransaction: beginTransaction,
//        inTransaction: function() { return inTransaction; },
//        endTransaction: endTransaction,
  getDebug() { return { offset: this.offset, length: this.length, seg: this.seg }; }
}

function sliceData( base, offset, size ): Uint8Array
{
  return base.subarray( offset, offset + size );
}

export class MemoryManager
{
  private memorySegments = [];

  private memTraces = [];

  newSegment( memType, size, flags?  ): Segment
  {
    let newSeg = new Segment( memType, size, flags );

    this.memorySegments[ memType ] = newSeg;

    newSeg.memTraces = this.memTraces;

    return newSeg;
  }

  getMemTrace() { return this.memTraces; }

  initMemTrace() { this.memTraces = []; }

  getSegment( type ) { return this.memorySegments[ type ]; }
}

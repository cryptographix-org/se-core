import * as MEL from './mel-defines';
import { ByteArray } from 'cryptographix-sim-core';

import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

function hex( val ) { return val.toString( 16 ); }
function hex2( val ) { return ( "00" + val.toString( 16 ) ).substr( -2 ); }
function hex4( val ) { return ( "0000" + val.toString( 16 ) ).substr( -4 ); }
function ljust( str, w ) { return ( str + Array( w + 1 ).join( " " ) ).substr( 0, w ); }
function rjust( str, w ) { return ( Array( w + 1 ).join( " " ) + str ).substr( -w ); }

function   BA2W( val )
{
  return ( val[ 0 ] << 8 ) | val[ 1 ];
}

function   W2BA( val )
{

  return new ByteArray( [ val >> 8, val & 0xFF ] );
}

export class MELVirtualMachine {
  // card
  ramSegment;
  romSegment;

  // application
  codeArea;
  staticArea;
  publicArea;
  dynamicArea;
  sessionSize;

  // execution
  isExecuting;
  currentIP;
  localBase;
  dynamicTop;
  conditionCodeReg;

  initMVM( params )
  {
    this.romSegment = params.romSegment;
    this.ramSegment = params.ramSegment;

    this.publicArea = this.ramSegment.newAccessor( 0, 512, "P" );
  }

  disassembleCode( resetIP, stepToNextIP )
  {
    var dismText = "";
    function print( str ) { dismText += str; }

    if ( resetIP )
      this.currentIP = 0;

    if ( this.currentIP >= this.codeArea.getLength() )
      return null;

    try
    {
      var nextIP = this.currentIP;
      var instByte = this.codeArea.readByte( nextIP++ );
      var paramCount = 0;
      var paramVal = [];
      var paramDef = [];

      var melInst = MEL.MELDecode[ instByte ];

      if ( melInst == undefined )
      {
        print( "[" + hex4( this.currentIP ) + "]          " + ljust( "ERROR:" + hex2( instByte ), 8 ) + " ********\n" );
      }
      else
      {
        var paramDefs = melInst.paramDefs;
        while( paramDefs != 0 )
        {
          paramDef[ paramCount ] = paramDefs & 0xFF;
          switch( paramDefs & 0xF0 )
          {
            case 0x00: break;
            case 0x10: paramVal[ paramCount ] = this.codeArea.readByte( nextIP++ ); break;
            case 0x20: paramVal[ paramCount ] = BA2W( [ this.codeArea.readByte( nextIP++ ), this.codeArea.readByte( nextIP++ ) ] ); break;
          }
          paramCount++;
          paramDefs >>= 8;
        }

        print( "[" + hex4( this.currentIP ) + "]          " + ljust( melInst.instName, 8 ) );

        if ( ( paramCount > 1 )
          && ( ( paramDef[ 0 ] == MEL.MELPARAMDEF.melParamDefByteOperLen )
            || ( paramDef[ 0 ] == MEL.MELPARAMDEF.melParamDefByteImmediate )
            || ( paramDef[ 0 ] == MEL.MELPARAMDEF.melParamDefWordImmediate ) )
          && ( paramDef[ 1 ] != MEL.MELPARAMDEF.melParamDefByteImmediate )
          && ( paramDef[ 1 ] != MEL.MELPARAMDEF.melParamDefByteOperLen ) )
        {
          var tempVal = paramVal[1]; paramVal[1] = paramVal[0]; paramVal[0] = tempVal;
          var tempDef = paramDef[1]; paramDef[1] = paramDef[0]; paramDef[0] = tempDef;
        }

        for( var paramIndex = 0; paramIndex < paramCount; ++paramIndex )
        {
          var v = paramVal[ paramIndex ];
          var d = paramDef[ paramIndex ];

          switch( d )
          {
            case MEL.MELPARAMDEF.melParamDefByteOperLen:
              if ( v > 0 )
                print( "0x" + hex( v ) );
              else
                print( v );
              break;

            case MEL.MELPARAMDEF.melParamDefByteImmediate:
              if ( v > 0 )
                print( "0x" + hex( v ) );
              else
                print( v );
              break;

            case MEL.MELPARAMDEF.melParamDefWordImmediate:
              print( "0x" + hex( v ) );
              break;

            case MEL.MELPARAMDEF.melParamDefWordCodeAddress:
              print( hex4( v ) );
              break;

            case MEL.MELPARAMDEF.melParamDefByteCodeRelative:
              print( hex4( this.currentIP + 2 + v ) );
              break;

            case MEL.MELPARAMDEF.melParamDefWordOffsetSB:  // 01
            case MEL.MELPARAMDEF.melParamDefWordOffsetST:  // 02
            case MEL.MELPARAMDEF.melParamDefWordOffsetDB:  // 03
            case MEL.MELPARAMDEF.melParamDefWordOffsetLB:  // 04
            case MEL.MELPARAMDEF.melParamDefWordOffsetDT:  // 05
            case MEL.MELPARAMDEF.melParamDefWordOffsetPB:  // 06
            case MEL.MELPARAMDEF.melParamDefWordOffsetPT:  // 07
            {
              var seg = [ "", "SB", "ST", "DB", "LB", "DT", "PB", "PT" ];
              print( seg[ d & 0x07 ] );
              if ( v > 0 )
                print( "[0x" + hex( v ) + "]" );
              else
                print( "[" + v + "]" );
              break;
            }
          }

          if ( paramIndex < paramCount - 1 )
            print( ", " );
        }
        print( "\n" );
      }

      if ( stepToNextIP )
        this.currentIP = nextIP;
    }
    catch( e )
    {
      print( e );
    };


    return dismText;
  }

  //
  // MULTOS addresses are 16-bit linear values, when pushed onto stack
  // and used for indirection. We map address-tag and offset pairs to linear
  // addresses, and back again, by basing static at 0x0000, dynamic at 0x8000
  // and public at 0xF000.
  //
  private mapToSegmentAddr( addrTag, addrOffset )
  {
    var targetAccess = this.checkDataAccess( addrTag, addrOffset, 0 );

    switch( addrTag )
    {
      case MEL.MELTAGADDR.melAddrTOS:
      case MEL.MELTAGADDR.melAddrDB:
      case MEL.MELTAGADDR.melAddrLB:
      case MEL.MELTAGADDR.melAddrDT:
        return 0x8000 + targetAccess.dataOffset;

      case MEL.MELTAGADDR.melAddrSB:
      case MEL.MELTAGADDR.melAddrST:
        return targetAccess.dataOffset;

      case MEL.MELTAGADDR.melAddrPB:
      case MEL.MELTAGADDR.melAddrPT:
        return 0xF000 + targetAccess.dataOffset;
    }
  }

  private mapFromSegmentAddr( segmentAddr )
  {
    if ( segmentAddr & 0x8000 )
    {
      if ( segmentAddr >= 0xF000 )
      {
        return {
          dataArea: this.publicArea,
          dataAddrTag: MEL.MELTAGADDR.melAddrPB,
          dataOffset: segmentAddr & 0x0FFF
        };
      }
      else
      {
        return {
          dataArea: this.dynamicArea,
          dataAddrTag: MEL.MELTAGADDR.melAddrDB,
          dataOffset: segmentAddr & 0x3FFF
        };
      }
    }
    else
    {
      return {
        dataArea: this.staticArea,
        dataAddrTag: MEL.MELTAGADDR.melAddrSB,
        dataOffset: segmentAddr & 0x7FFF
      };
    }
  }

  //
  // validate a multi-byte memory access, specified by address-tag/offset pair
  // and length values. If ok, map to an area and offset within that area.
  // Can accept positive/negative offsets, since they area relative to the
  // the top or the bottom of the specified area, as indicated by the tag.
  //
  private checkDataAccess( addrTag, offset, length )
  {
    var dataArea;
    var dataOffset = offset;
    var areaLimit;

    switch( addrTag )
    {
      case MEL.MELTAGADDR.melAddrTOS:
        dataArea = this.dynamicArea;
        areaLimit = this.dynamicArea.getLength();
        dataOffset += this.localBase;
        break;

      case MEL.MELTAGADDR.melAddrDB:
        dataArea = this.dynamicArea;
        areaLimit = this.dynamicArea.getLength();
        break;

      case MEL.MELTAGADDR.melAddrLB:
        dataArea = this.dynamicArea;
        areaLimit = this.dynamicArea.getLength();
        dataOffset += this.localBase;
        break;

      case MEL.MELTAGADDR.melAddrDT:
        dataArea = this.dynamicArea;
        areaLimit = this.dynamicArea.getLength();
        dataOffset += this.dynamicTop;
        break;

      case MEL.MELTAGADDR.melAddrSB:
        dataArea = this.staticArea;
        areaLimit = this.staticArea.getLength();
        break;

      case MEL.MELTAGADDR.melAddrST:
        dataArea = this.staticArea;
        areaLimit = this.staticArea.getLength();
        dataOffset += areaLimit;
        break;

      case MEL.MELTAGADDR.melAddrPB:
        dataArea = this.publicArea;
        areaLimit = this.publicArea.getLength();
        break;

      case MEL.MELTAGADDR.melAddrPT:
        dataArea = this.publicArea;
        areaLimit = this.publicArea.getLength();
        dataOffset += areaLimit;
        break;
    }

    dataOffset &= 0xffff; // 16 bits addresses
    if ( ( dataOffset < areaLimit ) && ( dataOffset + length < areaLimit ) )
    {
      return {
        dataArea: dataArea,
        dataOffset: dataOffset
      };
    }
  }

  //
  // perform a validated multi-byte read, specified by address-tag/offset pair and
  // length values. Return data-array, or undefined
  //
  private readSegmentData( addrTag, offset, length )
  {
    var targetAccess = this.checkDataAccess( addrTag, offset, 1 );
    if ( targetAccess == undefined )
      return;

    return targetAccess.dataArea.readBytes( targetAccess.dataOffset, length );
  }

  //
  // perform a validated multi-byte write, specified by address-tag/offset pair and
  // data-array to be written.
  //
  private writeSegmentData( addrTag, offset, val )
  {
    var targetAccess = this.checkDataAccess( addrTag, offset, 1 );
    if ( targetAccess == undefined )
      return;

    targetAccess.dataArea.writeBytes( targetAccess.dataOffset, val );
  }

  private pushZerosToStack( cnt )
  {
    this.dynamicArea.zeroBytes( this.dynamicTop, cnt );

    this.dynamicTop += cnt;
  }

  private pushConstToStack( cnt, val )
  {
    if ( cnt == 1 )
      this.dynamicArea.writeBytes( this.dynamicTop, [ val ] );
    else
      this.dynamicArea.writeBytes( this.dynamicTop, W2BA( val ) );

    this.dynamicTop += cnt;
  }

  private copyOnStack( fromOffset, toOffset, cnt )
  {
    this.dynamicArea.copyBytes( fromOffset, toOffset, cnt );
  }

  private pushToStack( addrTag, offset, cnt )
  {
    this.dynamicTop += cnt;
    this.dynamicArea.writeBytes( this.dynamicTop, this.readSegmentData( addrTag, offset, cnt ) );
  }

  private popFromStackAndStore( addrTag, offset, cnt )
  {
    this.dynamicTop -= cnt;

    this.writeSegmentData( addrTag, offset, this.dynamicArea.readBytes( this.dynamicTop, cnt ) );
  }

  private popFromStack( cnt )
  {
    this.dynamicTop -= cnt;

    return this.dynamicArea.readBytes( this.dynamicTop, cnt );
  }

  // setup application for execution
  setupApplication( execParams )
  {
    this.codeArea = execParams.codeArea;
    this.staticArea = execParams.staticArea;
    this.sessionSize = execParams.sessionSize;

    this.dynamicArea = this.ramSegment.newAccessor( 0, 512, "D" ); //TODO: execParams.sessionSize

    this.initExecution();
  }

  private initExecution()
  {
    this.currentIP = 0;
    this.isExecuting = true;

    // TODO: Separate stack and session
    this.localBase = this.sessionSize;
    this.dynamicTop = this.localBase;

    this.conditionCodeReg = 0;
  }

  segs = [ "", "SB", "ST", "DB", "LB", "DT", "PB", "PT" ];

  private constByteBinaryOperation( opCode, constVal, addrTag, addrOffset )
  {
    var targetAccess = this.checkDataAccess( addrTag, addrOffset, 1 );
    if ( targetAccess == undefined )
      return;

    var tempVal = targetAccess.dataArea.readByte( targetAccess.dataOffset );

    switch( opCode )
    {
      case MEL.MELINST.melADDB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = ( tempVal + constVal );
        if ( tempVal < constVal )  // wrap?
          this.conditionCodeReg |= MEL.MEL_CCR_C;
        break;

      case MEL.MELINST.melSUBB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = ( tempVal - constVal );
        if ( tempVal > constVal )  // wrap?
          this.conditionCodeReg |= MEL.MEL_CCR_C;
        break;

      case MEL.MELINST.melCMPB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = ( tempVal - constVal );
        if ( tempVal > constVal ) // wrap?
          this.conditionCodeReg |= MEL.MEL_CCR_C;
        break;

      case MEL.MELINST.melSETB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = constVal;
        break;
    }

    if ( tempVal == 0 )
      this.conditionCodeReg |= MEL.MEL_CCR_Z;

    if ( opCode != MEL.MELINST.melCMPB )
    {
      targetAccess.dataArea.writeByte( targetAccess.dataOffset, tempVal );
    }
  }

  private constWordBinaryOperation( opCode, constVal, addrTag, addrOffset )
  {
    var targetAccess = this.checkDataAccess( addrTag, addrOffset, 2 );
    if ( targetAccess == undefined )
      return;

    var tempVal = BA2W( targetAccess.dataArea.readBytes( targetAccess.dataOffset, 2 ) );

    switch( opCode )
    {
      case MEL.MELINST.melADDB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = ( tempVal + constVal );
        if ( tempVal < constVal )  // wrap?
          this.conditionCodeReg |= MEL.MEL_CCR_C;
        break;

      case MEL.MELINST.melSUBB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = ( tempVal - constVal );
        if ( tempVal > constVal )  // wrap?
          this.conditionCodeReg |= MEL.MEL_CCR_C;
        break;

      case MEL.MELINST.melCMPB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = ( tempVal - constVal );
        if ( tempVal > constVal ) // wrap?
          this.conditionCodeReg |= MEL.MEL_CCR_C;
        break;

      case MEL.MELINST.melSETB:
        this.conditionCodeReg &= ~( MEL.MEL_CCR_C | MEL.MEL_CCR_Z );
        tempVal = constVal;
        break;
    }

    if ( tempVal == 0 )
      this.conditionCodeReg |= MEL.MEL_CCR_Z;

    if ( opCode != MEL.MELINST.melCMPW )
    {
      targetAccess.dataArea.writeBytes( targetAccess.dataOffset, W2BA( tempVal ) );
    }
  }

  private binaryOperation( opCode, opSize, addrTag, addrOffset )
  {
    var targetAccess = this.checkDataAccess( addrTag, addrOffset, 1 );
    if ( targetAccess == undefined )
      return;

    this.checkDataAccess( -opSize - 1, opSize, MEL.MELTAGADDR.melAddrTOS ); // First

    // todo:
  }

  private unaryOperation( opCode, opSize, addrTag, addrOffset )
  {
    var targetAccess = this.checkDataAccess( addrTag, addrOffset, 1 );
    if ( targetAccess == undefined )
      return;

    switch( opCode )
    {
      case MEL.MELINST.melCLEARN:
        targetAccess.dataArea.zeroBytes( targetAccess.dataOffset, opSize );
        break;

      case MEL.MELINST.melTESTN:         // 16
      case MEL.MELINST.melINCN:          // 17
      case MEL.MELINST.melDECN:          // 18
      case MEL.MELINST.melNOTN:          // 19
        ;
    }
  }

  private handleReturn( inBytes, outBytes )
  {
    var retValOffset = this.dynamicTop - outBytes;

    var returnIP = BA2W( this.dynamicArea.readBytes( this.localBase - 2, 2 ) );
    this.localBase = BA2W( this.dynamicArea.readBytes( this.localBase - 4, 2 ) );

    this.dynamicTop = this.localBase + outBytes;
    if ( outBytes )
      this.copyOnStack( retValOffset, this.localBase, outBytes );

    return returnIP;
  }

  private isCondition( tag )
  {
    switch( tag )
    {
      case MEL.MELTAGCOND.melCondEQ:
        return ( this.conditionCodeReg & MEL.MEL_CCR_Z );
      case MEL.MELTAGCOND.melCondLT:
        return !( this.conditionCodeReg & MEL.MEL_CCR_C );
      case MEL.MELTAGCOND.melCondLE:
        return ( this.conditionCodeReg & MEL.MEL_CCR_Z ) || !( this.conditionCodeReg & MEL.MEL_CCR_C );
      case MEL.MELTAGCOND.melCondGT:
        return ( this.conditionCodeReg & MEL.MEL_CCR_C );
      case MEL.MELTAGCOND.melCondGE:
        return ( this.conditionCodeReg & MEL.MEL_CCR_Z ) || ( this.conditionCodeReg & MEL.MEL_CCR_C );
      case MEL.MELTAGCOND.melCondNE:
        return !( this.conditionCodeReg & MEL.MEL_CCR_Z );
      case MEL.MELTAGCOND.melCondALL:
        return true;
      default: // melCondSPEC
    }

    return false;
  }

  executeStep()
  {
    try
    {
      var nextIP = this.currentIP;
      var instByte = this.codeArea.readByte( nextIP++ );
      var paramCount = 0;
      var paramVal = [];
      var paramDef = [];

      var melInst = MEL.MELDecode[ instByte ];

      if ( melInst == undefined )
      {
        return null;
      }
      else
      {
        var paramDefs = melInst.paramDefs;

        while( paramDefs != 0 )
        {
          paramDef[ paramCount ] = paramDefs & 0xFF;
          switch( paramDefs & 0xF0 )
          {
            case 0x00: break;
            case 0x10: paramVal[ paramCount ] = this.codeArea.readByte( nextIP++ ); break;
            case 0x20: paramVal[ paramCount ] = BA2W( [ this.codeArea.readByte( nextIP++ ), this.codeArea.readByte( nextIP++ ) ] ); break;
          }
          paramCount++;
          paramDefs >>= 8;
        }
      }

      var opCode = MEL.MEL2OPCODE( instByte );
      var tag = MEL.MEL2TAG( instByte );

      switch( opCode )
      {
        case MEL.MELINST.melSYSTEM:        // 00
        {
          var publicTop = this.publicArea.getLength();

          switch( tag )
          {
            case MEL.MELTAGSYSTEM. melSystemExit:
              this.isExecuting = false;
              //no break
            case MEL.MELTAGSYSTEM. melSystemNOP:
              break;

            case MEL.MELTAGSYSTEM. melSystemExitSW:
              this.isExecuting = false;
              //no break
            case MEL.MELTAGSYSTEM. melSystemSetSW:
              this.publicArea.writeBytes( publicTop - 2, W2BA( paramVal[ 0 ] ) );
              break;

            case MEL.MELTAGSYSTEM. melSystemExitLa:
              this.isExecuting = false;
              //no break
            case MEL.MELTAGSYSTEM. melSystemSetLa:
              this.publicArea.writeBytes( publicTop - 4, W2BA( paramVal[ 0 ] ) );
              break;

            case MEL.MELTAGSYSTEM. melSystemExitSWLa:
              this.isExecuting = false;
              //no break
            case MEL.MELTAGSYSTEM. melSystemSetSWLa:
              this.publicArea.writeBytes( publicTop - 2, W2BA( paramVal[ 0 ] ) );
              this.publicArea.writeBytes( publicTop - 4, W2BA( paramVal[ 1 ] ) );
              break;
          }
          break;
        }

        case MEL.MELINST.melBRANCH:        // 01
          if ( this.isCondition( tag ) )
            nextIP = nextIP + paramVal[ 0 ];
          break;

        case MEL.MELINST.melJUMP:          // 02
          if ( this.isCondition( tag ) )
            nextIP = paramVal[ 0 ];
          break;

        case MEL.MELINST.melCALL:          // 03
          if ( this.isCondition( tag ) )
          {
            this.pushConstToStack( 2, this.localBase );
            this.pushConstToStack( 2, nextIP );

            nextIP = paramVal[ 0 ];
            this.localBase = this.dynamicTop;
          }
          break;

        case MEL.MELINST.melSTACK:         // 04
        {
          switch( tag )
          {
            case MEL.MELTAGSTACK.melStackPUSHZ:
            {
              this.pushZerosToStack( paramVal[ 0 ] );
              break;
            }
            case MEL.MELTAGSTACK.melStackPUSHB:
              this.pushConstToStack( 1, paramVal[ 0 ] );
              break;

            case MEL.MELTAGSTACK.melStackPUSHW:
              this.pushConstToStack( 2, paramVal[ 0 ] );
              break;

            case MEL.MELTAGSTACK.melStackPOPN:
              this.popFromStack( paramVal[ 0 ] );
              break;

            case MEL.MELTAGSTACK.melStackPOPB:
              this.popFromStack( 1 );
              break;

            case MEL.MELTAGSTACK.melStackPOPW:
              this.popFromStack( 2 );
              break;
          }
          break;
        }

        case MEL.MELINST.melPRIMRET:       // 05
        {
          switch( tag )
          {
            case MEL.MELTAGPRIMRET.melPrimRetPRIM0:
            case MEL.MELTAGPRIMRET.melPrimRetPRIM1:
            case MEL.MELTAGPRIMRET.melPrimRetPRIM2:
            case MEL.MELTAGPRIMRET.melPrimRetPRIM3:
              break;

            case MEL.MELTAGPRIMRET.melPrimRetRET:
              nextIP = this.handleReturn( 0, 0 );
              break;

            case MEL.MELTAGPRIMRET.melPrimRetRETI:
              nextIP = this.handleReturn( paramVal[ 0 ], 0 );
              break;

            case MEL.MELTAGPRIMRET.melPrimRetRETO:
              nextIP = this.handleReturn( 0, paramVal[ 0 ] );
              break;

            case MEL.MELTAGPRIMRET.melPrimRetRETIO:
              nextIP = this.handleReturn( paramVal[ 0 ], paramVal[ 1 ] );
              break;
          }
          break;
        }

        case MEL.MELINST.melLOAD:          // 07
          if ( tag == MEL.MELTAGADDR.melAddrTOS )
          {
            // DUP TOS
            this.copyOnStack( this.dynamicTop - paramVal[ 0 ], this.dynamicTop, paramVal[ 0 ] );
            this.dynamicTop += paramVal[ 0 ];
          }
          else
            this.pushToStack( tag, paramVal[ 1 ], paramVal[ 0 ] );
          break;

        case MEL.MELINST.melSTORE:         // 08
          if ( tag == MEL.MELTAGADDR.melAddrTOS )
          {
            // SHIFT TOS
            this.dynamicTop -= paramVal[ 0 ];
            this.copyOnStack( this.dynamicTop, this.dynamicTop - paramVal[ 0 ], paramVal[ 0 ] );
          }
          else
            this.popFromStackAndStore( tag, paramVal[ 1 ], paramVal[ 0 ] );
          break;


        case MEL.MELINST.melLOADI:         // 09
        {
          var segmentAddr = BA2W( this.readSegmentData( tag, paramVal[ 1 ], 2 ) );
          var targetAccess = this.mapFromSegmentAddr( segmentAddr );
          this.pushToStack( targetAccess.dataAddrTag, targetAccess.dataOffset, paramVal[ 0 ] );
          break;
        }

        case MEL.MELINST.melSTOREI:        // 0A
        {
          var segmentAddr = BA2W( this.readSegmentData( tag, paramVal[ 1 ], 2 ) );
          var targetAccess = this.mapFromSegmentAddr( segmentAddr );
          this.popFromStackAndStore( targetAccess.dataAddrTag, targetAccess.dataOffset, paramVal[ 0 ] );
          break;
        }

        case MEL.MELINST.melLOADA:         // 0B
          this.pushConstToStack( 2, this.mapToSegmentAddr( tag, paramVal[ 0 ] ) );
          break;

        case MEL.MELINST.melINDEX:         // 0C
          break;

        case MEL.MELINST.melSETB:          // 0D
        case MEL.MELINST.melCMPB:          // 0E
        case MEL.MELINST.melADDB:          // 0F
        case MEL.MELINST.melSUBB:          // 10
          if ( tag == MEL.MELTAGADDR.melAddrTOS )
            this.constByteBinaryOperation( opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -1 );
          else
            this.constByteBinaryOperation( opCode, paramVal[0], tag, paramVal[1] );
          break;

        case MEL.MELINST.melSETW:          // 11
        case MEL.MELINST.melCMPW:          // 12
        case MEL.MELINST.melADDW:          // 13
        case MEL.MELINST.melSUBW:          // 14
          if ( tag == MEL.MELTAGADDR.melAddrTOS )
            this.constWordBinaryOperation( opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -2 );
          else
            this.constWordBinaryOperation( opCode, paramVal[0], tag, paramVal[1] );
          break;

        case MEL.MELINST.melCLEARN:        // 15
        case MEL.MELINST.melTESTN:         // 16
        case MEL.MELINST.melINCN:          // 17
        case MEL.MELINST.melDECN:          // 18
        case MEL.MELINST.melNOTN:          // 19
          if ( tag == MEL.MELTAGADDR.melAddrTOS )
            this.unaryOperation( opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -1 * paramVal[0] );
          else
            this.unaryOperation( opCode, paramVal[0], tag, paramVal[1] );
          break;

        case MEL.MELINST.melCMPN:          // 1A
        case MEL.MELINST.melADDN:          // 1B
        case MEL.MELINST.melSUBN:          // 1C
        case MEL.MELINST.melANDN:          // 1D
        case MEL.MELINST.melORN:           // 1E
        case MEL.MELINST.melXORN:          // 1F
          if ( tag == MEL.MELTAGADDR.melAddrTOS )
            this.binaryOperation( opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -2 * paramVal[0] );
          else
            this.binaryOperation( opCode, paramVal[0], tag, paramVal[1] );
          break;
      }

      this.currentIP = nextIP;
    }
    catch( e )
    {
      //print( e );
    }
  }

  setCommandAPDU( commandAPDU: CommandAPDU )
  {
    var publicTop = this.publicArea.getLength();

    // -2,-1 = SW12
    this.publicArea.writeBytes( publicTop - 2, W2BA( 0x9000 ) );

    // -4,-3 = La
    this.publicArea.writeBytes( publicTop - 4, W2BA( 0x0000 ) );

    // -6,-5 = Le
    this.publicArea.writeBytes( publicTop - 6, W2BA( commandAPDU.Le ) );

    // -8,-7 = Lc
    this.publicArea.writeBytes( publicTop - 8, W2BA( commandAPDU.data.length ) );
    this.publicArea.writeBytes( publicTop - 13, commandAPDU.header );

    this.publicArea.writeBytes( 0, commandAPDU.data );

    this.initExecution();
  }

  getResponseAPDU(): ResponseAPDU
  {
    var publicTop = this.publicArea.getLength();

    var la = BA2W( this.publicArea.readBytes( publicTop - 4, 2 ) );

    return new ResponseAPDU( { sw: BA2W( this.publicArea.readBytes( publicTop - 2, 2 ) ), data: this.publicArea.readBytes( 0, la )  } )

  }

  get getDebug(): {}
  {
    return {
      ramSegment: this.ramSegment,
      dynamicArea: this.dynamicArea,
      publicArea: this.publicArea,
      staticArea: this.staticArea,
      currentIP: this.currentIP,
      dynamicTop: this.dynamicTop,
      localBase: this.localBase
    };
  }
//  isExecuting: function() { return isExecuting; },
}

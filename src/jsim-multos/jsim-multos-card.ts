import { ByteArray } from 'cryptographix-sim-core';
import { MemoryManager, MEMFLAGS } from './memory-manager';
import { MELVirtualMachine } from './virtual-machine';

import { ISO7816 } from '../iso7816/ISO7816';
import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

import { JSIMCard } from '../jsim-card/jsim-card';

function  BA2W( val )
{
  return ( val[ 0 ] << 8 ) | val[ 1 ];
}

export class JSIMMultosApplet
{
  sessionSize;
  codeArea;
  staticArea;

  constructor( codeArea, staticArea, sessionSize )
  {
    this.codeArea = codeArea;
    this.staticArea = staticArea;
    this.sessionSize = sessionSize;
  }
}

export class JSIMMultosCard implements JSIMCard
{
  private cardConfig;

  static defaultConfig = {
    romSize: 0,
    ramSize: 1024,
    publicSize: 512,
    nvramSize: 32768
  };

  private powerIsOn: boolean;
  private atr: ByteArray;

  applets: { aid: ByteArray, applet: JSIMMultosApplet }[];

  selectedApplet: JSIMMultosApplet;

  constructor( config? )
  {
    if ( config )
      this.cardConfig = config;
    else
      this.cardConfig = JSIMMultosCard.defaultConfig;

    this.atr = new ByteArray( [] );

    this.applets = [];
  }

  loadApplication( aid: ByteArray, alu: ByteArray )
  {
    var len = 0;

    var off = 8;

    // LEN::CODE
    len = alu.wordAt( off );
    off += 2;

    let codeArea = this.nvramSegment.newAccessor( 0, len, "code" );
    codeArea.writeBytes( 0, alu.viewAt( off, len ) );
    off += len;

    // LEN::DATA
    len = alu.wordAt( off );
    off += 2;

    let staticArea = this.nvramSegment.newAccessor( codeArea.getLength(), len, "S" );
    staticArea.writeBytes( 0, alu.viewAt( off, len ) );
    off += len;

    let applet = new JSIMMultosApplet( codeArea, staticArea, 0 );

    this.applets.push( { aid: aid, applet: applet } );
  }

  public get isPowered(): boolean
  {
    return this.powerIsOn;
  }

  public powerOn(): Promise<ByteArray>
  {
    this.powerIsOn = true;

    this.initializeVM( this.cardConfig );

    return Promise.resolve( this.atr );
  }

  public powerOff(): Promise<any>
  {
    this.powerIsOn = false;

    this.resetVM();

    this.selectedApplet = undefined;

    return Promise.resolve(  );
  }

  public reset(): Promise<ByteArray>
  {
    this.powerIsOn = true;

    this.selectedApplet = undefined;

    this.shutdownVM();

    return Promise.resolve( this.atr );
  }

  public exchangeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    if ( commandAPDU.INS == 0xA4 )
    {
      if ( this.selectedApplet )
      {
        //this.selectedApplet.deselectApplication();

        this.selectedApplet = undefined;
      }

      //TODO: Lookup Application
      this.selectedApplet = this.applets[ 0 ].applet;

      let fci = new ByteArray( [ 0x6F, 0x00 ] );

      this.mvm.setupApplication( this.selectedApplet );

      return Promise.resolve<ResponseAPDU>( new ResponseAPDU( { sw: 0x9000, data: fci  } ) );
    }

    this.mvm.setCommandAPDU( commandAPDU);

//    getResponseAPDU()
//    {
//      return this.mvm.getResponseAPDU();
//    }
    return Promise.resolve<ResponseAPDU>( new ResponseAPDU( { sw: 0x9000, data: []  } ) );

    //return this.executeAPDU( commandAPDU );
  }

  memoryManager: MemoryManager;

  // Card Memory Segments
  romSegment;      // ROM: codelets
  nvramSegment;    // NVRAM: applets code + data
  ramSegment;      // RAM: workspace

  mvm;

  initializeVM( config )
  {
    this.memoryManager = new MemoryManager();

    this.romSegment = this.memoryManager.newSegment( 0, this.cardConfig.romSize, MEMFLAGS.READ_ONLY )
    this.ramSegment = this.memoryManager.newSegment( 1, this.cardConfig.ramSize, 0 );
    this.nvramSegment = this.memoryManager.newSegment( 2, this.cardConfig.nvramSize, MEMFLAGS.TRANSACTIONABLE );

    this.mvm = new MELVirtualMachine();

    this.resetVM();
  }

  resetVM()
  {
    // first time ...
    // init VirtualMachine
    var mvmParams = {
      ramSegment: this.ramSegment,
      romSegment: this.romSegment,
      publicSize: this.cardConfig.publicSize
    };

    this.mvm.initMVM( mvmParams );
  }

  shutdownVM()
  {
    this.resetVM();
    this.mvm = null;
  }

  selectApplication( applet: JSIMMultosApplet, sessionSize )
  {
    var execParams = {
      codeArea: applet.codeArea,
      staticArea: applet.staticArea,
      sessionSize: sessionSize
    };

    this.mvm.execApplication( execParams );
  }

  executeStep()
  {
    return this.mvm.executeStep();
  }
}

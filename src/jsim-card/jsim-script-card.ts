import { ByteArray } from 'sim-core';

import { ISO7816 } from '../base/ISO7816';
import { Slot } from '../base/slot';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

import { JSIMApplet } from './jsim-applet';

export class JSIMCard implements Slot
{
  private powerIsOn: boolean;
  private atr: ByteArray;

  applets: { aid: ByteArray, applet: JSIMApplet }[];

  selectedApplet: JSIMApplet;

  constructor()
  {
    this.atr = new ByteArray( [] );
  }

  loadApplication( aid: ByteArray, applet: JSIMApplet )
  {
    this.applets.push( { aid: aid, applet: applet } );
  }

  get isPresent()
  {
    return true;
  }

  get isPowered(): boolean
  {
    return this.powerIsOn;
  }

  powerOn(): Promise<ByteArray>
  {
    return Promise.resolve( this.atr );
  }

  powerOff(): Promise<any>
  {
    return Promise.resolve(  );
  }

  reset(): Promise<ByteArray>
  {
    return Promise.resolve( this.atr );
  }

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    if ( commandAPDU.properties.INS == 0xA4 )
    {
      if ( this.selectedApplet )
      {
        this.selectedApplet.deselectApplication();

        this.selectedApplet = undefined;
      }

      //TODO: Lookup Application
      this.selectedApplet = this.applets[ 0 ].applet;

      return this.selectedApplet.selectApplication( commandAPDU );
    }

    return this.selectedApplet.executeAPDU( commandAPDU );
  }

}

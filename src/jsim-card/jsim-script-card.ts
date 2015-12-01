import { ByteArray } from 'sim-core';

import { ISO7816 } from '../base/ISO7816';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

import { JSIMCard } from './jsim-card';
import { JSIMScriptApplet } from './jsim-script-applet';

export class JSIMScriptCard implements JSIMCard
{
  private powerIsOn: boolean;
  private atr: ByteArray;

  applets: { aid: ByteArray, applet: JSIMScriptApplet }[];

  selectedApplet: JSIMScriptApplet;

  constructor()
  {
    this.atr = new ByteArray( [] );
  }

  loadApplication( aid: ByteArray, applet: JSIMScriptApplet )
  {
    this.applets.push( { aid: aid, applet: applet } );
  }

  get isPowered(): boolean
  {
    return this.powerIsOn;
  }

  powerOn(): Promise<ByteArray>
  {
    this.powerIsOn = true;

    return Promise.resolve( this.atr );
  }

  powerOff(): Promise<any>
  {
    this.powerIsOn = false;

    this.selectedApplet = undefined;

    return Promise.resolve(  );
  }

  reset(): Promise<ByteArray>
  {
    this.powerIsOn = true;

    this.selectedApplet = undefined;

    // TODO: Reset

    return Promise.resolve( this.atr );
  }

  exchangeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
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

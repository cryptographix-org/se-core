import { ByteArray } from 'cryptographix-sim-core';

import { ISO7816 } from '../iso7816/ISO7816';
import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

import { JSIMCard } from './jsim-card';
import { JSIMScriptApplet } from './jsim-script-applet';

export class JSIMScriptCard implements JSIMCard
{
  private _powerIsOn: boolean;
  private _atr: ByteArray;

  applets: { aid: ByteArray, applet: JSIMScriptApplet }[] = [];

  selectedApplet: JSIMScriptApplet;

  constructor()
  {
    this._atr = new ByteArray( [] );
  }

  loadApplication( aid: ByteArray, applet: JSIMScriptApplet )
  {
    this.applets.push( { aid: aid, applet: applet } );
  }

  get isPowered(): boolean
  {
    return this._powerIsOn;
  }

  powerOn(): Promise<ByteArray>
  {
    this._powerIsOn = true;

    return Promise.resolve<ByteArray>( this._atr );
  }

  powerOff(): Promise<any>
  {
    this._powerIsOn = false;

    this.selectedApplet = undefined;

    return Promise.resolve();
  }

  reset(): Promise<ByteArray>
  {
    this._powerIsOn = true;

    this.selectedApplet = undefined;

    // TODO: Reset

    return Promise.resolve<ByteArray>( this._atr );
  }

  exchangeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    if ( commandAPDU.INS == 0xA4 )
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

import { ByteArray } from 'sim-core';

import { Slot } from '../base/slot';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';
import { JSIMCard } from './jsim-card';

export class JSIMSlot implements Slot
{
  public card: JSIMCard;

  constructor( card?: JSIMCard )
  {
    this.card = card;
  }

  get isPresent(): boolean
  {
    return !!this.card;
  }

  get isPowered(): boolean
  {
    return this.isPresent && this.card.isPowered;
  }

  powerOn(): Promise<ByteArray>
  {
    if ( !this.isPresent )
      return Promise.reject<ByteArray>( new Error( "JSIM: Card not present" ) );

    return this.card.powerOn();
  }

  powerOff(): Promise<boolean>
  {
    if ( !this.isPresent )
      return Promise.reject<boolean>( new Error( "JSIM: Card not present" ) );

    return this.card.powerOff();
  }

  reset(): Promise<ByteArray>
  {
    if ( !this.isPresent )
      return Promise.reject<ByteArray>( new Error( "JSIM: Card not present" ) );

    return this.card.reset();
  }

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    if ( !this.isPresent )
      return Promise.reject<ResponseAPDU>( new Error( "JSIM: Card not present" ) );

    if ( !this.isPowered )
      return Promise.reject<ResponseAPDU>( new Error( "JSIM: Card unpowered" ) );

    return this.card.exchangeAPDU( commandAPDU );
  }

  insertCard( card: JSIMCard )
  {
    if ( this.card )
      this.ejectCard();

    this.card = card;
  }

  ejectCard()
  {
    if ( this.card )
    {
      if ( this.card.isPowered )
        this.card.powerOff();

      this.card = undefined;
    }
  }
}

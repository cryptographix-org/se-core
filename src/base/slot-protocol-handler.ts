import { ByteArray, EndPoint, Message, MessageHeader } from 'cryptographix-sim-core';

import { Slot } from '../base/slot';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

export class SlotProtocolHandler
{
  endPoint: EndPoint;
  slot: Slot;

  constructor()
  {
  }

  linkSlot( slot: Slot, endPoint: EndPoint )
  {
    this.endPoint = endPoint;
    this.slot = slot;

    endPoint.onMessage( this.onMessage );
  }

  unlinkSlot()
  {
    this.endPoint.onMessage( null );
    this.endPoint = null;
    this.slot = null;
  }

  onMessage( packet: Message<any>, receivingEndPoint: EndPoint )
  {
    let hdr: any = packet.header;
    let payload = packet.payload;

    let response: Promise<any>;

    switch( hdr.method )
    {
      case "executeAPDU":
        if ( !( hdr.kind instanceof CommandAPDU ) )
          break;

        response = this.slot.executeAPDU( <CommandAPDU>payload );

        response.then( ( responseAPDU: ResponseAPDU ) => {
          let replyPacket = new Message<ResponseAPDU>( { method: "executeAPDU" }, responseAPDU );

          receivingEndPoint.sendMessage( replyPacket );
        });
        break;


      case "powerOff":
      case "powerOn":
      case "reset":
        if ( hdr.method == 'reset' )
          response = this.slot.reset();
        else if ( hdr.method == 'powerOn' )
          response = this.slot.powerOn();
        else // if ( hdr.method == 'powerOff' )
          response = this.slot.powerOff();

        response.then( ( respData: ByteArray )=> {
          receivingEndPoint.sendMessage( new Message<ByteArray>( { method: hdr.method }, respData ) );
        });

      default:
        response = Promise.reject<Error>( new Error( "Invalid method" + hdr.method ) );
        break;
    } // switch

    // trap and return any errors
    response.catch( ( e: any ) => {
      let errorPacket = new Message<Error>( { method: "error" }, e );

      receivingEndPoint.sendMessage( errorPacket );
    });
  }
}

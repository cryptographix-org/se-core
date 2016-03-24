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
        if ( !( payload instanceof CommandAPDU ) )
          break;

        response = this.slot.executeAPDU( <CommandAPDU>payload );

        response.then( ( responseAPDU: ResponseAPDU ) => {
          let replyPacket = new Message<ResponseAPDU>( { method: "executeAPDU" }, responseAPDU );

          receivingEndPoint.sendMessage( replyPacket );
        });
        break;

      case "powerOff":
        response = this.slot.powerOff()
          .then( ( respData: boolean )=> {
            receivingEndPoint.sendMessage( new Message<ByteArray>( { method: hdr.method }, new ByteArray() ) );
          });
        break;

      case "powerOn":
        response = this.slot.powerOn()
          .then( ( respData: ByteArray )=> {
            receivingEndPoint.sendMessage( new Message<ByteArray>( { method: hdr.method }, respData ) );
          });
        break;

      case "reset":
        response = this.slot.reset()
          .then( ( respData: ByteArray )=> {
            receivingEndPoint.sendMessage( new Message<ByteArray>( { method: hdr.method }, respData ) );
          });
        break;

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

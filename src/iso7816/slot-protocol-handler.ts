import { ByteArray, EndPoint, Message, MessageHeader, Direction, Channel } from 'cryptographix-sim-core';

import { Slot } from '../iso7816/slot';
import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

export class SlotProtocolHandler
{
  endPoint: EndPoint;
  slot: Slot;

  constructor()
  {
  }

  linkSlot( slot: Slot, endPoint: EndPoint )
  {
    let me = this;

    this.endPoint = endPoint;
    this.slot = slot;

    endPoint.onMessage( ( msg, ep ) => {
      me.onMessage( msg,ep );
    } );
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
    let replyHeader = { method: hdr.method, isResponse: true };

    switch( hdr.method )
    {
      case "executeAPDU":
        if ( !( payload instanceof CommandAPDU ) )
          break;

        response = this.slot.executeAPDU( <CommandAPDU>payload );

        response.then( ( responseAPDU: ResponseAPDU ) => {
          let replyPacket = new Message<ResponseAPDU>( replyHeader, responseAPDU );

          receivingEndPoint.sendMessage( replyPacket );
        });
        break;

      case "powerOff":
        response = this.slot.powerOff()
          .then( ( respData: ByteArray )=> {
            receivingEndPoint.sendMessage( new Message<ByteArray>( replyHeader, new ByteArray() ) );
          });
        break;

      case "powerOn":
        response = this.slot.powerOn()
          .then( ( respData: ByteArray )=> {
            receivingEndPoint.sendMessage( new Message<ByteArray>( replyHeader, respData ) );
          });
        break;

      case "reset":
        response = this.slot.reset()
          .then( ( respData: ByteArray )=> {
            receivingEndPoint.sendMessage( new Message<ByteArray>( replyHeader, respData ) );
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

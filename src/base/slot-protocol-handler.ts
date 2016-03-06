import { ByteArray, EndPoint, Message, MessageHeader } from 'cryptographix-sim-core';

import { Slot } from '../base/slot';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

export class SlotProtocolHandler
{
  endPoint: EndPoint;
  slot: Slot;

  constructor(  )
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
    this.endPoint.onMessage( undefined );
    this.endPoint = undefined;
    this.slot = undefined;
  }

  onMessage( packet: Message<any>, receivingEndPoint: EndPoint )
  {
    let hdr: any = packet.header;
    let payload = packet.payload;

    switch( hdr.command )
    {
      case "executeAPDU":
      {
        if ( !( hdr.kind instanceof CommandAPDU ) )
          break;

        let commandAPDU: CommandAPDU = <CommandAPDU>payload;

        var resp = this.slot.executeAPDU( commandAPDU );
        let x: MessageHeader = null;

        resp.then( ( responseAPDU ) => {
          let replyPacket = new Message<ResponseAPDU>( { method: "executeAPDU" }, responseAPDU );

          receivingEndPoint.sendMessage( replyPacket );
        })
        .catch( () => {
          let errorPacket = new Message<Error>( { method: "error" }, undefined );

          receivingEndPoint.sendMessage( errorPacket );
        });

        break;
      }

/*          case "ctrlPowerReset":
          {
            var atr = null;

            if ( cmd.data == "powerOff" )
              atr = slot.ctrlPowerReset( 0 );
            else if ( cmd.data == "powerOn" )
              atr = slot.ctrlPowerReset( 1 );
            else if ( cmd.data == "reset" )
              atr = slot.ctrlPowerReset( 2 );

            return sendResponsePacket(
              port,
              packet.header,
              {
                command: "ctrlPowerReset",
                data: new Uint8Array( atr )
              } );
          }*/
        } // switch
  }
}

import { ByteArray, EndPoint, Message, MessageHeader, Direction, Channel, Protocol } from 'cryptographix-sim-core';

import { Slot } from '../iso7816/slot';
import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

export class SlotProtocol implements Protocol<Slot> {
  static getHandler(): SlotProtocolHandler {
    return new SlotProtocolHandler();
  }

  static getProxy( endPoint: EndPoint ): SlotProtocolProxy {
    return new SlotProtocolProxy( endPoint );
  }
}

export class SlotProtocolProxy implements Slot {
  endPoint: EndPoint;
  pending: any;

  private powerCommand( method: string ): Promise<ByteArray> {
    let me = this;
    return new Promise<ByteArray>( (resolve, reject) => {
      me.pending = {
        method: method,
        resolve: resolve,
        reject: reject
      };

      me.endPoint.sendMessage( new Message<void>( { method: method }, null ) );
    });
  }

  constructor( endPoint: EndPoint ) {
    this.endPoint = endPoint;

    // Nasty plumbing .. each proxy-command will set pending to container
    //   - method called (powerOn, powerOff, reset, executeAPDU )
    //   - resolve callback (from promise) - receives the payload
    //   - reject callback (from promise)
    // When the end-point receives a message (response), check method
    // and if it matches the pending-op, resolve the promise
    // otherwise reject it
    let me = this;
    endPoint.onMessage( ( msg ) => {
      let pendingOp = me.pending;

      if ( pendingOp ) {
        if ( msg.header.isResponse && ( msg.header.method == pendingOp.method ) ) {
          pendingOp.resolve( msg.payload );
          return;
        }
        else {
          pendingOp.reject( msg.payload );
        }
      }
    });
  }

  powerOn(): Promise<ByteArray> {
    return this.powerCommand( 'powerOn' );
  }
  reset(): Promise<ByteArray> {
    return this.powerCommand( 'reset' );
  }
  powerOff(): Promise<ByteArray> {
    return this.powerCommand( 'powerOff' );
  }
  get isPresent(): boolean {
    return false;
  }
  get isPowered(): boolean {
    return false;
  }

  executeAPDU( cmd: CommandAPDU ): Promise<ResponseAPDU> {
    let me = this;
    return new Promise<ResponseAPDU>( (resolve, reject) => {
      me.pending = {
        method: 'executeAPDU',
        resolve: resolve,
        reject: reject
      };

      me.endPoint.sendMessage( new Message<CommandAPDU>( { method: 'executeAPDU' }, cmd ) );
    });
  }
}

export class SlotProtocolHandler {

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

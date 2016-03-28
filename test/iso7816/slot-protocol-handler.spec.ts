import { ByteArray, Message, Direction, EndPoint, Channel } from 'cryptographix-sim-core';
import { CommandAPDU, ResponseAPDU, ISO7816, Slot, SlotProtocolHandler } from 'cryptographix-se-core';


class MockSlot implements Slot
{
  private _atr = [ 0x3B, 0x90, 0x01, 0x00 ];

  isPresent: boolean;
  isPowered: boolean = false;

  constructor( isPresent: boolean = true ) {
    this.isPresent = isPresent;
  }
  powerOn(): Promise<ByteArray> {
    this.isPowered = true;
    return Promise.resolve( new ByteArray( this._atr ) );
  }

  powerOff(): Promise<ByteArray> {
    this.isPowered = false;
    return Promise.resolve( new ByteArray() );
  }

  reset(): Promise<ByteArray> {
    this.isPowered = true;
    return Promise.resolve( new ByteArray( this._atr ) );
  }

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU> {
    this.isPowered = true;
    return Promise.resolve( new ResponseAPDU( { SW: 0x9000 } ) );
  }
}

function makeMockSlotEndPoint(): { endPoint: EndPoint, xchangeAPDU: ( cmd: CommandAPDU ) => Promise<ResponseAPDU>, handler: SlotProtocolHandler } {
  let slot: Slot = new MockSlot();
  let handler = new SlotProtocolHandler();
  let inPoint = new EndPoint( 'in', Direction.IN );
  let outPoint = new EndPoint( 'out', Direction.OUT );

  handler.linkSlot( slot, inPoint );
  let chan = new Channel();

  inPoint.attach( chan );
  outPoint.attach( chan );

  chan.activate();

  function xchgAPDU( cmd: CommandAPDU ): Promise<ResponseAPDU> {
    return new Promise<ResponseAPDU>( ( resolve, reject ) => {
      outPoint.sendMessage( new Message( { method: "executeAPDU" }, cmd ) );
      outPoint.onMessage( ( msg: Message<ResponseAPDU> ) => {
        if ( msg.header.method == 'executeAPDU' )
          resolve( msg.payload );
        else
          reject( msg.payload );
      } );
    });
  }

  return {
    endPoint: outPoint,
    xchangeAPDU: xchgAPDU,
    handler: handler
  }
}

describe('SlotProtocolHandler', ()=> {
  it('acts as a message proxy for a Slot', (done)=>{
    let mocker = makeMockSlotEndPoint();

    mocker.xchangeAPDU( new CommandAPDU( { INS: 0xA4 } ) )
      .then( (resp) => {
        expect( resp.SW ).toEqual( 0x9000 );
        console.log( 'Response:' + resp.SW.toString( 16 ) );
        done();
      })
      .catch( (err) => {
        console.log( 'Error: ' + err )
        done.fail();
      })

  })
});

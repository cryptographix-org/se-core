import { ByteArray } from 'cryptographix-sim-core';
import { CommandAPDU, ResponseAPDU, ISO7816 } from 'cryptographix-se-core';
import { JSIMMultosCard } from 'cryptographix-se-core';
import { IID } from './data/multos-alu-iid';
//import { ISD } from './data/multos-alu-isd';

describe('JSIMMultosCard', () => {
  it( 'can be selected', ( done ) => {
    var card = new JSIMMultosCard();

    card.powerOn().then( ()=>
    {
      card.loadApplication( new ByteArray( [0xA0, 0x00, 0x00, 0x01, 0x54, 0x49, 0x44] ), new ByteArray( IID ) );

      var selectAPDU = CommandAPDU.init().setINS( ISO7816.INS_SELECT_FILE );

      return card.exchangeAPDU( selectAPDU );
    })
    .then( (rAPDU) => {
      console.log( rAPDU );
      var gpoAPDU = CommandAPDU.init()
        .setINS( 0xB8 )
        .setData( new ByteArray( [ 0x83, 0x00 ] ) );

      return card.exchangeAPDU( gpoAPDU );
    })
    .then( (rAPDU) => {

      card.executeStep();
      card.executeStep();
      card.executeStep();
      card.executeStep();

      console.log( rAPDU );
      var gacAPDU = CommandAPDU.init()
        .setINS( 0xAC )
        .setData( new ByteArray( [ 0x00, 0x00 ] ) );

      return card.exchangeAPDU( gacAPDU );
    })
    .then( (rAPDU) => {
      console.log( rAPDU ); console.log( rAPDU.data );

      done();
    } )
    .catch( ( err ) => {
      console.log( err );
      done();
    })

  } );

} );

import { ALU } from 'cryptographix-se-core';
import { ByteArray } from 'cryptographix-sim-core';
import { IID } from './data/multos-alu-iid';

describe('Multos ALU', ()=> {
  it('can decode a binary object', ()=> {
    var ba = new ByteArray( IID );

    var aluX = new ALU().decodeBytes( ba );
    //console.log( aluX.toJSON() );
  })
});

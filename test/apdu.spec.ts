import { CommandAPDU, ResponseAPDU } from 'cryptographix-se-core';

describe('CommandAPDU', ()=> {
  it('can be created empty', ()=>{
    var cmd = new CommandAPDU();
    expect( cmd.CLA ).toBe( 0 );
  })
});

import { CommandAPDU, ResponseAPDU } from 'se-core';

describe('CommandAPDU', ()=> {
  it('can be created empty', ()=>{
    var cmd = new CommandAPDU();
    expect( cmd.properties.CLA ).toBe( 0 );
  })
});
